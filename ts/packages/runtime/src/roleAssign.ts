/**
 * Role-assignment management write SQL (Layer 3) — the control-plane writes over the
 * rolestore (the dual of the holds-resolver read), from the Go role_assignment_runtime.go.
 * Each builder returns SQL + ordered args (the caller executes them under the principal's
 * claims; the role_assignments object's own RLS is the write moat). The kind constant is
 * inlined as a SQL literal where it is not a runtime value; everything genuinely runtime
 * binds to $N. Import as a namespace: `roleAssignments.assignInsert(surface, …)`.
 */

import { touchOnConflict } from "./grants.js";
import type { RoleAssignmentSurface, ParamStatement, SqlArg } from "./types.js";

/**
 * The assignment-row projection in canonical order: pk, kind, subject, role, scope cols,
 * then whichever audit columns are declared (granted_at, granted_by, revoked, revoked_by),
 * then the extra context columns. What AssignInsert RETURNs and ListForRole selects.
 */
function assignmentCols(p: RoleAssignmentSurface): string[] {
  const cols = [p.pk, p.kindCol, p.subjectCol, p.roleCol, ...p.scopeCols];
  for (const c of [p.grantedAtCol, p.grantedByCol, p.revokedCol, p.revokedByCol]) {
    if (c !== "") cols.push(c);
  }
  return [...cols, ...p.extraCols];
}

/** The reactivate-on-conflict tail for an assignment (the TOUCH variant). Mirrors Go `touchClause`. */
function touchClause(p: RoleAssignmentSurface): string {
  const bare = [p.kindCol, p.subjectCol, p.roleCol];
  const nullable = [...p.scopeCols, ...p.extraCols];
  const sets: string[] = [];
  if (p.revokedCol !== "") sets.push(`${p.revokedCol} = NULL`);
  if (p.revokedByCol !== "") sets.push(`${p.revokedByCol} = NULL`);
  if (p.grantedAtCol !== "") sets.push(`${p.grantedAtCol} = now()`);
  if (p.grantedByCol !== "") sets.push(`${p.grantedByCol} = EXCLUDED.${p.grantedByCol}`);
  return touchOnConflict(bare, nullable, sets);
}

function assignSQL(
  p: RoleAssignmentSurface,
  touch: boolean,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg>,
): ParamStatement {
  const cols = [p.pk, p.kindCol, p.subjectCol, p.roleCol];
  const args: SqlArg[] = [assignmentID, p.kindVal, subjectID, roleID];
  for (let i = 0; i < p.scopeCols.length; i++) {
    cols.push(p.scopeCols[i]!);
    args.push(i < scope.length ? scope[i]! : null); // a short scope tail is unpinned (NULL)
  }
  if (p.grantedByCol !== "") {
    cols.push(p.grantedByCol);
    args.push(grantedBy);
  }
  for (const c of p.extraCols) {
    cols.push(c);
    args.push(extra[c] ?? null); // a declared col absent from `extra` is written NULL
  }
  const ph = cols.map((_, i) => `$${i + 1}`);
  const conflict = touch ? " " + touchClause(p) : "";
  const sql =
    `INSERT INTO ${p.assignments} (${cols.join(", ")}) VALUES (${ph.join(", ")})${conflict} ` +
    `RETURNING ${assignmentCols(p).join(", ")}`;
  return { sql, args };
}

/**
 * The INSERT that confers a role on a principal at a scope, plus ordered args. The kind
 * is inlined as the bound $2 constant; granted_at is left to the table default. Errors on
 * a unique-constraint conflict (use {@link assignTouchInsert} to reactivate instead).
 * Mirrors Go `AssignInsert`.
 *
 * Args order: assignmentID, kindVal, subjectID, roleID, scope…, [grantedBy], extra…
 */
export function assignInsert(
  p: RoleAssignmentSurface,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  return assignSQL(p, false, assignmentID, subjectID, roleID, scope, grantedBy, extra);
}

/**
 * The idempotent (TOUCH) variant: re-assigning a tuple of the same natural identity
 * REACTIVATES it (NULLs the soft-revoke columns, refreshes granted_at / granted_by)
 * instead of erroring on conflict. The args are byte-identical to {@link assignInsert}
 * (reactivation uses NULL/now()/EXCLUDED). Mirrors Go `AssignTouchInsert`.
 */
export function assignTouchInsert(
  p: RoleAssignmentSurface,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  return assignSQL(p, true, assignmentID, subjectID, roleID, scope, grantedBy, extra);
}

/**
 * The soft-revoke: stamps the revoked column (and the revoker, when declared) on an ACTIVE
 * assignment, keyed by PK. $1 = assignment id; $2 = revoker id (only when a revoked-by
 * column is declared). The `AND <revoked> IS NULL` guard makes it idempotent. Mirrors Go
 * `RevokeSQL`.
 */
export function revokeSQL(p: RoleAssignmentSurface): string {
  let set = `${p.revokedCol} = now()`;
  if (p.revokedByCol !== "") set += `, ${p.revokedByCol} = $2`;
  return `UPDATE ${p.assignments} SET ${set} WHERE ${p.pk} = $1 AND ${p.revokedCol} IS NULL`;
}

/**
 * Lists every assignment of a role (active AND revoked — an audit view), projected as the
 * assignment columns, newest first when a granted-at column is declared. $1 = role id.
 * Mirrors Go `ListForRoleSQL`.
 */
export function listForRoleSQL(p: RoleAssignmentSurface): string {
  let sql = `SELECT ${assignmentCols(p).join(", ")} FROM ${p.assignments} WHERE ${p.roleCol} = $1`;
  if (p.grantedAtCol !== "") sql += ` ORDER BY ${p.grantedAtCol} DESC`;
  return sql;
}

/**
 * Lists a principal's ACTIVE assignments joined to each role's key (and materialized
 * permissions, when declared). $1 = principal id; the kind is inlined as a SQL literal.
 * Mirrors Go `ListForPrincipalSQL`.
 */
export function listForPrincipalSQL(p: RoleAssignmentSurface): string {
  const cols = [`a.${p.pk}`, `a.${p.subjectCol}`, `a.${p.roleCol}`];
  for (const c of [p.grantedAtCol, p.grantedByCol]) {
    if (c !== "") cols.push(`a.${c}`);
  }
  cols.push(`r.${p.keyCol}`);
  if (p.permsCol !== "") cols.push(`r.${p.permsCol}`);
  return (
    `SELECT ${cols.join(", ")} FROM ${p.assignments} a JOIN ${p.rolesTable} r ON r.${p.rolesId} = a.${p.roleCol} ` +
    `WHERE a.${p.kindCol} = '${p.kindVal}' AND a.${p.subjectCol} = $1 AND a.${p.revokedCol} IS NULL`
  );
}
