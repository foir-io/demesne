

import { touchOnConflict } from "./grants.js";
import type { RoleAssignmentSurface, ParamStatement, SqlArg } from "./types.js";

function assignmentCols(p: RoleAssignmentSurface): string[] {
  const cols = [p.pk, p.kindCol, p.subjectCol, p.roleCol, ...p.scopeCols];
  for (const c of [p.grantedAtCol, p.grantedByCol, p.revokedCol, p.revokedByCol]) {
    if (c !== "") cols.push(c);
  }
  return [...cols, ...p.extraCols];
}

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
    args.push(i < scope.length ? scope[i]! : null);
  }
  if (p.grantedByCol !== "") {
    cols.push(p.grantedByCol);
    args.push(grantedBy);
  }
  for (const c of p.extraCols) {
    cols.push(c);
    args.push(extra[c] ?? null);
  }
  const ph = cols.map((_, i) => `$${i + 1}`);
  const conflict = touch ? " " + touchClause(p) : "";
  const sql =
    `INSERT INTO ${p.assignments} (${cols.join(", ")}) VALUES (${ph.join(", ")})${conflict} ` +
    `RETURNING ${assignmentCols(p).join(", ")}`;
  return { sql, args };
}

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

export function revokeSQL(p: RoleAssignmentSurface): string {
  let set = `${p.revokedCol} = now()`;
  if (p.revokedByCol !== "") set += `, ${p.revokedByCol} = $2`;
  return `UPDATE ${p.assignments} SET ${set} WHERE ${p.pk} = $1 AND ${p.revokedCol} IS NULL`;
}

export function listForRoleSQL(p: RoleAssignmentSurface): string {
  let sql = `SELECT ${assignmentCols(p).join(", ")} FROM ${p.assignments} WHERE ${p.roleCol} = $1`;
  if (p.grantedAtCol !== "") sql += ` ORDER BY ${p.grantedAtCol} DESC`;
  return sql;
}

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
