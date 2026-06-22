/**
 * Level-grant management write SQL (Layer 3) — the control-plane writes over a
 * `grant … via edge` store (operator / impersonation reach), from the Go grant_runtime.go.
 * The active predicate is built from the grant's own active/expiry columns — byte-for-byte
 * the conjuncts the reach definer uses — so management and enforcement agree on "active".
 * Import as a namespace: `levelGrants.grantInsert(surface, …)`.
 */

import type { GrantSurface, ParamStatement, SqlArg } from "./types.js";

/**
 * The "this grant is active" condition from the declared active/expiry columns, prefixed
 * by `prefix` (e.g. "" or "ig."): `<active> IS NULL` AND `<expires> > now()`, whichever
 * are declared. With neither declared a grant is always active, so this returns "TRUE".
 * Mirrors Go `activePredicate`.
 */
export function activePredicate(p: GrantSurface, prefix: string): string {
  const conj: string[] = [];
  if (p.activeCol !== "") conj.push(`${prefix}${p.activeCol} IS NULL`);
  if (p.expiresCol !== "") conj.push(`${prefix}${p.expiresCol} > now()`);
  if (conj.length === 0) return "TRUE";
  return conj.join(" AND ");
}

/**
 * The grant-row projection in canonical order: pk, grantee, level, then whichever
 * audit/validity columns are declared (granted_by, expires, created_at, active, revoked_by),
 * then the extra columns (declaration order). What GrantInsert RETURNs and ListSQL selects.
 */
function grantCols(p: GrantSurface): string[] {
  const cols = [p.pk, p.granteeCol, p.levelCol];
  for (const c of [p.grantedByCol, p.expiresCol, p.createdAtCol, p.activeCol, p.revokedByCol]) {
    if (c !== "") cols.push(c);
  }
  return [...cols, ...p.extraCols];
}

/**
 * The INSERT that issues a grant (the grantee reaches the given level node), plus ordered
 * args. Writes pk, grantee, level, and (when declared) the grantor and expiry; the audit
 * timestamp is left to the table default and active/revoker to NULL (a fresh grant is
 * active). Mirrors Go `GrantInsert`.
 *
 * Args order: grantID, granteeID, levelID, [grantedBy], [expiresAt], extra… (declaration order).
 */
export function grantInsert(
  p: GrantSurface,
  grantID: string,
  granteeID: string,
  levelID: string,
  grantedBy: string,
  expiresAt: SqlArg,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  const cols = [p.pk, p.granteeCol, p.levelCol];
  const args: SqlArg[] = [grantID, granteeID, levelID];
  if (p.grantedByCol !== "") {
    cols.push(p.grantedByCol);
    args.push(grantedBy);
  }
  if (p.expiresCol !== "") {
    cols.push(p.expiresCol);
    args.push(expiresAt);
  }
  for (const c of p.extraCols) {
    cols.push(c);
    args.push(extra[c] ?? null); // a declared col absent from `extra` is written NULL
  }
  const ph = cols.map((_, i) => `$${i + 1}`);
  const sql =
    `INSERT INTO ${p.table} (${cols.join(", ")}) VALUES (${ph.join(", ")}) ` +
    `RETURNING ${grantCols(p).join(", ")}`;
  return { sql, args };
}

/**
 * The revoke, keyed by PK. With an active column it is a SOFT-revoke that stamps it (and
 * the revoker, when declared) on an ACTIVE grant, RETURNING the row; with no active column
 * there is nothing to stamp, so it is a hard DELETE. $1 = grant id; $2 = revoker (only when
 * a revoked-by column is declared). Mirrors Go `RevokeSQL`.
 */
export function revokeSQL(p: GrantSurface): string {
  if (p.activeCol === "") {
    return `DELETE FROM ${p.table} WHERE ${p.pk} = $1`;
  }
  let set = `${p.activeCol} = now()`;
  if (p.revokedByCol !== "") set += `, ${p.revokedByCol} = $2`;
  return `UPDATE ${p.table} SET ${set} WHERE ${p.pk} = $1 AND ${p.activeCol} IS NULL RETURNING ${grantCols(p).join(", ")}`;
}

/**
 * Lists grants with three optional filters, projected as the grant columns, newest first
 * when a created-at column is declared: $1 = grantee (NULL ⇒ any), $2 = level id (NULL ⇒
 * any), $3 = active-only (true ⇒ only currently-active, via the same active predicate the
 * reach definer uses). Mirrors Go `ListSQL`.
 */
export function listSQL(p: GrantSurface): string {
  let sql =
    `SELECT ${grantCols(p).join(", ")} FROM ${p.table} ` +
    `WHERE ($1::text IS NULL OR ${p.granteeCol} = $1) AND ($2::text IS NULL OR ${p.levelCol} = $2) ` +
    `AND (NOT $3::boolean OR (${activePredicate(p, "")}))`;
  if (p.createdAtCol !== "") sql += ` ORDER BY ${p.createdAtCol} DESC`;
  return sql;
}
