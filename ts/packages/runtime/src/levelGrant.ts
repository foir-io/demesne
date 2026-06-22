

import type { GrantSurface, ParamStatement, SqlArg } from "./types.js";

export function activePredicate(p: GrantSurface, prefix: string): string {
  const conj: string[] = [];
  if (p.activeCol !== "") conj.push(`${prefix}${p.activeCol} IS NULL`);
  if (p.expiresCol !== "") conj.push(`${prefix}${p.expiresCol} > now()`);
  if (conj.length === 0) return "TRUE";
  return conj.join(" AND ");
}

function grantCols(p: GrantSurface): string[] {
  const cols = [p.pk, p.granteeCol, p.levelCol];
  for (const c of [p.grantedByCol, p.expiresCol, p.createdAtCol, p.activeCol, p.revokedByCol]) {
    if (c !== "") cols.push(c);
  }
  return [...cols, ...p.extraCols];
}

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
    args.push(extra[c] ?? null);
  }
  const ph = cols.map((_, i) => `$${i + 1}`);
  const sql =
    `INSERT INTO ${p.table} (${cols.join(", ")}) VALUES (${ph.join(", ")}) ` +
    `RETURNING ${grantCols(p).join(", ")}`;
  return { sql, args };
}

export function revokeSQL(p: GrantSurface): string {
  if (p.activeCol === "") {
    return `DELETE FROM ${p.table} WHERE ${p.pk} = $1`;
  }
  let set = `${p.activeCol} = now()`;
  if (p.revokedByCol !== "") set += `, ${p.revokedByCol} = $2`;
  return `UPDATE ${p.table} SET ${set} WHERE ${p.pk} = $1 AND ${p.activeCol} IS NULL RETURNING ${grantCols(p).join(", ")}`;
}

export function listSQL(p: GrantSurface): string {
  let sql =
    `SELECT ${grantCols(p).join(", ")} FROM ${p.table} ` +
    `WHERE ($1::text IS NULL OR ${p.granteeCol} = $1) AND ($2::text IS NULL OR ${p.levelCol} = $2) ` +
    `AND (NOT $3::boolean OR (${activePredicate(p, "")}))`;
  if (p.createdAtCol !== "") sql += ` ORDER BY ${p.createdAtCol} DESC`;
  return sql;
}
