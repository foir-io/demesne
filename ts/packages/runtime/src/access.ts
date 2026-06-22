

import type { ResourceAccessSurface, ParamStatement, SqlArg } from "./types.js";

export function isReadMode(p: ResourceAccessSurface, mode: string): boolean {
  return p.readModes.includes(mode);
}

export function grantKindAllowed(p: ResourceAccessSurface, kind: string): boolean {
  return p.grantKinds.includes(kind);
}

export function modeSQL(p: ResourceAccessSurface): string {
  return `SELECT ${p.modeCol} FROM ${p.table} WHERE ${p.pk} = $1`;
}

export function setVisibilitySQL(p: ResourceAccessSurface): string {
  return `UPDATE ${p.table} SET ${p.modeCol} = $1 WHERE ${p.pk} = $2`;
}

export function grantInsert(
  p: ResourceAccessSurface,
  scope: readonly string[],
  resourceID: string,
  kind: string,
  principalID: string,
  access: string,
): ParamStatement {
  const cols = [...p.scopeCols];
  const args: SqlArg[] = [...scope];
  if (p.discrimCol !== "") {
    cols.push(p.discrimCol);
    args.push(p.discrimVal);
  }
  cols.push(p.recordCol, p.kindCol, p.principalCol, p.accessCol);
  args.push(resourceID, kind, principalID, access);

  const ph = cols.map((_, i) => `$${i + 1}`);
  const conflict: string[] = [];
  if (p.discrimCol !== "") conflict.push(p.discrimCol);
  conflict.push(p.recordCol, p.kindCol, p.principalCol, p.accessCol);

  const sql =
    `INSERT INTO ${p.aclTable} (${cols.join(", ")}) VALUES (${ph.join(", ")}) ` +
    `ON CONFLICT (${conflict.join(", ")}) DO NOTHING RETURNING created_at`;
  return { sql, args };
}

export function revokeDelete(
  p: ResourceAccessSurface,
  resourceID: string,
  kind: string,
  principalID: string,
  access: string,
): ParamStatement {
  const conds: string[] = [];
  const args: SqlArg[] = [];
  const add = (col: string, val: SqlArg): void => {
    args.push(val);
    conds.push(`${col} = $${args.length}`);
  };
  add(p.recordCol, resourceID);
  if (p.discrimCol !== "") add(p.discrimCol, p.discrimVal);
  add(p.kindCol, kind);
  add(p.principalCol, principalID);
  if (access !== "") add(p.accessCol, access);
  return { sql: `DELETE FROM ${p.aclTable} WHERE ${conds.join(" AND ")}`, args };
}

export function listGrantsSQL(p: ResourceAccessSurface): string {
  let sql = `SELECT ${p.kindCol}, ${p.principalCol}, ${p.accessCol}, created_at FROM ${p.aclTable} WHERE ${p.recordCol} = $1`;
  if (p.discrimCol !== "") sql += ` AND ${p.discrimCol} = $2`;
  return sql + " ORDER BY created_at";
}

export function listGrantsArgs(p: ResourceAccessSurface, resourceID: string): SqlArg[] {
  if (p.discrimCol !== "") return [resourceID, p.discrimVal];
  return [resourceID];
}

export function accessorsSQL(p: ResourceAccessSurface): string {
  return `SELECT source, principal_kind, principal_id, access FROM ${p.accessorFn}($1)`;
}
