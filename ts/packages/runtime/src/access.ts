/**
 * Per-record access write/read surface (Layer 3) — the runtime over a content object's
 * grant (ACL) store, from the Go access_runtime.go. Read/write SQL the caller executes
 * under RLS (the @store_manage write-moat on the grant store enforces). Import as a
 * namespace: `resourceAccess.grantInsert(surface, …)`.
 */

import type { ResourceAccessSurface, ParamStatement, SqlArg } from "./types.js";

/** Whether a stored mode sentinel opens public read (e.g. "public"). Mirrors Go `IsReadMode`. */
export function isReadMode(p: ResourceAccessSurface, mode: string): boolean {
  return p.readModes.includes(mode);
}

/** Whether the descriptor's grant list admits a principal kind. Mirrors Go `GrantKindAllowed`. */
export function grantKindAllowed(p: ResourceAccessSurface, kind: string): boolean {
  return p.grantKinds.includes(kind);
}

/** Reads a resource's visibility mode: $1 = resource id. Mirrors Go `ModeSQL`. */
export function modeSQL(p: ResourceAccessSurface): string {
  return `SELECT ${p.modeCol} FROM ${p.table} WHERE ${p.pk} = $1`;
}

/** Sets a resource's visibility mode: $1 = mode sentinel, $2 = resource id. Mirrors Go `SetVisibilitySQL`. */
export function setVisibilitySQL(p: ResourceAccessSurface): string {
  return `UPDATE ${p.table} SET ${p.modeCol} = $1 WHERE ${p.pk} = $2`;
}

/**
 * The grant INSERT plus ordered args. `scope` is the containment values root→leaf. The row
 * carries the discriminator constant when the store is shared; ON CONFLICT DO NOTHING makes
 * a re-grant idempotent; RETURNING created_at echoes the grant timestamp. Mirrors Go
 * `GrantInsert`.
 *
 * Args order: scope…, [discrimVal], resourceID, kind, principalID, access.
 */
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

/**
 * The grant DELETE plus ordered args. An empty `access` revokes every level this grantee
 * holds; the discriminator scopes the delete to this resource kind. Placeholders track the
 * args in lockstep ($N = args length after each push). Mirrors Go `RevokeDelete`.
 */
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

/**
 * Selects the explicit grant rows on a resource: (kind, principal, access, created_at),
 * ordered by created_at. $1 = resource id; the discriminator binds to $2 when the store is
 * shared. Pair with {@link listGrantsArgs}. Mirrors Go `ListGrantsSQL`.
 */
export function listGrantsSQL(p: ResourceAccessSurface): string {
  let sql = `SELECT ${p.kindCol}, ${p.principalCol}, ${p.accessCol}, created_at FROM ${p.aclTable} WHERE ${p.recordCol} = $1`;
  if (p.discrimCol !== "") sql += ` AND ${p.discrimCol} = $2`;
  return sql + " ORDER BY created_at";
}

/** Args for {@link listGrantsSQL}: $1 = resource id, plus the discriminator constant when shared. Mirrors Go `ListGrantsArgs`. */
export function listGrantsArgs(p: ResourceAccessSurface, resourceID: string): SqlArg[] {
  if (p.discrimCol !== "") return [resourceID, p.discrimVal];
  return [resourceID];
}

/**
 * Runs the Expand enumerator: the generated SECURITY DEFINER `auth.<table>_accessors($1)`
 * → rows of (source, principal_kind, principal_id, access). $1 = resource id. Mirrors Go
 * `AccessorsSQL`.
 */
export function accessorsSQL(p: ResourceAccessSurface): string {
  return `SELECT source, principal_kind, principal_id, access FROM ${p.accessorFn}($1)`;
}
