/**
 * App-level read surface (Layer 2) — the ergonomic "can this subject do X to this row?"
 * builders from the Go app_surface.go. Every statement runs UNDER the subject's minted
 * claims + RLS role; the live RLS predicate decides (equal by delegation). Row identity
 * binds to $1. The EID-350 fast-path / async / edit strings are precomputed by the
 * engine and carried on the projection — the runtime templates or passes them through,
 * never recomputing them.
 */

import type { AppObjectSurface } from "./types.js";

/**
 * The point read-check: whether the subject can SEE the row whose id binds to $1.
 * Byte-identical to the engine's PointCheckSQL (equal-by-delegation), so the app-level
 * answer cannot drift from the enforced predicate. Mirrors Go `AppObjectSurface.CheckSQL`.
 */
export function checkSQL(o: AppObjectSurface): string {
  return `SELECT EXISTS (SELECT 1 FROM ${o.table} WHERE ${o.pk} = $1)`;
}

/**
 * The batched point-check: $1 binds an array of row ids; returns the PK of each one the
 * subject can see (RLS drops the rest). Mirrors Go `AppObjectSurface.CheckManySQL`.
 */
export function checkManySQL(o: AppObjectSurface): string {
  return `SELECT ${o.pk} FROM ${o.table} WHERE ${o.pk} = ANY($1)`;
}

/**
 * The keyset-paginated list of the rows the subject can SEE, in PK order. $1 = the
 * after-cursor (NULL for the first page); $2 = page size. PKs are cast to text so a NULL
 * first-page cursor has a determinable type and the keyset/order share one total order.
 * Mirrors Go `AppObjectSurface.ListResourcesSQL`.
 */
export function listResourcesSQL(o: AppObjectSurface): string {
  return `SELECT ${o.pk} FROM ${o.table} WHERE ($1::text IS NULL OR ${o.pk}::text > $1::text) ORDER BY ${o.pk}::text LIMIT $2`;
}

/**
 * The write/edit point-check (EID-350): "visible AND editable". The precomputed string
 * inlines the object's UPDATE policy predicate, or "" when the object has no `@rls
 * update` permission. Mirrors Go `AppObjectSurface.CheckEditSQL`.
 */
export function checkEditSQL(o: AppObjectSurface): string {
  return o.editCheckSQL;
}

/**
 * The materialized-flat fast-path variant of {@link listResourcesSQL}, valid ONLY when
 * `flatListFn` is set (a single-term, exclusion-free materialized via-group SELECT). It
 * narrows the scan via `<pk> IN (SELECT <flat>_resources())` so the keyset LIMIT pushes
 * down; it STILL runs under RLS (a candidate hint, not a second evaluator). "" when the
 * object is not fast-path-eligible. Mirrors Go `AppObjectSurface.ListResourcesFastSQL`.
 */
export function listResourcesFastSQL(o: AppObjectSurface): string {
  if (o.flatListFn === "") return "";
  return `SELECT ${o.pk} FROM ${o.table} WHERE ${o.pk} IN (SELECT ${o.flatListFn}()) AND ($1::text IS NULL OR ${o.pk}::text > $1::text) ORDER BY ${o.pk}::text LIMIT $2`;
}
