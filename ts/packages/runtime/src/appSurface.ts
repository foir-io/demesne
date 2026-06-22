

import type { AppObjectSurface } from "./types.js";

export function checkSQL(o: AppObjectSurface): string {
  return `SELECT EXISTS (SELECT 1 FROM ${o.table} WHERE ${o.pk} = $1)`;
}

export function checkManySQL(o: AppObjectSurface): string {
  return `SELECT ${o.pk} FROM ${o.table} WHERE ${o.pk} = ANY($1)`;
}

export function listResourcesSQL(o: AppObjectSurface): string {
  return `SELECT ${o.pk} FROM ${o.table} WHERE ($1::text IS NULL OR ${o.pk}::text > $1::text) ORDER BY ${o.pk}::text LIMIT $2`;
}

export function checkEditSQL(o: AppObjectSurface): string {
  return o.editCheckSQL;
}

export function listResourcesFastSQL(o: AppObjectSurface): string {
  if (o.flatListFn === "") return "";
  return `SELECT ${o.pk} FROM ${o.table} WHERE ${o.pk} IN (SELECT ${o.flatListFn}()) AND ($1::text IS NULL OR ${o.pk}::text > $1::text) ORDER BY ${o.pk}::text LIMIT $2`;
}
