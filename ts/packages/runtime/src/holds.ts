

import { goSort } from "./goCompat.js";
import { expandImplications, presetPermissions } from "./vocabulary.js";
import type { HoldsResolver, RoleAssignment } from "./types.js";

export function planeDepth(r: HoldsResolver): number {
  if (r.plane === undefined || r.plane === "") return r.scopeCols.length;
  const d = r.planeDepth ?? 0;
  if (d < 0) return 0;
  if (d > r.scopeCols.length) return r.scopeCols.length;
  return d;
}

export function selectedScopeCols(r: HoldsResolver): string[] {
  return r.scopeCols.slice(0, planeDepth(r));
}

export function assignmentsSQL(r: HoldsResolver): string {
  const cols = selectedScopeCols(r).map((c) => `ra.${c}`);
  cols.push(`r.${r.keyCol}`);
  if (r.permsCol !== "") cols.push(`r.${r.permsCol}`);
  const conds: string[] = [];
  if (r.kindCol !== "") conds.push(`ra.${r.kindCol} = '${r.kindVal}'`);
  conds.push(`ra.${r.subjectCol} = $1`);
  if (r.revokedCol !== "") conds.push(`ra.${r.revokedCol} IS NULL`);
  for (const c of r.scopeCols.slice(planeDepth(r))) conds.push(`ra.${c} IS NULL`);
  return (
    `SELECT ${cols.join(", ")} FROM ${r.assignments} ra JOIN ${r.rolesTable} r ON r.${r.rolesId} = ra.${r.roleCol} ` +
    `WHERE ${conds.join(" AND ")}`
  );
}

export interface EffectivePerms {

  holds(perm: string): boolean;

  permissions(): string[];
}

function makeEffectivePerms(perms: Set<string>): EffectivePerms {

  return {
    holds: (perm) => perms.has(perm),
    permissions: () => goSort([...perms]),
  };
}

export function scopeContains(assignment: readonly string[], query: readonly string[]): boolean {
  for (let i = 0; i < assignment.length; i++) {
    const a = assignment[i]!;
    if (a === "") continue;
    if (i >= query.length || query[i] !== a) return false;
  }
  return true;
}

export function withinPlane(scope: readonly string[], depth: number): boolean {
  for (let i = depth; i < scope.length; i++) {
    if (scope[i] !== "") return false;
  }
  return true;
}

export function resolve(
  resolver: HoldsResolver,
  assignments: readonly RoleAssignment[],
  scope: readonly string[],
): EffectivePerms {
  const depth = planeDepth(resolver);
  const perms = new Set<string>();
  for (const a of assignments) {
    if (!withinPlane(a.scope, depth)) continue;
    if (!scopeContains(depth < a.scope.length ? a.scope.slice(0, depth) : a.scope, scope)) continue;
    let contributed: string[];
    if (resolver.permsCol !== "") {

      contributed = a.permissions;
    } else {
      try {
        contributed = presetPermissions(resolver.vocab, a.roleKey);
      } catch (e) {
        throw new Error(`resolve: assignment role "${a.roleKey}": ${(e as Error).message}`);
      }
    }
    for (const p of expandImplications(resolver.vocab, contributed)) perms.add(p);
  }
  return makeEffectivePerms(perms);
}
