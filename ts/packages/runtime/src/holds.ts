

import { goSort } from "./goCompat.js";
import { presetPermissions } from "./vocabulary.js";
import type { HoldsResolver, RoleAssignment } from "./types.js";

export function assignmentsSQL(r: HoldsResolver): string {
  const cols = r.scopeCols.map((c) => `ra.${c}`);
  cols.push(`r.${r.keyCol}`);
  if (r.permsCol !== "") cols.push(`r.${r.permsCol}`);
  return (
    `SELECT ${cols.join(", ")} FROM ${r.assignments} ra JOIN ${r.rolesTable} r ON r.${r.rolesId} = ra.${r.roleCol} ` +
    `WHERE ra.${r.kindCol} = '${r.kindVal}' AND ra.${r.subjectCol} = $1 AND ra.${r.revokedCol} IS NULL`
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
    if (i === 0) {

      if (i >= query.length || query[i] !== a) return false;
      continue;
    }
    if (a === "") continue;
    if (i >= query.length || query[i] !== a) return false;
  }
  return true;
}

export function resolve(
  resolver: HoldsResolver,
  assignments: readonly RoleAssignment[],
  scope: readonly string[],
): EffectivePerms {
  const perms = new Set<string>();
  for (const a of assignments) {
    if (!scopeContains(a.scope, scope)) continue;
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
    for (const p of contributed) perms.add(p);
  }
  return makeEffectivePerms(perms);
}
