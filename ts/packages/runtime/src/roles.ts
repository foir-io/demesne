

import { goSort } from "./goCompat.js";
import { scopeContains } from "./holds.js";
import type { RoleAssignment } from "./types.js";

export interface EffectiveRoles {
  holds(roleKey: string): boolean;

  roles(): string[];
}

function makeEffectiveRoles(roles: Set<string>): EffectiveRoles {
  return {
    holds: (roleKey) => roles.has(roleKey),
    roles: () => goSort([...roles]),
  };
}

export function newEffectiveRoles(keys: readonly string[]): EffectiveRoles {
  const roles = new Set<string>();
  for (const k of keys) if (k !== "") roles.add(k);
  return makeEffectiveRoles(roles);
}

function scopeAllEmpty(scope: readonly string[]): boolean {
  for (const s of scope) if (s !== "") return false;
  return true;
}

export function resolveRoles(
  assignments: readonly RoleAssignment[],
  scope: readonly string[],
): EffectiveRoles {
  const roles = new Set<string>();
  for (const a of assignments) {
    if (a.roleKey === "") continue;
    if (scopeAllEmpty(a.scope) || scopeContains(a.scope, scope)) roles.add(a.roleKey);
  }
  return makeEffectiveRoles(roles);
}
