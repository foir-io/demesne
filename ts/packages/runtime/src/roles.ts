import { run } from "./engine.js";
import type { RoleAssignment } from "./types.js";

export interface EffectiveRoles {
  holds(roleKey: string): boolean;

  roles(): string[];
}

function effectiveRoles(roles: string[]): EffectiveRoles {
  const held = new Set(roles);
  return { holds: (roleKey) => held.has(roleKey), roles: () => [...roles] };
}

export function newEffectiveRoles(keys: readonly string[]): EffectiveRoles {
  return effectiveRoles(run("roles.new", { keys }));
}

export function resolveRoles(assignments: readonly RoleAssignment[], scope: readonly string[]): EffectiveRoles {
  return effectiveRoles(run("roles.resolve", { assignments, scope }));
}
