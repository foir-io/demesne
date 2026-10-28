import { run } from "./engine.js";
import type { HoldsResolver, RoleAssignment } from "./types.js";

export function planeDepth(r: HoldsResolver): number {
  return run("holds.planeDepth", { resolver: r });
}

export function selectedScopeCols(r: HoldsResolver): string[] {
  return run("holds.selectedScopeCols", { resolver: r });
}

export function assignmentsSQL(r: HoldsResolver): string {
  return run("holds.assignmentsSQL", { resolver: r });
}

export interface EffectivePerms {
  holds(perm: string): boolean;

  permissions(): string[];
}

export function scopeContains(assignment: readonly string[], query: readonly string[]): boolean {
  return run("holds.scopeContains", { assignment, query });
}

export function withinPlane(scope: readonly string[], depth: number): boolean {
  return run("holds.withinPlane", { scope, depth });
}

export function resolve(
  resolver: HoldsResolver,
  assignments: readonly RoleAssignment[],
  scope: readonly string[],
): EffectivePerms {
  const perms = run<string[]>("holds.resolve", { resolver, assignments, scope });
  const held = new Set(perms);
  return { holds: (perm) => held.has(perm), permissions: () => [...perms] };
}
