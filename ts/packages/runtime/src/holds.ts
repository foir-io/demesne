/**
 * The holds-resolver COMPUTE (Layer 2) — `scopeContains` and `Resolve` from the Go
 * holds.go. Given the assignments the database returned (via the read SQL, added in a
 * later increment) it applies the scope-containment match and unions the matched
 * assignments' permissions into the effective set. Pure stdlib, no policy
 * re-evaluation: it folds rows the DB already returned. The result's `holds(perm)` IS
 * the callback `authorize` takes, so the full Layer-2 decision is
 * `authorize(pdp, proc, eff.holds)`.
 */

import { goSort } from "./goCompat.js";
import { presetPermissions } from "./vocabulary.js";
import type { HoldsResolver, RoleAssignment } from "./types.js";

/** A principal's resolved effective permission set at a scope. Mirrors Go `EffectivePerms`. */
export interface EffectivePerms {
  /** Whether the resolved set grants a permission — the `authorize` callback. */
  holds(perm: string): boolean;
  /** The resolved effective set, sorted (deterministic). */
  permissions(): string[];
}

function makeEffectivePerms(perms: Set<string>): EffectivePerms {
  // holds / permissions are closures over `perms` (not `this`-methods), so `eff.holds`
  // can be passed standalone as the authorize callback exactly like Go's bound method value.
  return {
    holds: (perm) => perms.has(perm),
    permissions: () => goSort([...perms]),
  };
}

/**
 * Reports whether an assignment scope contains (is an ancestor-or-equal of) a query
 * scope, position by position over the shared root→leaf order. The ROOT column (index 0,
 * the tenancy boundary) requires strict equality — an empty/unpinned root matches ONLY
 * an empty-root query. Every level below the root is a wildcard when the assignment
 * leaves it empty (a grant pinned at level k covers k's whole subtree); a pinned deeper
 * level must be pinned-and-equal in the query. A query shorter than the assignment
 * treats the missing tail as unpinned. Mirrors Go `scopeContains`.
 */
export function scopeContains(assignment: readonly string[], query: readonly string[]): boolean {
  for (let i = 0; i < assignment.length; i++) {
    const a = assignment[i]!;
    if (i === 0) {
      // Root: strict equality, never wildcarded (the tenancy boundary).
      if (i >= query.length || query[i] !== a) return false;
      continue;
    }
    if (a === "") continue; // a deeper unpinned level wildcards over its subtree
    if (i >= query.length || query[i] !== a) return false;
  }
  return true;
}

/**
 * Computes a principal's effective permission set at a query scope from the assignments
 * the read returned. Keeps every assignment whose scope CONTAINS the query scope and
 * unions their permissions: the materialized column when the rolestore declares one
 * (`permsCol !== ""`), otherwise the role key expanded through the vocabulary. The branch
 * is per-RESOLVER (does this rolestore materialize?), not per-row, so a role that
 * legitimately grants nothing yields the empty set rather than a key expansion. Throws if
 * a non-materialized role key fails to expand (fail-closed). Mirrors Go `Resolve`.
 */
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
      // Materialized: the stored set (covers a custom role not in the vocabulary). Empty → grants nothing.
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
