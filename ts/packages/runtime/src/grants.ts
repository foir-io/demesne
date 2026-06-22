/**
 * Shared reachability-grant write helper (Layer 3) — `touchOnConflict` from the Go
 * grants.go. It is GENERAL: it produces the same idempotent reactivate-on-conflict shape
 * for any soft-revoke-aware grant edge (role assignments, level grants), so the
 * role-assignment touch and any other grant-edge touch stay byte-identical.
 */

/**
 * Builds the `ON CONFLICT (...) DO UPDATE SET ...` tail for a reactivating (TOUCH) write.
 * The conflict key is the bare identity columns plus the nullable context columns wrapped
 * in `COALESCE(c, '')` (so a NULL scope/context level participates in the unique key).
 * Mirrors Go `touchOnConflict`.
 */
export function touchOnConflict(
  bareKey: readonly string[],
  nullableKey: readonly string[],
  sets: readonly string[],
): string {
  const key = [...bareKey, ...nullableKey.map((c) => `COALESCE(${c}, '')`)];
  return `ON CONFLICT (${key.join(", ")}) DO UPDATE SET ${sets.join(", ")}`;
}
