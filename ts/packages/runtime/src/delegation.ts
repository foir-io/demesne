/**
 * The delegation cap (Layer 3) — the generic ReBAC guard "you cannot grant a permission
 * you do not hold." Pure compute, no SQL: it folds the vocabulary's permission list and
 * the grantor's effective held set (the `EffectivePerms` the holds-resolver produces).
 * The OTHER gates a real grant guard composes (a rank floor, a higher-plane bypass, the
 * principal-kind check) are adopter policy a caller layers around this. Mirrors Go
 * `Vocabulary.CapGrant`.
 */

import { goSort } from "./goCompat.js";
import type { Vocabulary, DelegationCap } from "./types.js";

/**
 * Computes the delegation cap: a grantor holding `held` may confer `requested` iff every
 * requested permission is (a) a real permission of this vocabulary AND (b) one the
 * grantor itself holds. Reports the two failure classes separately — `unknown` (outside
 * the vocabulary) and `excess` (valid but unheld) — disjoint, sorted, de-duplicated. An
 * empty `requested` is vacuously allowed.
 */
export function capGrant(vocab: Vocabulary, held: readonly string[], requested: readonly string[]): DelegationCap {
  const inVocab = new Set(vocab.permissions);
  const heldSet = new Set(held);
  const unknown: string[] = [];
  const excess: string[] = [];
  const seenU = new Set<string>();
  const seenE = new Set<string>();
  for (const p of requested) {
    if (!inVocab.has(p)) {
      if (!seenU.has(p)) {
        seenU.add(p);
        unknown.push(p);
      }
    } else if (!heldSet.has(p)) {
      // A VALID permission the grantor does not hold — the cap violation.
      if (!seenE.has(p)) {
        seenE.add(p);
        excess.push(p);
      }
    }
  }
  const u = goSort(unknown);
  const e = goSort(excess);
  return { allowed: u.length === 0 && e.length === 0, unknown: u, excess: e };
}
