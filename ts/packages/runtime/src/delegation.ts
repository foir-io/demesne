

import { goSort } from "./goCompat.js";
import type { Vocabulary, DelegationCap } from "./types.js";

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
