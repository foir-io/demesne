import { run } from "./engine.js";
import type { Vocabulary, DelegationCap } from "./types.js";

export function capGrant(vocab: Vocabulary, held: readonly string[], requested: readonly string[]): DelegationCap {
  return run("vocab.capGrant", { vocab, held, requested });
}
