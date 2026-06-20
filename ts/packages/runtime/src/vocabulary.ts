/**
 * Vocabulary expansion (Layer 2) — preset → permissions, and the rank-ladder helpers.
 * Pure compute over the vocabulary projection; mirrors the `Vocabulary` methods in the
 * Go holds.go. Sorted outputs use Go byte order (see goCompat). Errors are thrown (the
 * TS analogue of Go's returned error), fail-closed: a cyclic or dangling preset resolves
 * to no answer, never a partial one.
 */

import { goSort } from "./goCompat.js";
import type { Vocabulary, Preset } from "./types.js";

function presetByName(vocab: Vocabulary, name: string): Preset | undefined {
  return vocab.presets.find((p) => p.name === name);
}

/**
 * Expands a preset to its FLAT effective permission set: the whole vocabulary for a `*`
 * (star) preset, otherwise the union of the preset's own permission keys and the
 * recursive expansion of every preset it references. Deduplicated and sorted. Throws on
 * an unknown preset, a reference that is neither a permission nor a preset, or a cycle.
 * Mirrors Go `Vocabulary.PresetPermissions`.
 */
export function presetPermissions(vocab: Vocabulary, name: string): string[] {
  const into = new Set<string>();
  expandPreset(vocab, name, into, new Set<string>());
  return goSort([...into]);
}

function expandPreset(vocab: Vocabulary, name: string, into: Set<string>, onStack: Set<string>): void {
  if (onStack.has(name)) {
    throw new Error(
      `vocabulary "${vocab.name}": preset "${name}" is cyclic (a preset cannot reference itself, directly or transitively)`,
    );
  }
  const p = presetByName(vocab, name);
  if (p === undefined) {
    throw new Error(`vocabulary "${vocab.name}": no preset "${name}"`);
  }
  if (p.star) {
    for (const perm of vocab.permissions) into.add(perm);
    return;
  }
  const perms = new Set(vocab.permissions);
  onStack.add(name);
  try {
    for (const item of p.set) {
      if (perms.has(item)) {
        into.add(item);
      } else if (presetByName(vocab, item) !== undefined) {
        expandPreset(vocab, item, into, onStack);
      } else {
        throw new Error(
          `vocabulary "${vocab.name}": preset "${name}" references "${item}", which is neither a permission nor a preset in this vocabulary`,
        );
      }
    }
  } finally {
    onStack.delete(name);
  }
}

/**
 * A preset's position in the rank ladder (0 = highest authority) and whether it is
 * ranked. An unranked vocabulary or preset returns `{ index: 0, ok: false }` — check
 * `ok`, since index 0 is also valid. Mirrors Go `Vocabulary.RankOf`.
 */
export function rankOf(vocab: Vocabulary, preset: string): { index: number; ok: boolean } {
  const i = vocab.rank.indexOf(preset);
  return i >= 0 ? { index: i, ok: true } : { index: 0, ok: false };
}

/**
 * The ranked presets whose authority is >= the threshold — the threshold and everything
 * above it, in ladder order (highest first). An unranked threshold returns `[]` (Go's
 * nil). Mirrors Go `Vocabulary.PresetsAtOrAbove`.
 */
export function presetsAtOrAbove(vocab: Vocabulary, threshold: string): string[] {
  const { index: ti, ok } = rankOf(vocab, threshold);
  if (!ok) return [];
  const out: string[] = [];
  for (let i = 0; i <= ti; i++) out.push(vocab.rank[i]!);
  return out;
}
