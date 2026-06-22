

import { goSort } from "./goCompat.js";
import type { Vocabulary, Preset } from "./types.js";

function presetByName(vocab: Vocabulary, name: string): Preset | undefined {
  return vocab.presets.find((p) => p.name === name);
}

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

export function rankOf(vocab: Vocabulary, preset: string): { index: number; ok: boolean } {
  const i = vocab.rank.indexOf(preset);
  return i >= 0 ? { index: i, ok: true } : { index: 0, ok: false };
}

export function presetsAtOrAbove(vocab: Vocabulary, threshold: string): string[] {
  const { index: ti, ok } = rankOf(vocab, threshold);
  if (!ok) return [];
  const out: string[] = [];
  for (let i = 0; i <= ti; i++) out.push(vocab.rank[i]!);
  return out;
}
