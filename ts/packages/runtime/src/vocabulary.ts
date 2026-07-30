

import { goSort } from "./goCompat.js";
import type { Vocabulary, Preset, Implication } from "./types.js";

function presetByName(vocab: Vocabulary, name: string): Preset | undefined {
  return vocab.presets.find((p) => p.name === name);
}

function implicationOf(vocab: Vocabulary, perm: string): Implication | undefined {
  return (vocab.implications ?? []).find((im) => im.perm === perm);
}

function matchWildcard(vocab: Vocabulary, item: string): string[] {
  if (!item.endsWith(":*")) return [];
  const prefix = item.slice(0, -1);
  return vocab.permissions.filter((p) => p.startsWith(prefix));
}

export function impliedPermissions(vocab: Vocabulary, perm: string): string[] {
  const into = new Set<string>();
  expandImplication(vocab, perm, into, new Set<string>());
  return goSort([...into]);
}

function expandImplication(vocab: Vocabulary, perm: string, into: Set<string>, onStack: Set<string>): void {
  if (onStack.has(perm)) {
    throw new Error(
      `vocabulary "${vocab.name}": permission "${perm}" is cyclic (a permission cannot imply itself, directly or transitively)`,
    );
  }
  into.add(perm);
  const im = implicationOf(vocab, perm);
  if (im === undefined) return;
  if (im.star) {
    for (const p of vocab.permissions) into.add(p);
    return;
  }
  onStack.add(perm);
  try {
    for (const item of im.set) {
      let matched = matchWildcard(vocab, item);
      if (matched.length === 0) {
        if (!vocab.permissions.includes(item)) {
          throw new Error(
            `vocabulary "${vocab.name}": permission "${perm}" implies "${item}", which is neither a permission of this vocabulary nor a \`<domain>:*\` wildcard matching one`,
          );
        }
        matched = [item];
      }
      for (const m of matched) expandImplication(vocab, m, into, onStack);
    }
  } finally {
    onStack.delete(perm);
  }
}

export function expandImplications(vocab: Vocabulary, perms: readonly string[]): string[] {
  if ((vocab.implications ?? []).length === 0) return [...perms];
  const out = [...perms];
  for (const p of perms) {
    if (implicationOf(vocab, p) === undefined) continue;
    out.push(...impliedPermissions(vocab, p));
  }
  return out;
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
