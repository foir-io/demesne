import { run } from "./engine.js";
import type { Vocabulary } from "./types.js";

export function impliedPermissions(vocab: Vocabulary, perm: string): string[] {
  return run("vocab.impliedPermissions", { vocab, perm });
}

export function expandImplications(vocab: Vocabulary, perms: readonly string[]): string[] {
  return run("vocab.expandImplications", { vocab, perms });
}

export function presetPermissions(vocab: Vocabulary, name: string): string[] {
  return run("vocab.presetPermissions", { vocab, name });
}

export function rankOf(vocab: Vocabulary, preset: string): { index: number; ok: boolean } {
  return run("vocab.rankOf", { vocab, preset });
}

export function presetsAtOrAbove(vocab: Vocabulary, threshold: string): string[] {
  return run("vocab.presetsAtOrAbove", { vocab, threshold });
}
