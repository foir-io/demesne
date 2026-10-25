import { run } from "./engine.js";

export function touchOnConflict(bareKey: readonly string[], nullableKey: readonly string[], sets: readonly string[]): string {
  return run("grants.touchOnConflict", { bareKey, nullableKey, sets });
}
