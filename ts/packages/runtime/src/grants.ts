

export function touchOnConflict(
  bareKey: readonly string[],
  nullableKey: readonly string[],
  sets: readonly string[],
): string {
  const key = [...bareKey, ...nullableKey.map((c) => `COALESCE(${c}, '')`)];
  return `ON CONFLICT (${key.join(", ")}) DO UPDATE SET ${sets.join(", ")}`;
}
