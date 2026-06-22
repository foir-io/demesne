

export function goCmp(a: string, b: string): -1 | 0 | 1 {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function goSort(items: readonly string[]): string[] {
  return [...items].sort(goCmp);
}

const LINE_SEP = new RegExp(String.fromCharCode(0x2028), "g");
const PARA_SEP = new RegExp(String.fromCharCode(0x2029), "g");

export function goEncodeString(s: string): string {
  return JSON.stringify(s)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(LINE_SEP, "\\u2028")
    .replace(PARA_SEP, "\\u2029");
}

export function goJSONStringify(obj: Record<string, string>): string {
  const keys = goSort(Object.keys(obj));
  return "{" + keys.map((k) => goEncodeString(k) + ":" + goEncodeString(obj[k]!)).join(",") + "}";
}
