/**
 * Go-compatibility primitives — the small set of Go stdlib behaviors the Demesne
 * engine relies on that JavaScript does NOT reproduce out of the box.
 *
 * Every artifact and SQL string this runtime builds must be **byte-identical** to the
 * Go side: the differential oracle (EID-338 / WS6) compares them directly, and a
 * minted claims blob that differs by one escape is a different GUC value the policies
 * read. These helpers close the two gaps that matter:
 *
 *   1. **Ordering.** Go `sort.Strings` / `sort.Slice(...< )` order strings by raw byte
 *      value. For the ASCII-plus identifiers Demesne uses (claim keys, permission
 *      names, column names) that is the same as code-point order, which JS `<` gives —
 *      but `String.prototype.localeCompare` is NOT (it reorders by locale/case). We pin
 *      one explicit comparator, {@link goCmp}, and ban `localeCompare` in this package.
 *
 *   2. **JSON encoding.** Go `encoding/json.Marshal(map[string]string)` emits keys in
 *      byte order, with NO insignificant whitespace, and — HTML escaping is on by
 *      default — escapes `<`, `>`, `&` as `<`, `>`, `&`, plus the Unicode
 *      line/paragraph separators U+2028 / U+2029. `JSON.stringify` preserves insertion
 *      order and escapes none of those. `mintClaims` marshals the claims map, so
 *      {@link goJSONStringify} reproduces Go's encoder exactly.
 *
 * Verified byte-for-byte against `encoding/json` reference output — see
 * `test/goCompat.test.ts`, whose vectors are the literal stdout of a Go program.
 */

/**
 * Code-point string comparator matching Go's byte-wise `sort.Strings`. Returns -1, 0,
 * or 1. Correct for the ASCII-plus inputs Demesne sorts; for strings mixing BMP and
 * astral code points UTF-16 order can differ from UTF-8 byte order, which never occurs
 * for identifier inputs.
 */
export function goCmp(a: string, b: string): -1 | 0 | 1 {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Returns a new array sorted like Go `sort.Strings` (byte/code-point order). Does not
 * mutate the input.
 */
export function goSort(items: readonly string[]): string[] {
  return [...items].sort(goCmp);
}

// The U+2028 / U+2029 patterns are built via String.fromCharCode so this source stays
// pure ASCII (a literal separator character would itself be a line break to the parser).
const LINE_SEP = new RegExp(String.fromCharCode(0x2028), "g");
const PARA_SEP = new RegExp(String.fromCharCode(0x2029), "g");

/**
 * Encodes a single string exactly as Go's `encoding/json` does (HTML escaping on, the
 * default), INCLUDING the surrounding double quotes. Builds on `JSON.stringify` — which
 * already matches Go for `"`, `\`, and the `\b \t \n \f \r` / `\u00xx` control forms —
 * then layers on the escapes Go adds and JS omits: `<`, `>`, `&`, U+2028, U+2029.
 */
export function goEncodeString(s: string): string {
  return JSON.stringify(s)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(LINE_SEP, "\\u2028")
    .replace(PARA_SEP, "\\u2029");
}

/**
 * Serializes a string map exactly as Go `encoding/json.Marshal(map[string]string)`:
 * keys in byte order, no whitespace, each key and value encoded by {@link
 * goEncodeString}. An empty map renders as `{}`. This is what `mintClaims` returns and
 * what the session installs into the claims GUC the RLS policies read.
 */
export function goJSONStringify(obj: Record<string, string>): string {
  const keys = goSort(Object.keys(obj));
  return "{" + keys.map((k) => goEncodeString(k) + ":" + goEncodeString(obj[k]!)).join(",") + "}";
}
