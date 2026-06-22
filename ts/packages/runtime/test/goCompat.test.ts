import { describe, it, expect } from "vitest";
import { goCmp, goSort, goEncodeString, goJSONStringify } from "../src/goCompat.js";

const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);

describe("goJSONStringify — byte-identical to Go encoding/json.Marshal(map[string]string)", () => {

  const cases: Array<[Record<string, string>, string]> = [
    [
      { tenant_id: "t1", project_id: "p1", customer_id: "c1" },
      '{"customer_id":"c1","project_id":"p1","tenant_id":"t1"}',
    ],
    [{ b: "2", a: "1", c: "3" }, '{"a":"1","b":"2","c":"3"}'],
    [{}, "{}"],
    [{ k: "" }, '{"k":""}'],
    [{ html: "a<b>c&d" }, '{"html":"a\\u003cb\\u003ec\\u0026d"}'],
    [{ quote: 'he said "hi"\\back' }, '{"quote":"he said \\"hi\\"\\\\back"}'],
    [{ ctrl: "tab\there\nnl" }, '{"ctrl":"tab\\there\\nnl"}'],
    [{ uni: "café—ok" }, '{"uni":"café—ok"}'],
    [{ ls: "line" + LS + "sep" + PS + "para" }, '{"ls":"line\\u2028sep\\u2029para"}'],
    [{ slash: "a/b" }, '{"slash":"a/b"}'],
    [{ Z: "1", a: "2", _x: "3", "0": "4" }, '{"0":"4","Z":"1","_x":"3","a":"2"}'],
  ];
  it.each(cases)("marshals %o", (input, expected) => {
    expect(goJSONStringify(input)).toBe(expected);
  });
});

describe("goEncodeString", () => {
  it("includes the surrounding quotes", () => {
    expect(goEncodeString("abc")).toBe('"abc"');
    expect(goEncodeString("")).toBe('""');
  });
  it("HTML-escapes < > & like Go (default encoder)", () => {
    expect(goEncodeString("a<b>c&d")).toBe('"a\\u003cb\\u003ec\\u0026d"');
  });
  it("escapes U+2028 / U+2029", () => {
    expect(goEncodeString(LS)).toBe('"\\u2028"');
    expect(goEncodeString(PS)).toBe('"\\u2029"');
  });
  it("does NOT escape the forward slash (Go does not)", () => {
    expect(goEncodeString("a/b")).toBe('"a/b"');
  });
});

describe("goSort — Go sort.Strings byte order", () => {
  it("orders by ASCII byte value: digits, then uppercase, underscore, lowercase", () => {
    expect(goSort(["a", "Z", "_x", "0", "B"])).toEqual(["0", "B", "Z", "_x", "a"]);
  });
  it("returns a new array and does not mutate the input", () => {
    const xs = ["b", "a"];
    const sorted = goSort(xs);
    expect(sorted).toEqual(["a", "b"]);
    expect(xs).toEqual(["b", "a"]);
  });
});

describe("goCmp", () => {
  it("returns -1 / 0 / 1", () => {
    expect(goCmp("a", "b")).toBe(-1);
    expect(goCmp("b", "a")).toBe(1);
    expect(goCmp("a", "a")).toBe(0);
  });
});
