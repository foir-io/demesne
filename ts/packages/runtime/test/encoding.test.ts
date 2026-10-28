import { describe, it, expect } from "vitest";
import { mintClaimsValuesWithExtra, presetPermissions } from "../src/index.js";
import type { Vocabulary } from "../src/index.js";

const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);

describe("minted claims are byte-identical to Go encoding/json.Marshal(map[string]string)", () => {
  const cases: Array<[Record<string, string>, string]> = [
    [{ tenant_id: "t1", project_id: "p1", customer_id: "c1" }, '{"customer_id":"c1","project_id":"p1","tenant_id":"t1"}'],
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
  it.each(cases)("mints %o", (values, expected) => {
    expect(mintClaimsValuesWithExtra(Object.keys(values), values)).toBe(expected);
  });
});

describe("permissions come back in Go's byte order", () => {
  it("orders digits, uppercase, underscore, then lowercase, and astral characters after the BMP by UTF-8", () => {
    const vocab: Vocabulary = {
      name: "v",
      permissions: ["a:x", "Z:x", "_x:y", "0:z", "B:q", "\u{1F600}:s", "～:t"],
      presets: [{ name: "all", star: true, set: [] }],
      rank: [],
    };
    expect(presetPermissions(vocab, "all")).toEqual(["0:z", "B:q", "Z:x", "_x:y", "a:x", "～:t", "\u{1F600}:s"]);
  });
});
