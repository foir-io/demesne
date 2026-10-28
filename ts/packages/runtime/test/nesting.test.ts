import { describe, it, expect } from "vitest";
import "../src/index.js";
import { call } from "../src/wasm/demesne_runtime_wasm.js";

const MAX_DEPTH = 128;

const args = (depth: number) => `{"keys":["a"],"deep":${"[".repeat(depth - 1)}${"]".repeat(depth - 1)}}`;
const refused = { error: "demesne runtime: roles.new: json: invalid character '[' exceeded max depth" };

describe("the runtime refuses JSON nested past its depth limit and keeps answering", () => {
  it("accepts arguments nested to the limit", () => {
    expect(JSON.parse(call("roles.new", args(MAX_DEPTH)))).toEqual({ ok: ["a"] });
  });

  it("refuses arguments one level deeper", () => {
    expect(JSON.parse(call("roles.new", args(MAX_DEPTH + 1)))).toEqual(refused);
  });

  it("still answers after arguments deep enough to exhaust the stack", () => {
    expect(JSON.parse(call("roles.new", args(100_000)))).toEqual(refused);
    expect(JSON.parse(call("roles.new", '{"keys":["b"]}'))).toEqual({ ok: ["b"] });
  });
});
