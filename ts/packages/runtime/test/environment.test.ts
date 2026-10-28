import { describe, it, expect } from "vitest";
import { composeCan, Decision } from "../src/index.js";

declare const Deno: unknown;
declare const document: unknown;
declare const navigator: { userAgent?: string } | undefined;

function runtime(): string {
  if (typeof Deno !== "undefined") return "deno";
  if (typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers") return "workerd";
  if (typeof document !== "undefined") return "browser";
  return "node";
}

const expected = (import.meta as { env?: Record<string, string | undefined> }).env?.["VITE_DEMESNE_RUNTIME"];

describe("the runtime runs where the suite says it does", () => {
  it.runIf(expected !== undefined)(`runs under ${expected}`, () => {
    expect(runtime()).toBe(expected);
  });

  it("calls into the WebAssembly runtime", () => {
    expect(composeCan(true, true, Decision.NotGoverned)).toBe(Decision.Allow);
  });
});
