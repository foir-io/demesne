import { describe, it, expect } from "vitest";
import { capGrant, presetsAtOrAbove } from "../src/index.js";
import { capVocab } from "./fixtures.js";

describe("capGrant — the intersection cap", () => {
  it("a subset of held is allowed cleanly", () => {
    const got = capGrant(capVocab, ["a:read", "a:write", "b:read"], ["a:read", "b:read"]);
    expect(got).toEqual({ allowed: true, unknown: [], excess: [] });
  });
  it("granting your full held set is allowed", () => {
    const held = ["a:read", "a:write", "b:read"];
    expect(capGrant(capVocab, held, held).allowed).toBe(true);
  });
  it("an empty request is vacuously allowed", () => {
    expect(capGrant(capVocab, [], []).allowed).toBe(true);
  });

  it("valid-but-unheld perms are Excess (sorted), denied", () => {
    const got = capGrant(capVocab, ["a:read", "b:read"], ["a:read", "b:write", "a:write"]);
    expect(got.allowed).toBe(false);
    expect(got.excess).toEqual(["a:write", "b:write"]);
    expect(got.unknown).toEqual([]);
  });

  it("out-of-vocabulary perms are Unknown, disjoint from Excess", () => {
    const got = capGrant(capVocab, ["a:read"], ["a:read", "zzz:bogus", "qqq:nope", "b:read"]);
    expect(got.allowed).toBe(false);
    expect(got.unknown).toEqual(["qqq:nope", "zzz:bogus"]);
    expect(got.excess).toEqual(["b:read"]);
  });

  it("de-duplicates both reports", () => {
    const got = capGrant(capVocab, ["a:read"], ["b:write", "b:write", "zzz", "zzz"]);
    expect(got.excess).toEqual(["b:write"]);
    expect(got.unknown).toEqual(["zzz"]);
  });
});

describe("rank-floor composition (the shape a real grant guard wraps)", () => {
  const atOrAbove = presetsAtOrAbove(capVocab, "editor");
  const meetsFloor = (role: string) => atOrAbove.includes(role);
  const guard = (role: string, held: string[], requested: string[]) =>
    meetsFloor(role) && capGrant(capVocab, held, requested).allowed;

  const held = ["a:read", "b:read"];

  it("the floor admits owner + editor, not viewer", () => {
    expect(atOrAbove).toEqual(["owner", "editor"]);
  });
  it("a below-floor grantor is denied even when the cap alone would allow", () => {
    expect(capGrant(capVocab, held, ["a:read"]).allowed).toBe(true);
    expect(guard("viewer", held, ["a:read"])).toBe(false);
  });
  it("an at-floor grantor granting a held subset passes; an unheld perm is still capped", () => {
    expect(guard("editor", held, ["a:read"])).toBe(true);
    expect(guard("editor", held, ["a:write"])).toBe(false);
  });
});
