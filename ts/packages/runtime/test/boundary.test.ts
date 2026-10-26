import { describe, it, expect } from "vitest";
import { composeCan, Decision } from "../src/index.js";
import { call } from "../src/wasm/demesne_runtime_wasm.js";

const claims = { setting: "request.jwt.claims", cast: "json", role: "authenticated", contract: [], entries: [], subjects: [], levels: [] };
const refused = (op: string, args: unknown) => JSON.parse(call(op, JSON.stringify(args))).error;

describe("the runtime refuses an argument of the wrong type instead of reading it as empty", () => {
  it("refuses a decision it doesn't know rather than treating it as ungoverned", () => {
    expect(() => composeCan(true, true, "DENY" as Decision)).toThrow('demesne runtime: pdp.composeCan: pdp must be "allow", "deny" or "ungoverned"');
    expect(composeCan(true, true, Decision.Deny)).toBe(Decision.Deny);
  });

  it("refuses a list holding something other than a string", () => {
    expect(refused("holds.scopeContains", { assignment: ["t1", null], query: ["t1", "p1"] })).toBe(
      "demesne runtime: holds.scopeContains: assignment must be an array of strings",
    );
    expect(refused("roles.resolve", { assignments: [{ scope: [null, "p1"], roleKey: "r", permissions: [] }], scope: ["t1", "p1"] })).toBe(
      "demesne runtime: roles.resolve: assignments[0].scope must be an array of strings",
    );
  });

  it("refuses a missing flag rather than choosing a session-wide setting", () => {
    expect(refused("claims.setRoleSQL", { claims })).toBe("demesne runtime: claims.setRoleSQL: local must be a boolean");
    expect(JSON.parse(call("claims.setRoleSQL", JSON.stringify({ claims, local: true })))).toEqual({ ok: "SET LOCAL ROLE authenticated" });
  });

  it("refuses a negative depth, a malformed projection and arguments that aren't an object", () => {
    expect(refused("holds.withinPlane", { scope: [], depth: -1 })).toBe("demesne runtime: holds.withinPlane: depth must be a non-negative integer");
    expect(refused("claims.setRoleSQL", { claims: { ...claims, role: 7 }, local: true })).toBe(
      "demesne runtime: claims.setRoleSQL: claims.role must be a string",
    );
    expect(refused("roles.new", [])).toBe("demesne runtime: roles.new: the arguments must be an object");
  });
});
