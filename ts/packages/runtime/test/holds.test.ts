import { describe, it, expect } from "vitest";
import { scopeContains, resolve, type RoleAssignment } from "../src/index.js";
import { rolesResolver, rolesResolverNoPerms } from "./fixtures.js";

// Ports holds_test.go: TestScopeContainsMultiLevel, TestResolveMaterialized,
// TestResolveExpandKey, TestResolveRootStrict, TestResolveMaterializedPassThrough,
// TestResolveEmptyAndNil.

describe("scopeContains — root strict, deeper levels empty-wildcard", () => {
  const cases: Array<[string, string[], string[], boolean]> = [
    ["exact", ["O1", "T1", "P1"], ["O1", "T1", "P1"], true],
    ["tenant-wide covers project", ["O1", "T1", ""], ["O1", "T1", "P1"], true],
    ["tenant-wide at tenant query", ["O1", "T1", ""], ["O1", "T1", ""], true],
    ["org-wide covers deep", ["O1", "", ""], ["O1", "T9", "P9"], true],
    ["root differs", ["O1", "", ""], ["O2", "T1", "P1"], false],
    ["deeper grant rejects shallower query", ["O1", "T1", "P1"], ["O1", "T1", ""], false],
    ["mid-level differs", ["O1", "T1", "P1"], ["O1", "T2", "P1"], false],
    ["empty root never matches real", ["", "T1", "P1"], ["O1", "T1", "P1"], false],
    ["mid-level gap wildcards", ["O1", "", "P1"], ["O1", "T1", "P1"], true],
    ["shorter query, unpinned tail ok", ["O1", "", ""], ["O1"], true],
  ];
  it.each(cases)("%s", (_name, assignment, query, want) => {
    expect(scopeContains(assignment, query)).toBe(want);
  });
});

describe("resolve — MATERIALIZED permissions (scope-containment + dedup union)", () => {
  const assignments: RoleAssignment[] = [
    { scope: ["T1", ""], roleKey: "viewer", permissions: ["docs:read", "admin:read"] },
    { scope: ["T1", "TM1"], roleKey: "custom", permissions: ["docs:write"] },
    { scope: ["T2", "TM9"], roleKey: "owner", permissions: ["admin:write"] },
  ];
  const cases: Array<[string, string, string[]]> = [
    ["T1", "TM1", ["admin:read", "docs:read", "docs:write"]], // tenant-wide + custom
    ["T1", "TM2", ["admin:read", "docs:read"]], // tenant-wide only
    ["T1", "", ["admin:read", "docs:read"]], // tenant-wide query: project grant excluded
    ["T2", "TM9", ["admin:write"]], // other tenant
    ["T3", "TM1", []], // no match
  ];
  it.each(cases)("(%s,%s)", (tenant, team, want) => {
    const eff = resolve(rolesResolver, assignments, [tenant, team]);
    expect(eff.permissions()).toEqual(want);
    for (const p of want) expect(eff.holds(p)).toBe(true);
    expect(eff.holds("docs:read")).toBe(want.includes("docs:read"));
  });

  it("eff.holds can be passed standalone as the authorize callback", () => {
    const eff = resolve(rolesResolver, assignments, ["T1", "TM1"]);
    const cb = eff.holds; // detached — must still close over the resolved set
    expect(cb("docs:write")).toBe(true);
    expect(cb("admin:write")).toBe(false);
  });
});

describe("resolve — NO materialized column (role keys expand through the vocabulary)", () => {
  it("owner (*) subsumes everything → the whole vocabulary", () => {
    const assignments: RoleAssignment[] = [
      { scope: ["T1", "TM1"], roleKey: "editor", permissions: [] },
      { scope: ["T1", ""], roleKey: "owner", permissions: [] },
    ];
    const eff = resolve(rolesResolverNoPerms, assignments, ["T1", "TM1"]);
    expect(eff.permissions()).toEqual([
      "admin:read",
      "admin:write",
      "docs:publish",
      "docs:read",
      "docs:write",
    ]);
  });
  it("an unknown role key with no materialized perms fails closed", () => {
    const assignments: RoleAssignment[] = [{ scope: ["T1", "TM1"], roleKey: "ghost", permissions: [] }];
    expect(() => resolve(rolesResolverNoPerms, assignments, ["T1", "TM1"])).toThrow(/ghost/);
  });
});

describe("resolve — root strictness + pass-through + empty", () => {
  it("an empty-root assignment never leaks into a real tenant, but matches an empty-root query", () => {
    const asg: RoleAssignment[] = [{ scope: ["", ""], roleKey: "x", permissions: ["docs:read"] }];
    expect(resolve(rolesResolver, asg, ["T1", "TM1"]).permissions()).toEqual([]);
    expect(resolve(rolesResolver, asg, ["", ""]).permissions()).toEqual(["docs:read"]);
  });
  it("materialized perms pass through opaque (incl. out-of-vocabulary)", () => {
    const asg: RoleAssignment[] = [{ scope: ["T1", "TM1"], roleKey: "weird", permissions: ["totally:madeup"] }];
    expect(resolve(rolesResolver, asg, ["T1", "TM1"]).permissions()).toEqual(["totally:madeup"]);
  });
  it("empty input and an empty materialized role both yield the empty set", () => {
    expect(resolve(rolesResolver, [], ["T1", "TM1"]).permissions()).toEqual([]);
    const asg: RoleAssignment[] = [{ scope: ["T1", "TM1"], roleKey: "empty-role", permissions: [] }];
    expect(resolve(rolesResolver, asg, ["T1", "TM1"]).permissions()).toEqual([]);
  });
});
