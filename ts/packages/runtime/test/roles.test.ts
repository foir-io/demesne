import { describe, it, expect } from "vitest";
import { resolveRoles, newEffectiveRoles, type RoleAssignment } from "../src/index.js";

describe("resolveRoles — scoped containment + global plane reach", () => {
  const asg: RoleAssignment[] = [
    { scope: ["t1", ""], roleKey: "tenant_owner", permissions: [] },
    { scope: ["t1", "p1"], roleKey: "project_admin", permissions: [] },
    { scope: ["", ""], roleKey: "platform_admin", permissions: [] },
  ];
  const cases: Array<[string, string[], string[]]> = [
    ["own project", ["t1", "p1"], ["platform_admin", "project_admin", "tenant_owner"]],
    ["sibling project keeps tenant + plane", ["t1", "p2"], ["platform_admin", "tenant_owner"]],
    ["foreign tenant keeps only plane", ["t2", "p9"], ["platform_admin"]],
    ["no current scope keeps only plane", ["", ""], ["platform_admin"]],
  ];
  it.each(cases)("%s", (_name, scope, want) => {
    const r = resolveRoles(asg, scope);
    expect(r.roles()).toEqual(want);
    for (const k of want) expect(r.holds(k)).toBe(true);
  });

  it("matches the Go ResolveRoles semantics: the plane is global, scoped roles are not", () => {
    expect(resolveRoles(asg, ["t2", "p9"]).holds("tenant_owner")).toBe(false);
    expect(resolveRoles(asg, ["t2", "p9"]).holds("platform_admin")).toBe(true);
  });
});

describe("resolveRoles + newEffectiveRoles — fail closed", () => {
  it("nil / empty / blank-key inputs yield no membership", () => {
    expect(resolveRoles([], ["t1", "p1"]).roles()).toEqual([]);
    const blanks: RoleAssignment[] = [
      { scope: ["t1", "p1"], roleKey: "", permissions: [] },
      { scope: ["t9", ""], roleKey: "tenant_owner", permissions: [] },
    ];
    expect(resolveRoles(blanks, ["t1", "p1"]).roles()).toEqual([]);
  });

  it("newEffectiveRoles drops blanks and reads back sorted", () => {
    const e = newEffectiveRoles(["platform_admin", "", "tenant_owner"]);
    expect(e.holds("platform_admin")).toBe(true);
    expect(e.holds("tenant_owner")).toBe(true);
    expect(e.holds("")).toBe(false);
    expect(e.holds("ws_editor")).toBe(false);
    expect(e.roles()).toEqual(["platform_admin", "tenant_owner"]);
  });

  it("holds can be passed standalone as a predicate", () => {
    const r = resolveRoles([{ scope: ["", ""], roleKey: "platform_admin", permissions: [] }], ["t1", "p1"]);
    const cb = r.holds;
    expect(cb("platform_admin")).toBe(true);
    expect(cb("tenant_owner")).toBe(false);
  });
});
