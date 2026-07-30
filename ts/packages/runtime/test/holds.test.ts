import { describe, it, expect } from "vitest";
import { assignmentsSQL, scopeContains, resolve, type RoleAssignment } from "../src/index.js";
import { rolesResolver, rolesResolverNoPerms, manageResolver } from "./fixtures.js";

describe("assignmentsSQL — the active-assignment read", () => {
  it("projects the scope cols, role key, and the materialized perms column when declared", () => {
    expect(assignmentsSQL(rolesResolver)).toBe(
      "SELECT ra.tenant_id, ra.team_id, r.key, r.perms FROM role_assignments ra " +
        "JOIN roles_tbl r ON r.id = ra.role_id WHERE ra.principal_kind = 'member' " +
        "AND ra.principal_id = $1 AND ra.revoked_at IS NULL",
    );
  });
  it("drops the perms column from the projection when undeclared", () => {
    expect(assignmentsSQL(rolesResolverNoPerms)).toBe(
      "SELECT ra.tenant_id, ra.team_id, r.key FROM role_assignments ra " +
        "JOIN roles_tbl r ON r.id = ra.role_id WHERE ra.principal_kind = 'member' " +
        "AND ra.principal_id = $1 AND ra.revoked_at IS NULL",
    );
  });
});

describe("scopeContains — every level empty-wildcard, including the root", () => {
  const cases: Array<[string, string[], string[], boolean]> = [
    ["exact", ["O1", "T1", "P1"], ["O1", "T1", "P1"], true],
    ["tenant-wide covers project", ["O1", "T1", ""], ["O1", "T1", "P1"], true],
    ["tenant-wide at tenant query", ["O1", "T1", ""], ["O1", "T1", ""], true],
    ["org-wide covers deep", ["O1", "", ""], ["O1", "T9", "P9"], true],
    ["root differs", ["O1", "", ""], ["O2", "T1", "P1"], false],
    ["deeper grant rejects shallower query", ["O1", "T1", "P1"], ["O1", "T1", ""], false],
    ["mid-level differs", ["O1", "T1", "P1"], ["O1", "T2", "P1"], false],
    ["empty root wildcards, deeper levels still pinned", ["", "T1", "P1"], ["O1", "T1", "P1"], true],
    ["empty root wildcards but a pinned deeper level still differs", ["", "T1", "P1"], ["O1", "T2", "P1"], false],
    ["fully empty scope is global", ["", "", ""], ["O9", "T9", "P9"], true],
    ["a pinned root still never crosses", ["O1", "T1", ""], ["O2", "T1", "P1"], false],
    ["a pinned root never answers a global query", ["O1", "", ""], ["", "", ""], false],
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
    ["T1", "TM1", ["admin:read", "docs:read", "docs:write"]],
    ["T1", "TM2", ["admin:read", "docs:read"]],
    ["T1", "", ["admin:read", "docs:read"]],
    ["T2", "TM9", ["admin:write"]],
    ["T3", "TM1", []],
  ];
  it.each(cases)("(%s,%s)", (tenant, team, want) => {
    const eff = resolve(rolesResolver, assignments, [tenant, team]);
    expect(eff.permissions()).toEqual(want);
    for (const p of want) expect(eff.holds(p)).toBe(true);
    expect(eff.holds("docs:read")).toBe(want.includes("docs:read"));
  });

  it("eff.holds can be passed standalone as the authorize callback", () => {
    const eff = resolve(rolesResolver, assignments, ["T1", "TM1"]);
    const cb = eff.holds;
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

describe("resolve — global root + pass-through + empty", () => {
  it("an empty-root assignment is global and reaches every tenant", () => {
    const asg: RoleAssignment[] = [{ scope: ["", ""], roleKey: "x", permissions: ["docs:read"] }];
    expect(resolve(rolesResolver, asg, ["T1", "TM1"]).permissions()).toEqual(["docs:read"]);
    expect(resolve(rolesResolver, asg, ["", ""]).permissions()).toEqual(["docs:read"]);
  });
  it("a tenant-pinned assignment gains no cross-tenant reach", () => {
    const asg: RoleAssignment[] = [{ scope: ["T1", ""], roleKey: "x", permissions: ["docs:read"] }];
    expect(resolve(rolesResolver, asg, ["T2", "TM1"]).permissions()).toEqual([]);
    expect(resolve(rolesResolver, asg, ["", ""]).permissions()).toEqual([]);
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

describe("resolve — the scope-relative manage keys (key = ceiling, scope = subtree)", () => {
  const asg = (scope: string[], perm: string): RoleAssignment[] => [
    { scope, roleKey: "", permissions: [perm] },
  ];

  it("platform:manage at the global scope confers the whole vocabulary anywhere", () => {
    const eff = resolve(manageResolver, asg(["", ""], "platform:manage"), ["T9", "P9"]);
    expect(eff.permissions()).toEqual(manageResolver.vocab.permissions.slice().sort());
  });

  it("tenant:manage reaches two hops down but never up", () => {
    const eff = resolve(manageResolver, asg(["T1", ""], "tenant:manage"), ["T1", "P1"]);
    expect(eff.holds("project:manage")).toBe(true);
    expect(eff.holds("records:write")).toBe(true);
    expect(eff.holds("billing:write")).toBe(true);
    expect(eff.holds("platform:manage")).toBe(false);
  });

  it("tenant:manage is bounded by its assignment scope", () => {
    expect(resolve(manageResolver, asg(["T1", ""], "tenant:manage"), ["T2", "P1"]).permissions()).toEqual([]);
  });

  it("project:manage keeps its ceiling even when assigned at tenant scope", () => {
    const eff = resolve(manageResolver, asg(["T1", ""], "project:manage"), ["T1", "P7"]);
    expect(eff.permissions()).toEqual([
      "content:publish",
      "content:read",
      "project:manage",
      "records:read",
      "records:write",
    ]);
    expect(eff.holds("billing:read")).toBe(false);
    expect(eff.holds("tenant:manage")).toBe(false);
  });

  it("a leaf verb confers only itself", () => {
    const eff = resolve(manageResolver, asg(["T1", "P1"], "records:read"), ["T1", "P1"]);
    expect(eff.permissions()).toEqual(["records:read"]);
  });
});
