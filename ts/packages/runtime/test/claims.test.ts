import { describe, it, expect } from "vitest";
import {
  claimsContract,
  mintClaims,
  buildClaims,
  mintClaimsFor,
  setRoleSQL,
  claimsSetSQL,
  sessionSetupSQL,
} from "../src/index.js";
import { runtimeClaims, virtualRootClaims, overrideClaims, noIdentityClaims } from "./fixtures.js";

// Ports claims_test.go / runtime_test.go (MintClaims) + session_test.go.

describe("claimsContract / mintClaims", () => {
  it("the flat contract is the entry keys, byte-sorted", () => {
    expect(claimsContract(runtimeClaims.entries)).toEqual(["customer_id", "project_id", "sub", "tenant_id"]);
  });

  it("mints a customer's subset deterministically (sorted-key JSON)", () => {
    const got = mintClaims(runtimeClaims, { customer_id: "c1", tenant_id: "t1", project_id: "p1" });
    expect(got).toBe('{"customer_id":"c1","project_id":"p1","tenant_id":"t1"}');
  });

  it("rejects a key outside the contract (typo / stale-key protection)", () => {
    expect(() => mintClaims(runtimeClaims, { tenant_id: "t1", tenantId: "oops" })).toThrow(/not in the claims contract/);
  });

  it("claimsSetSQL targets the spec's claims setting", () => {
    expect(claimsSetSQL(runtimeClaims, true)).toBe("SELECT set_config('request.jwt.claims', $1, true)");
  });
});

describe("buildClaims — principal → contract values", () => {
  it("an admin's id lands under its identity key (sub); scopes under the level keys", () => {
    expect(
      buildClaims(runtimeClaims, { subject: "admin", id: "u1", scopes: { tenant: "t1", project: "p1" } }),
    ).toEqual({ sub: "u1", tenant_id: "t1", project_id: "p1" });
  });

  it("a customer's id lands under customer_id, NOT sub", () => {
    const cust = buildClaims(runtimeClaims, { subject: "customer", id: "c1", scopes: { tenant: "t1", project: "p1" } });
    expect(cust).toEqual({ customer_id: "c1", tenant_id: "t1", project_id: "p1" });
    expect("sub" in cust).toBe(false);
  });

  it("rejects an unknown subject and an unknown level", () => {
    expect(() => buildClaims(runtimeClaims, { subject: "nope", id: "x", scopes: {} })).toThrow(/no subject/);
    expect(() => buildClaims(runtimeClaims, { subject: "admin", id: "u1", scopes: { galaxy: "g" } })).toThrow(
      /unknown level/,
    );
  });

  it("rejects a scope for a VIRTUAL level; sets no identity key when no id is supplied", () => {
    expect(() =>
      buildClaims(virtualRootClaims, { subject: "admin", id: "u1", scopes: { platform: "anything" } }),
    ).toThrow(/virtual/);
    expect(buildClaims(virtualRootClaims, { subject: "admin", id: "", scopes: { tenant: "t1" } })).toEqual({
      tenant_id: "t1",
    });
  });

  it("rejects an id for a subject with no identity key; allows a no-id principal", () => {
    expect(() => buildClaims(noIdentityClaims, { subject: "svc", id: "x", scopes: {} })).toThrow(/no identity key/);
    expect(buildClaims(noIdentityClaims, { subject: "svc", id: "", scopes: {} })).toEqual({});
  });

  it("maps via the declared claim keys / identity, not the <level>_id / sub conventions", () => {
    expect(
      buildClaims(overrideClaims, { subject: "admin", id: "u1", scopes: { org: "o1", team: "tm1" } }),
    ).toEqual({ who: "u1", org_ref: "o1", team_ref: "tm1" });
  });
});

describe("mintClaimsFor — buildClaims → mintClaims in one call", () => {
  it("produces deterministic sorted-key JSON", () => {
    const got = mintClaimsFor(runtimeClaims, { subject: "admin", id: "u1", scopes: { tenant: "t1", project: "p1" } });
    expect(got).toBe('{"project_id":"p1","sub":"u1","tenant_id":"t1"}');
  });
});

describe("session envelope", () => {
  it("defaults: role authenticated, request.jwt.claims GUC", () => {
    expect(setRoleSQL(runtimeClaims, true)).toBe("SET LOCAL ROLE authenticated");
    expect(setRoleSQL(runtimeClaims, false)).toBe("SET ROLE authenticated");
    expect(sessionSetupSQL(runtimeClaims, true)).toEqual([
      "SET LOCAL ROLE authenticated",
      "SELECT set_config('request.jwt.claims', $1, true)",
    ]);
  });

  it("spec-declared role + GUC flow through", () => {
    expect(setRoleSQL(virtualRootClaims, true)).toBe("SET LOCAL ROLE app_user");
    expect(sessionSetupSQL(virtualRootClaims, true)).toEqual([
      "SET LOCAL ROLE app_user",
      "SELECT set_config('app.ctx', $1, true)",
    ]);
  });
});
