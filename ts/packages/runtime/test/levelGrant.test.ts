import { describe, it, expect } from "vitest";
import { levelGrants, type GrantSurface } from "../src/index.js";
import { fullGrant, minimalGrant, extraColsGrant } from "./fixtures.js";

// Ports grant_runtime_test.go.

describe("full surface (active + expiry + audit + reason column)", () => {
  it("grantInsert writes/projects the reason column, args in order", () => {
    const { sql, args } = levelGrants.grantInsert(
      fullGrant,
      "g1",
      "u1",
      "t1",
      "granter1",
      "2030-01-01T00:00:00Z",
      { reason: "audit me" },
    );
    expect(sql).toBe(
      "INSERT INTO impersonation_grants (id, grantee_id, tenant_id, granted_by, expires_at, reason) " +
        "VALUES ($1, $2, $3, $4, $5, $6) " +
        "RETURNING id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason",
    );
    expect(args).toEqual(["g1", "u1", "t1", "granter1", "2030-01-01T00:00:00Z", "audit me"]);
  });
  it("revokeSQL is a soft-revoke RETURNING the row", () => {
    expect(levelGrants.revokeSQL(fullGrant)).toBe(
      "UPDATE impersonation_grants SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL " +
        "RETURNING id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason",
    );
  });
  it("listSQL has three filters + the active predicate, newest first", () => {
    expect(levelGrants.listSQL(fullGrant)).toBe(
      "SELECT id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason " +
        "FROM impersonation_grants " +
        "WHERE ($1::text IS NULL OR grantee_id = $1) AND ($2::text IS NULL OR tenant_id = $2) " +
        "AND (NOT $3::boolean OR (revoked_at IS NULL AND expires_at > now())) ORDER BY created_at DESC",
    );
  });
});

describe("minimal surface (only reach columns)", () => {
  it("grantInsert is a bare INSERT; grantor/expiry/extras ignored", () => {
    const { sql, args } = levelGrants.grantInsert(minimalGrant, "g1", "u1", "t1", "ignored", null);
    expect(sql).toBe("INSERT INTO simple_grants (id, grantee_id, tenant_id) VALUES ($1, $2, $3) RETURNING id, grantee_id, tenant_id");
    expect(args).toEqual(["g1", "u1", "t1"]);
  });
  it("revokeSQL is a hard DELETE (no active column)", () => {
    expect(levelGrants.revokeSQL(minimalGrant)).toBe("DELETE FROM simple_grants WHERE id = $1");
  });
  it("listSQL has active predicate TRUE and no ORDER BY", () => {
    expect(levelGrants.listSQL(minimalGrant)).toBe(
      "SELECT id, grantee_id, tenant_id FROM simple_grants " +
        "WHERE ($1::text IS NULL OR grantee_id = $1) AND ($2::text IS NULL OR tenant_id = $2) AND (NOT $3::boolean OR (TRUE))",
    );
  });
});

describe("activePredicate degrades gracefully", () => {
  it("full → both conjuncts with the prefix", () => {
    expect(levelGrants.activePredicate(fullGrant, "ig.")).toBe("ig.revoked_at IS NULL AND ig.expires_at > now()");
  });
  it("revoked-only / expiry-only / neither", () => {
    const revokedOnly = { activeCol: "revoked_at", expiresCol: "" } as GrantSurface;
    const expiryOnly = { activeCol: "", expiresCol: "expires_at" } as GrantSurface;
    const neither = { activeCol: "", expiresCol: "" } as GrantSurface;
    expect(levelGrants.activePredicate(revokedOnly, "")).toBe("revoked_at IS NULL");
    expect(levelGrants.activePredicate(expiryOnly, "")).toBe("expires_at > now()");
    expect(levelGrants.activePredicate(neither, "")).toBe("TRUE");
  });
});

describe("multiple declared columns (declaration order, missing → NULL)", () => {
  it("grantInsert writes both, projects both; absent value is NULL", () => {
    const { sql, args } = levelGrants.grantInsert(extraColsGrant, "g1", "u1", "t1", "", null, { reason: "r" });
    expect(sql).toBe(
      "INSERT INTO edges (id, grantee_id, tenant_id, reason, note) VALUES ($1, $2, $3, $4, $5) " +
        "RETURNING id, grantee_id, tenant_id, reason, note",
    );
    expect(args).toEqual(["g1", "u1", "t1", "r", null]);
  });
});
