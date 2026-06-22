import { describe, it, expect } from "vitest";
import { roleAssignments, touchOnConflict } from "../src/index.js";
import { fullRoleAssign, minimalRoleAssign, rpScopedRoleAssign, pkOverrideRoleAssign } from "./fixtures.js";

// Ports role_assignment_runtime_test.go.

describe("touchOnConflict — general across grant edges", () => {
  it("a role-assignment tuple", () => {
    expect(
      touchOnConflict(
        ["principal_kind", "principal_id", "role_id"],
        ["tenant_id", "project_id", "client_id"],
        ["revoked_at = NULL", "granted_at = now()"],
      ),
    ).toBe(
      "ON CONFLICT (principal_kind, principal_id, role_id, COALESCE(tenant_id, ''), COALESCE(project_id, ''), COALESCE(client_id, '')) DO UPDATE SET revoked_at = NULL, granted_at = now()",
    );
  });
  it("a level-grant edge tuple", () => {
    expect(touchOnConflict(["grantee_id"], ["tenant_id"], ["revoked_at = NULL"])).toBe(
      "ON CONFLICT (grantee_id, COALESCE(tenant_id, '')) DO UPDATE SET revoked_at = NULL",
    );
  });
});

describe("assignInsert / assignTouchInsert — extra context column + TOUCH", () => {
  it("CREATE writes + projects the extra column", () => {
    const { sql, args } = roleAssignments.assignInsert(
      rpScopedRoleAssign,
      "a1",
      "u1",
      "role1",
      ["t1", "p1"],
      "g1",
      { client_id: "rp1" },
    );
    expect(sql).toBe(
      "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by, client_id) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " +
        "RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by, client_id",
    );
    expect(args).toEqual(["a1", "admin", "u1", "role1", "t1", "p1", "g1", "rp1"]);
  });

  it("TOUCH reactivates on conflict; args are byte-identical to CREATE", () => {
    const create = roleAssignments.assignInsert(rpScopedRoleAssign, "a1", "u1", "role1", ["t1", "p1"], "g1", {
      client_id: "rp1",
    });
    const touch = roleAssignments.assignTouchInsert(rpScopedRoleAssign, "a1", "u1", "role1", ["t1", "p1"], "g1", {
      client_id: "rp1",
    });
    expect(touch.sql).toBe(
      "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by, client_id) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " +
        "ON CONFLICT (principal_kind, principal_id, role_id, COALESCE(tenant_id, ''), COALESCE(project_id, ''), COALESCE(client_id, '')) DO UPDATE SET " +
        "revoked_at = NULL, revoked_by = NULL, granted_at = now(), granted_by = EXCLUDED.granted_by " +
        "RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by, client_id",
    );
    expect(touch.args).toEqual(create.args);
  });
});

describe("full surface", () => {
  it("assignInsert (kind inlined as bound $2, full audit projection)", () => {
    const { sql, args } = roleAssignments.assignInsert(fullRoleAssign, "a1", "u1", "role1", ["t1", "p1"], "granter1");
    expect(sql).toBe(
      "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7) " +
        "RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by",
    );
    expect(args).toEqual(["a1", "admin", "u1", "role1", "t1", "p1", "granter1"]);
  });
  it("revokeSQL (soft-revoke by PK + revoker, idempotent)", () => {
    expect(roleAssignments.revokeSQL(fullRoleAssign)).toBe(
      "UPDATE role_assignments SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL",
    );
  });
  it("listForRoleSQL (audit view, newest first)", () => {
    expect(roleAssignments.listForRoleSQL(fullRoleAssign)).toBe(
      "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by " +
        "FROM role_assignments WHERE role_id = $1 ORDER BY granted_at DESC",
    );
  });
  it("listForPrincipalSQL (active, joined to key + perms; kind inlined)", () => {
    expect(roleAssignments.listForPrincipalSQL(fullRoleAssign)).toBe(
      "SELECT a.id, a.principal_id, a.role_id, a.granted_at, a.granted_by, r.key, r.permissions " +
        "FROM role_assignments a JOIN roles r ON r.id = a.role_id " +
        "WHERE a.principal_kind = 'admin' AND a.principal_id = $1 AND a.revoked_at IS NULL",
    );
  });
});

describe("minimal surface (undeclared audit columns omitted)", () => {
  it("assignInsert omits the grantor column (grantedBy arg ignored)", () => {
    const { sql, args } = roleAssignments.assignInsert(minimalRoleAssign, "a1", "u1", "role1", ["t1", "p1"], "ignored");
    expect(sql).toBe(
      "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id) " +
        "VALUES ($1, $2, $3, $4, $5, $6) " +
        "RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at",
    );
    expect(args).toEqual(["a1", "admin", "u1", "role1", "t1", "p1"]);
  });
  it("revokeSQL with no revoker column", () => {
    expect(roleAssignments.revokeSQL(minimalRoleAssign)).toBe(
      "UPDATE role_assignments SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    );
  });
  it("listForRoleSQL with no granted-at column (no ORDER BY)", () => {
    expect(roleAssignments.listForRoleSQL(minimalRoleAssign)).toBe(
      "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at FROM role_assignments WHERE role_id = $1",
    );
  });
  it("listForPrincipalSQL omits all three optional columns", () => {
    expect(roleAssignments.listForPrincipalSQL(minimalRoleAssign)).toBe(
      "SELECT a.id, a.principal_id, a.role_id, r.key " +
        "FROM role_assignments a JOIN roles r ON r.id = a.role_id " +
        "WHERE a.principal_kind = 'admin' AND a.principal_id = $1 AND a.revoked_at IS NULL",
    );
  });
});

describe("edge cases", () => {
  it("a scope shorter than scopeCols leaves the tail NULL (not a crash)", () => {
    const { args } = roleAssignments.assignInsert(fullRoleAssign, "a1", "u1", "role1", ["t1"], "g1");
    expect(args).toEqual(["a1", "admin", "u1", "role1", "t1", null, "g1"]);
  });
  it("the pk override threads through the INSERT id column and the revoke key", () => {
    expect(roleAssignments.revokeSQL(pkOverrideRoleAssign)).toBe(
      "UPDATE grants SET ended_at = now() WHERE grant_id = $1 AND ended_at IS NULL",
    );
    const { sql } = roleAssignments.assignInsert(pkOverrideRoleAssign, "g1", "u1", "r1", ["t1"], "");
    expect(sql).toBe(
      "INSERT INTO grants (grant_id, kind, who, role_ref, tenant_id) VALUES ($1, $2, $3, $4, $5) " +
        "RETURNING grant_id, kind, who, role_ref, tenant_id, ended_at",
    );
  });
});
