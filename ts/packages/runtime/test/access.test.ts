import { describe, it, expect } from "vitest";
import { resourceAccess } from "../src/index.js";
import { recordAccess } from "./fixtures.js";

describe("resource access surface (discriminated store)", () => {
  it("projects the read-mode and grant-kind sets", () => {
    expect(resourceAccess.isReadMode(recordAccess, "public_project")).toBe(true);
    expect(resourceAccess.isReadMode(recordAccess, "private")).toBe(false);
    expect(resourceAccess.grantKindAllowed(recordAccess, "customer")).toBe(true);
    expect(resourceAccess.grantKindAllowed(recordAccess, "nobody")).toBe(false);
  });

  it("modeSQL / setVisibilitySQL / accessorsSQL", () => {
    expect(resourceAccess.modeSQL(recordAccess)).toBe("SELECT access_mode FROM records WHERE id = $1");
    expect(resourceAccess.setVisibilitySQL(recordAccess)).toBe("UPDATE records SET access_mode = $1 WHERE id = $2");
    expect(resourceAccess.accessorsSQL(recordAccess)).toBe(
      "SELECT source, principal_kind, principal_id, access FROM auth.records_accessors($1)",
    );
  });

  it("grantInsert carries scope, discriminator, the grant tuple, and the matching conflict key", () => {
    const { sql, args } = resourceAccess.grantInsert(recordAccess, ["t1", "p1"], "rec1", "customer", "cust9", "read");
    expect(sql).toBe(
      "INSERT INTO resource_acl (tenant_id, project_id, resource_type, resource_id, principal_kind, principal_id, access) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (resource_type, resource_id, principal_kind, principal_id, access) DO NOTHING RETURNING created_at",
    );
    expect(args).toEqual(["t1", "p1", "record", "rec1", "customer", "cust9", "read"]);
  });

  it("revokeDelete pins all five columns with an access level, omits it without", () => {
    const del = resourceAccess.revokeDelete(recordAccess, "rec1", "customer", "cust9", "read");
    expect(del.sql).toBe(
      "DELETE FROM resource_acl WHERE resource_id = $1 AND resource_type = $2 AND principal_kind = $3 AND principal_id = $4 AND access = $5",
    );
    expect(del.args).toEqual(["rec1", "record", "customer", "cust9", "read"]);

    const delAll = resourceAccess.revokeDelete(recordAccess, "rec1", "customer", "cust9", "");
    expect(delAll.sql).not.toContain("access =");
    expect(delAll.args).toEqual(["rec1", "record", "customer", "cust9"]);
  });

  it("listGrantsSQL / listGrantsArgs (discriminator → $2)", () => {
    expect(resourceAccess.listGrantsSQL(recordAccess)).toBe(
      "SELECT principal_kind, principal_id, access, created_at FROM resource_acl WHERE resource_id = $1 AND resource_type = $2 ORDER BY created_at",
    );
    expect(resourceAccess.listGrantsArgs(recordAccess, "rec1")).toEqual(["rec1", "record"]);
  });
});
