

import type {
  Vocabulary,
  HoldsResolver,
  Pdp,
  Claims,
  RoleAssignmentSurface,
  GrantSurface,
  ResourceAccessSurface,
} from "../src/index.js";

export const rolesVocab: Vocabulary = {
  name: "roles",
  permissions: ["docs:read", "docs:write", "docs:publish", "admin:read", "admin:write"],
  presets: [
    { name: "viewer", star: false, set: ["docs:read", "admin:read"] },
    { name: "editor", star: false, set: ["viewer", "docs:write", "docs:publish"] },
    { name: "owner", star: true, set: [] },
  ],
  rank: ["owner", "editor", "viewer"],
};

export const rolesResolver: HoldsResolver = {
  assignments: "role_assignments",
  kindCol: "principal_kind",
  kindVal: "member",
  subjectCol: "principal_id",
  scopeCols: ["tenant_id", "team_id"],
  revokedCol: "revoked_at",
  roleCol: "role_id",
  rolesTable: "roles_tbl",
  rolesId: "id",
  keyCol: "key",
  permsCol: "perms",
  vocab: rolesVocab,
};

export const rolesResolverNoPerms: HoldsResolver = { ...rolesResolver, permsCol: "" };

export const capVocab: Vocabulary = {
  name: "admin",
  permissions: ["a:read", "a:write", "b:read", "b:write"],
  presets: [
    { name: "viewer", star: false, set: ["a:read", "b:read"] },
    { name: "editor", star: false, set: ["viewer", "a:write"] },
    { name: "owner", star: true, set: [] },
  ],
  rank: ["owner", "editor", "viewer"],
};

export const adminPdp: Pdp = {
  emitSite: "admin",
  policy: { "records.v1.RecordsService/UpdateRecord": "content:write" },
  ungoverned: { "records.v1.RecordsService/GetRecord": "read path" },
};

export const runtimeClaims: Claims = {
  setting: "request.jwt.claims",
  cast: "json",
  role: "authenticated",
  contract: ["customer_id", "project_id", "sub", "tenant_id"],
  entries: [
    { key: "customer_id", level: "", subjects: ["customer"] },
    { key: "project_id", level: "project", subjects: [] },
    { key: "sub", level: "", subjects: ["admin"] },
    { key: "tenant_id", level: "tenant", subjects: [] },
  ],
  subjects: [
    { name: "admin", identifies: "sub" },
    { name: "customer", identifies: "customer_id" },
  ],
  levels: [
    { name: "tenant", claimKey: "tenant_id", virtual: false },
    { name: "project", claimKey: "project_id", virtual: false },
  ],
};

export const virtualRootClaims: Claims = {
  setting: "app.ctx",
  cast: "jsonb",
  role: "app_user",
  contract: ["sub", "tenant_id"],
  entries: [
    { key: "sub", level: "", subjects: ["admin"] },
    { key: "tenant_id", level: "tenant", subjects: [] },
  ],
  subjects: [{ name: "admin", identifies: "sub" }],
  levels: [
    { name: "platform", claimKey: "platform_id", virtual: true },
    { name: "tenant", claimKey: "tenant_id", virtual: false },
  ],
};

export const overrideClaims: Claims = {
  setting: "request.jwt.claims",
  cast: "json",
  role: "authenticated",
  contract: ["org_ref", "team_ref", "who"],
  entries: [
    { key: "org_ref", level: "org", subjects: [] },
    { key: "team_ref", level: "team", subjects: [] },
    { key: "who", level: "", subjects: ["admin"] },
  ],
  subjects: [{ name: "admin", identifies: "who" }],
  levels: [
    { name: "org", claimKey: "org_ref", virtual: false },
    { name: "team", claimKey: "team_ref", virtual: false },
  ],
};

export const noIdentityClaims: Claims = {
  setting: "request.jwt.claims",
  cast: "json",
  role: "authenticated",
  contract: [],
  entries: [],
  subjects: [{ name: "svc", identifies: "" }],
  levels: [{ name: "tenant", claimKey: "tenant_id", virtual: false }],
};

export const fullRoleAssign: RoleAssignmentSurface = {
  assignments: "role_assignments",
  pk: "id",
  kindCol: "principal_kind",
  kindVal: "admin",
  subjectCol: "principal_id",
  roleCol: "role_id",
  scopeCols: ["tenant_id", "project_id"],
  revokedCol: "revoked_at",
  grantedAtCol: "granted_at",
  grantedByCol: "granted_by",
  revokedByCol: "revoked_by",
  extraCols: [],
  rolesTable: "roles",
  rolesId: "id",
  keyCol: "key",
  permsCol: "permissions",
};

export const minimalRoleAssign: RoleAssignmentSurface = {
  assignments: "role_assignments",
  pk: "id",
  kindCol: "principal_kind",
  kindVal: "admin",
  subjectCol: "principal_id",
  roleCol: "role_id",
  scopeCols: ["tenant_id", "project_id"],
  revokedCol: "revoked_at",
  grantedAtCol: "",
  grantedByCol: "",
  revokedByCol: "",
  extraCols: [],
  rolesTable: "roles",
  rolesId: "id",
  keyCol: "key",
  permsCol: "",
};

export const rpScopedRoleAssign: RoleAssignmentSurface = {
  ...fullRoleAssign,
  extraCols: ["client_id"],
  permsCol: "",
};

export const pkOverrideRoleAssign: RoleAssignmentSurface = {
  assignments: "grants",
  pk: "grant_id",
  kindCol: "kind",
  kindVal: "op",
  subjectCol: "who",
  roleCol: "role_ref",
  scopeCols: ["tenant_id"],
  revokedCol: "ended_at",
  grantedAtCol: "",
  grantedByCol: "",
  revokedByCol: "",
  extraCols: [],
  rolesTable: "role_defs",
  rolesId: "ref",
  keyCol: "slug",
  permsCol: "",
};

export const fullGrant: GrantSurface = {
  name: "impersonation",
  level: "tenant",
  table: "impersonation_grants",
  granteeCol: "grantee_id",
  levelCol: "tenant_id",
  activeCol: "revoked_at",
  expiresCol: "expires_at",
  pk: "id",
  grantedByCol: "granted_by",
  revokedByCol: "revoked_by",
  createdAtCol: "created_at",
  extraCols: ["reason"],
};

export const minimalGrant: GrantSurface = {
  name: "simple",
  level: "tenant",
  table: "simple_grants",
  granteeCol: "grantee_id",
  levelCol: "tenant_id",
  activeCol: "",
  expiresCol: "",
  pk: "id",
  grantedByCol: "",
  revokedByCol: "",
  createdAtCol: "",
  extraCols: [],
};

export const extraColsGrant: GrantSurface = {
  name: "g",
  level: "tenant",
  table: "edges",
  granteeCol: "grantee_id",
  levelCol: "tenant_id",
  activeCol: "",
  expiresCol: "",
  pk: "id",
  grantedByCol: "",
  revokedByCol: "",
  createdAtCol: "",
  extraCols: ["reason", "note"],
};

export const recordAccess: ResourceAccessSurface = {
  table: "records",
  scopeCols: ["tenant_id", "project_id"],
  modeCol: "access_mode",
  pk: "id",
  readModes: ["public_project"],
  grantKinds: ["customer"],
  aclTable: "resource_acl",
  recordCol: "resource_id",
  kindCol: "principal_kind",
  principalCol: "principal_id",
  accessCol: "access",
  discrimCol: "resource_type",
  discrimVal: "record",
  accessorFn: "auth.records_accessors",
};
