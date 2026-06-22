/**
 * Hand-written projection literals mirroring the specs the Go unit tests parse, so the
 * pure-compute ports can be exercised without the emitter (which arrives in a later
 * increment). Each corresponds to a spec in the Go test suite — names noted inline.
 */

import type {
  Vocabulary,
  HoldsResolver,
  Pdp,
  Claims,
  RoleAssignmentSurface,
  GrantSurface,
  ResourceAccessSurface,
} from "../src/index.js";

/** The `roles` vocabulary from holds_test.go's `holdsSpec` (nested preset + star + rank). */
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

/** The materialized-permissions resolver from holds_test.go's `holdsSpec`. */
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

/** The same resolver with no materialized column — role keys expand through the vocabulary. */
export const rolesResolverNoPerms: HoldsResolver = { ...rolesResolver, permsCol: "" };

/** The `admin` cap vocabulary from delegation_test.go's `capVocabSpec`. */
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

/** The `admin` PDP from runtime_test.go's `runtimeSpec`. */
export const adminPdp: Pdp = {
  emitSite: "admin",
  policy: { "records.v1.RecordsService/UpdateRecord": "content:write" },
  ungoverned: { "records.v1.RecordsService/GetRecord": "read path" },
};

/** The claims projection for runtime_test.go / session_test.go's `runtimeSpec` (no claims block → defaults). */
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

/** session_test.go's `virtualRootSpec` — a spec-declared GUC/role + a VIRTUAL root level. */
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

/** session_test.go's claim-key override spec (`claim org_ref` / `claim team_ref`, `identifies who`). */
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

/** A subject with NO identity key (session_test.go's TestSession_BuildClaims_NoIdentityKey). */
export const noIdentityClaims: Claims = {
  setting: "request.jwt.claims",
  cast: "json",
  role: "authenticated",
  contract: [],
  entries: [],
  subjects: [{ name: "svc", identifies: "" }],
  levels: [{ name: "tenant", claimKey: "tenant_id", virtual: false }],
};

// --- Layer 3: role-assignment surfaces (role_assignment_runtime_test.go) ------

/** fullRoleStoreSpec — every optional write column declared. */
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

/** minimalRoleStoreSpec — only the read columns; default id PK, no audit/perms. */
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

/** rpScopedRoleStoreSpec — full audit + an extra context column (client_id), no perms. */
export const rpScopedRoleAssign: RoleAssignmentSurface = {
  ...fullRoleAssign,
  extraCols: ["client_id"],
  permsCol: "",
};

/** The pk-override spec (assignments grants, pk grant_id, role_defs/ref/slug). */
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

// --- Layer 3: level-grant surfaces (grant_runtime_test.go) --------------------

/** fullGrantSpec — impersonation grant with active/expiry + full audit + a reason column. */
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

/** minimalGrantSpec — only the reach columns; default id PK, hard-DELETE revoke. */
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

/** A grant with two declared `column`s (reason, note) — declaration-order write/project. */
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

// --- Layer 3: resource-ACL surface (access_runtime_test.go / adminOwnerSpec) ---

/** adminOwnerSpec's `record` object — a discriminated (shared) grant store. */
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
