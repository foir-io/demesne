/**
 * Hand-written projection literals mirroring the specs the Go unit tests parse, so the
 * pure-compute ports can be exercised without the emitter (which arrives in a later
 * increment). Each corresponds to a spec in the Go test suite — names noted inline.
 */

import type { Vocabulary, HoldsResolver, Pdp } from "../src/index.js";

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
