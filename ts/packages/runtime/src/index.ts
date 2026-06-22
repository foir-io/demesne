/**
 * @demesne/runtime — the Demesne authorization runtime.
 *
 * Reproduces the Go engine's Layer-2 (read glue) and Layer-3 (control-plane write)
 * helpers from the same plain-data projection the engine emits. Zero runtime
 * dependencies; every SQL string and minted claims blob is byte-identical to the Go
 * side (proven by the differential golden oracle).
 */

export * from "./goCompat.js";
export * from "./decision.js";
export * from "./claims.js";
export * from "./pdp.js";
export * from "./appSurface.js";
export * from "./vocabulary.js";
export * from "./holds.js";
export * from "./delegation.js";
export * from "./grants.js";
export type * from "./types.js";

// The Layer-3 write surfaces are exposed as namespaces — they mirror the Go receiver
// methods (whose names collide across surfaces: grantInsert on both the level-grant and
// resource-access surfaces, revokeSQL on both the role-assignment and level-grant ones).
// Call sites read as `roleAssignments.assignInsert(surface, …)`.
export * as roleAssignments from "./roleAssign.js";
export * as levelGrants from "./levelGrant.js";
export * as resourceAccess from "./access.js";
