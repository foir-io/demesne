import { DriverValues, run } from "./engine.js";
import type { ResourceAccessSurface, ParamStatement, SqlArg } from "./types.js";

export function isReadMode(p: ResourceAccessSurface, mode: string): boolean {
  return run("resourceAccess.isReadMode", { surface: p, mode });
}

export function grantKindAllowed(p: ResourceAccessSurface, kind: string): boolean {
  return run("resourceAccess.grantKindAllowed", { surface: p, kind });
}

export function modeSQL(p: ResourceAccessSurface): string {
  return run("resourceAccess.modeSQL", { surface: p });
}

export function setVisibilitySQL(p: ResourceAccessSurface): string {
  return run("resourceAccess.setVisibilitySQL", { surface: p });
}

export function grantInsert(
  p: ResourceAccessSurface,
  scope: readonly string[],
  resourceID: string,
  kind: string,
  principalID: string,
  access: string,
): ParamStatement {
  return new DriverValues().statement("resourceAccess.grantInsert", { surface: p, scope, resourceID, kind, principalID, access });
}

export function revokeDelete(p: ResourceAccessSurface, resourceID: string, kind: string, principalID: string, access: string): ParamStatement {
  return new DriverValues().statement("resourceAccess.revokeDelete", { surface: p, resourceID, kind, principalID, access });
}

export function listGrantsSQL(p: ResourceAccessSurface): string {
  return run("resourceAccess.listGrantsSQL", { surface: p });
}

export function listGrantsArgs(p: ResourceAccessSurface, resourceID: string): SqlArg[] {
  return run("resourceAccess.listGrantsArgs", { surface: p, resourceID });
}

export function accessorsSQL(p: ResourceAccessSurface): string {
  return run("resourceAccess.accessorsSQL", { surface: p });
}
