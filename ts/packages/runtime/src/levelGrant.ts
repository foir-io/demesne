import { DriverValues, run } from "./engine.js";
import type { GrantSurface, ParamStatement, SqlArg } from "./types.js";

export function activePredicate(p: GrantSurface, prefix: string): string {
  return run("levelGrant.activePredicate", { surface: p, prefix });
}

export function grantInsert(
  p: GrantSurface,
  grantID: string,
  granteeID: string,
  levelID: string,
  grantedBy: string,
  expiresAt: SqlArg,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  const values = new DriverValues();
  return values.statement("levelGrant.grantInsert", {
    surface: p,
    grantID,
    granteeID,
    levelID,
    grantedBy,
    expiresAt: values.hold(expiresAt),
    extra: values.holdAll(extra),
  });
}

export function revokeSQL(p: GrantSurface): string {
  return run("levelGrant.revokeSQL", { surface: p });
}

export function listSQL(p: GrantSurface): string {
  return run("levelGrant.listSQL", { surface: p });
}
