import { run } from "./engine.js";
import type { Claims, ClaimEntry, Principal } from "./types.js";

export function claimsContract(entries: readonly ClaimEntry[]): string[] {
  return entries.map((e) => e.key);
}

export function mintClaims(claims: Claims, values: Record<string, string>): string {
  return run("claims.mint", { claims, values });
}

export function mintClaimsValuesWithExtra(
  contract: readonly string[],
  values: Record<string, string>,
  extra?: Record<string, string>,
): string {
  return run("claims.mintWithExtra", { contract, values, extra: extra ?? {} });
}

export function buildClaims(claims: Claims, principal: Principal): Record<string, string> {
  return run("claims.build", { claims, principal });
}

export function mintClaimsFor(claims: Claims, principal: Principal): string {
  return run("claims.mintFor", { claims, principal });
}

export function setRoleSQL(claims: Claims, local: boolean): string {
  return run("claims.setRoleSQL", { claims, local });
}

export function claimsSetSQL(claims: Claims, local: boolean): string {
  return run("claims.claimsSetSQL", { claims, local });
}

export function sessionSetupSQL(claims: Claims, local: boolean): [string, string] {
  return run("claims.sessionSetupSQL", { claims, local });
}
