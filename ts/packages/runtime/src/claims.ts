

import { goCmp, goSort, goJSONStringify } from "./goCompat.js";
import type { Claims, ClaimEntry, Principal } from "./types.js";

export function claimsContract(entries: readonly ClaimEntry[]): string[] {
  return entries.map((e) => e.key);
}

export function mintClaims(claims: Claims, values: Record<string, string>): string {
  const known = new Set(claims.contract);
  const bad = Object.keys(values).filter((k) => !known.has(k));
  if (bad.length > 0) {
    bad.sort(goCmp);
    throw new Error(`mintClaims: key(s) not in the claims contract: [${bad.join(" ")}]`);
  }
  return goJSONStringify(values);
}

export function buildClaims(claims: Claims, principal: Principal): Record<string, string> {
  const subject = claims.subjects.find((s) => s.name === principal.subject);
  if (subject === undefined) {
    throw new Error(`buildClaims: no subject "${principal.subject}" in the spec`);
  }
  const values: Record<string, string> = {};
  if (principal.id !== "") {
    if (subject.identifies === "") {
      throw new Error(
        `buildClaims: subject "${principal.subject}" has no identity key (\`identifies\`) but an id was supplied`,
      );
    }
    values[subject.identifies] = principal.id;
  }

  for (const name of goSort(Object.keys(principal.scopes))) {
    const level = claims.levels.find((l) => l.name === name);
    if (level === undefined) {
      throw new Error(`buildClaims: subject "${principal.subject}" presents a scope for unknown level "${name}"`);
    }
    if (level.virtual) {
      throw new Error(`buildClaims: level "${name}" is virtual (no scope claim) — it cannot carry a scope id`);
    }
    values[level.claimKey] = principal.scopes[name]!;
  }
  return values;
}

export function mintClaimsFor(claims: Claims, principal: Principal): string {
  return mintClaims(claims, buildClaims(claims, principal));
}

export function setRoleSQL(claims: Claims, local: boolean): string {
  return `${local ? "SET LOCAL ROLE" : "SET ROLE"} ${claims.role}`;
}

export function claimsSetSQL(claims: Claims, local: boolean): string {
  return `SELECT set_config('${claims.setting}', $1, ${local})`;
}

export function sessionSetupSQL(claims: Claims, local: boolean): [string, string] {
  return [setRoleSQL(claims, local), claimsSetSQL(claims, local)];
}
