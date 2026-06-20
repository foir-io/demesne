/**
 * Claims contract + session minting (Layer 2) — `MintClaims` / `BuildClaims` /
 * `MintClaimsFor` and the WithRLS session envelope (`SetRoleSQL` / `ClaimsSetSQL` /
 * `SessionSetupSQL`) from the Go session.go + runtime.go. The engine BUILDS the
 * statements; the CALLER runs them in its own transaction (the moat — no driver here).
 * Everything is spec-derived from the {@link Claims} projection.
 */

import { goCmp, goSort, goJSONStringify } from "./goCompat.js";
import type { Claims, ClaimEntry, Principal } from "./types.js";

/** The flat claims contract — the entry keys, byte-sorted (the entries already are). Mirrors Go `ClaimsContract`. */
export function claimsContract(entries: readonly ClaimEntry[]): string[] {
  return entries.map((e) => e.key);
}

/**
 * Builds the deterministic claims blob a session presents from a principal's claim
 * values. Every supplied key must be a real key of the contract — a typo or stale key is
 * rejected rather than silently producing a claim no policy reads. The JSON is
 * byte-identical to Go `encoding/json` (sorted keys, no whitespace). Mirrors Go `MintClaims`.
 */
export function mintClaims(claims: Claims, values: Record<string, string>): string {
  const known = new Set(claims.contract);
  const bad = Object.keys(values).filter((k) => !known.has(k));
  if (bad.length > 0) {
    bad.sort(goCmp);
    throw new Error(`mintClaims: key(s) not in the claims contract: [${bad.join(" ")}]`);
  }
  return goJSONStringify(values);
}

/**
 * Maps a principal onto the claims contract, producing the `values` map `mintClaims`
 * consumes: the subject's id under that subject's identity key, and each presented scope
 * id under that level's claim key. Fail-closed: an unknown subject, a subject with no
 * identity key when an id is supplied, or a scope for an unknown / VIRTUAL level is
 * rejected (never mint a claim no policy reads). Mirrors Go `BuildClaims`.
 */
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
  // Sort the presented level names → deterministic error order (matches Go).
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

/** One-call path from a principal to the minted claims blob: buildClaims → mintClaims. Mirrors Go `MintClaimsFor`. */
export function mintClaimsFor(claims: Claims, principal: Principal): string {
  return mintClaims(claims, buildClaims(claims, principal));
}

/** `SET [LOCAL] ROLE <role>` — the role switch so RLS evaluates under the connection role. Mirrors Go `SetRoleSQL`. */
export function setRoleSQL(claims: Claims, local: boolean): string {
  return `${local ? "SET LOCAL ROLE" : "SET ROLE"} ${claims.role}`;
}

/** `SELECT set_config('<setting>', $1, <local>)` — installs the minted blob ($1) into the claims GUC. Mirrors Go `ClaimsSetSQL`. */
export function claimsSetSQL(claims: Claims, local: boolean): string {
  return `SELECT set_config('${claims.setting}', $1, ${local})`;
}

/**
 * The WithRLS-shaped statement sequence: assume the RLS role, then install the claims.
 * Run in order inside one tx; the SECOND statement binds the mintClaims result to $1.
 * Mirrors Go `SessionSetupSQL`.
 */
export function sessionSetupSQL(claims: Claims, local: boolean): [string, string] {
  return [setRoleSQL(claims, local), claimsSetSQL(claims, local)];
}
