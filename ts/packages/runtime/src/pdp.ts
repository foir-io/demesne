/**
 * The verb PDP decision logic (Layer 2) — `Authorize` and `ComposeCan` from the Go
 * runtime.go. Pure compute: neither re-evaluates policy, they only read the emitted PDP
 * map and fold pre-computed answers (the database / the emitted map already decided).
 */

import { Decision } from "./decision.js";
import type { Pdp } from "./types.js";

/**
 * Decides whether a caller may invoke a procedure under this PDP. A governed procedure
 * (present in `policy`) is allowed iff `holds` reports the caller has the required
 * permission; an exempt or unlisted procedure is NotGoverned. Mirrors Go `PDP.Authorize`.
 */
export function authorize(pdp: Pdp, procedure: string, holds: (perm: string) => boolean): Decision {
  const perm = pdp.policy[procedure];
  if (perm !== undefined) {
    return holds(perm) ? Decision.Allow : Decision.Deny;
  }
  return Decision.NotGoverned;
}

/**
 * The unified Can(principal, action, resource) decision: COMPOSES the two governing
 * layers a pre-flight check consults without re-evaluating either — the row predicate
 * (`pointGoverned` / `pointAllow`, from the point-check run under the principal's claims)
 * and the verb gate (`pdp`). Fail-closed, and the branch order is load-bearing (a
 * governing layer that DENIES denies the whole check; only when NEITHER layer governs is
 * the result NotGoverned). Mirrors Go `ComposeCan`.
 */
export function composeCan(pointGoverned: boolean, pointAllow: boolean, pdp: Decision): Decision {
  if (!pointGoverned && pdp === Decision.NotGoverned) return Decision.NotGoverned;
  if (pointGoverned && !pointAllow) return Decision.Deny;
  if (pdp === Decision.Deny) return Decision.Deny;
  return Decision.Allow;
}
