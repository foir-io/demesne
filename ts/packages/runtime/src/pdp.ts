

import { Decision } from "./decision.js";
import type { Pdp } from "./types.js";

export function authorize(pdp: Pdp, procedure: string, holds: (perm: string) => boolean): Decision {
  const perm = pdp.policy[procedure];
  if (perm !== undefined) {
    return holds(perm) ? Decision.Allow : Decision.Deny;
  }
  return Decision.NotGoverned;
}

export function composeCan(pointGoverned: boolean, pointAllow: boolean, pdp: Decision): Decision {
  if (!pointGoverned && pdp === Decision.NotGoverned) return Decision.NotGoverned;
  if (pointGoverned && !pointAllow) return Decision.Deny;
  if (pdp === Decision.Deny) return Decision.Deny;
  return Decision.Allow;
}
