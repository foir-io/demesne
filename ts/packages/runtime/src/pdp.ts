import type { Decision } from "./decision.js";
import { run, runAuthorize } from "./engine.js";
import type { Pdp } from "./types.js";

export function authorize(pdp: Pdp, procedure: string, holds: (perm: string) => boolean): Decision {
  return runAuthorize(pdp, procedure, holds) as Decision;
}

export function composeCan(pointGoverned: boolean, pointAllow: boolean, pdp: Decision): Decision {
  return run("pdp.composeCan", { pointGoverned, pointAllow, pdp });
}
