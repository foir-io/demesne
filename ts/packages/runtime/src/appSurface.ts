import { run } from "./engine.js";
import type { AppObjectSurface } from "./types.js";

export function checkSQL(o: AppObjectSurface): string {
  return run("app.checkSQL", { object: o });
}

export function checkManySQL(o: AppObjectSurface): string {
  return run("app.checkManySQL", { object: o });
}

export function listResourcesSQL(o: AppObjectSurface): string {
  return run("app.listResourcesSQL", { object: o });
}

export function checkEditSQL(o: AppObjectSurface): string {
  return run("app.checkEditSQL", { object: o });
}

export function listResourcesFastSQL(o: AppObjectSurface): string {
  return run("app.listResourcesFastSQL", { object: o });
}
