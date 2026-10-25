import { authorize, call } from "./wasm/demesne_runtime_wasm.js";
import type { ParamStatement, SqlArg } from "./types.js";

type Envelope = { ok: unknown } | { error: string };

function unwrap(raw: string): unknown {
  const r = JSON.parse(raw) as Envelope;
  if ("error" in r) throw new Error(r.error);
  return r.ok;
}

export function run<T>(op: string, args: object): T {
  return unwrap(call(op, JSON.stringify(args))) as T;
}

export function runAuthorize(pdp: object, procedure: string, holds: (perm: string) => boolean): string {
  return unwrap(authorize(JSON.stringify(pdp), procedure, holds)) as string;
}

const MARK = "\u0000demesne:";

export class DriverValues {
  private readonly values: SqlArg[] = [];

  hold(v: SqlArg | undefined): string | null {
    if (v === undefined || v === null) return null;
    this.values.push(v);
    return MARK + (this.values.length - 1);
  }

  holdAll(extra: Record<string, SqlArg>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(extra)) {
      const held = this.hold(v);
      if (held !== null) out[k] = held;
    }
    return out;
  }

  statement(op: string, args: object): ParamStatement {
    const r = run<{ sql: string; args: (string | null)[] }>(op, args);
    return { sql: r.sql, args: r.args.map((a) => (a !== null && a.startsWith(MARK) ? this.values[Number(a.slice(MARK.length))]! : a)) };
  }
}
