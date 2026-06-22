import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildClaims, listResourcesSQL } from "@demesne/runtime";
import { claims, appSurface } from "../generated/supabase/projection.js";
import { pgCtlAvailable, startCluster, type Cluster } from "../src/pg.js";

// The Supabase deployment profile, proven end-to-end (EID-339). Against a real Supabase
// project ($SUPABASE_DB_URL — a session-pooler / IPv4 connection string) or, failing that,
// a local Supabase-shaped Postgres, it walks the WHOLE claims path:
//
//   buildClaims(principal)  ->  stored as the user's app_metadata
//        ->  the emitted custom access-token hook LIFTS each contract key to a top-level claim
//        ->  PostgREST exposes them as request.jwt.claims
//        ->  the generated RLS reads them and filters
//
// so "what listResources returns under the authenticated role" IS "what the subject may
// SELECT" — equal-by-delegation, on Supabase's own role + GUC conventions. It also shows
// service_role (BYPASSRLS) reading past every policy: why it must stay off the request path.

const realUrl = process.env["SUPABASE_DB_URL"];
const canRun = Boolean(realUrl) || pgCtlAvailable();
const suite = canRun ? describe : describe.skip;

const sqlFile = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

suite(`Supabase profile round-trip ${realUrl ? "(real project)" : "(local Supabase-shaped Postgres)"}`, () => {
  let cluster: Cluster | undefined;
  let client: Client;
  const note = appSurface.find((o) => o.object === "note")!;

  beforeAll(async () => {
    if (realUrl) {
      client = new Client({ connectionString: realUrl });
    } else {
      cluster = startCluster();
      client = new Client({ host: cluster.socketDir, user: "postgres", database: "postgres" });
    }
    await client.connect();

    // 1. roles (idempotent) + 2. schemas/tables (no RLS yet) + 3. seed (pre-RLS, so a plain
    //    INSERT works regardless of the connection role's RLS attributes).
    await client.query(sqlFile("../sql/supabase-roles.sql"));
    await client.query(sqlFile("../sql/supabase-setup.sql"));
    await client.query(`
      INSERT INTO public.notes (note_pk, org_ref, ws_ref, owner_ref, visibility) VALUES
        ('n1', 'o1', 'w1', 'm1', 'private'),
        ('n2', 'o1', 'w1', 'm2', 'open'),
        ('n3', 'o1', 'w1', 'm2', 'private'),
        ('n4', 'o2', 'w9', 'm1', 'private')
    `);
    // 4. definers + ENABLE/FORCE RLS + policy, 5. the access-token hook, 6. let the request
    //    role execute the definers the RLS calls.
    await client.query(sqlFile("../generated/supabase/policies.sql"));
    await client.query(sqlFile("../generated/supabase/hook.sql"));
    await client.query("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA demesne TO authenticated");
  }, 60_000);

  afterAll(async () => {
    if (client) {
      // Leave a real project clean.
      await client.query("DROP TABLE IF EXISTS public.note_acl, public.notes CASCADE").catch(() => {});
      await client.query("DROP SCHEMA IF EXISTS demesne CASCADE").catch(() => {});
      await client.query("DROP FUNCTION IF EXISTS public.demesne_access_token_hook(jsonb)").catch(() => {});
      await client.end();
    }
    cluster?.stop();
  });

  // Compute a principal's post-hook JWT claims exactly as Supabase would: buildClaims →
  // app_metadata → the DB hook lifts the contract keys → the resulting top-level claims.
  async function postHookClaims(member: string, org: string, ws: string): Promise<Record<string, unknown>> {
    const appMetadata = buildClaims(claims, { subject: "member", id: member, scopes: { org, workspace: ws } });
    const event = { claims: { role: "authenticated", app_metadata: appMetadata } };
    const r = await client.query<{ claims: Record<string, unknown> }>(
      "SELECT public.demesne_access_token_hook($1::jsonb) -> 'claims' AS claims",
      [JSON.stringify(event)],
    );
    return r.rows[0]!.claims;
  }

  // Read the notes a member can SEE, under the authenticated role + the post-hook claims —
  // the live RLS predicate decides.
  async function visibleTo(member: string, org: string, ws: string): Promise<string[]> {
    const jwtClaims = await postHookClaims(member, org, ws);
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL ROLE authenticated");
      await client.query("SELECT set_config('request.jwt.claims', $1, true)", [JSON.stringify(jwtClaims)]);
      const r = await client.query(listResourcesSQL(note), [null, 100]);
      return r.rows.map((row) => row.note_pk as string).sort();
    } finally {
      await client.query("COMMIT");
    }
  }

  it("the access-token hook lifts each contract key from app_metadata to a top-level claim", async () => {
    const c = await postHookClaims("m1", "o1", "w1");
    expect(c["org"]).toBe("o1");
    expect(c["ws"]).toBe("w1");
    expect(c["member_ref"]).toBe("m1");
    // and it preserves the rest of the token (e.g. role).
    expect(c["role"]).toBe("authenticated");
  });

  it("RLS enforces row reachability under the lifted claims (owner + open, same scope)", async () => {
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]); // owns n1; n2 is open
    expect(await visibleTo("m2", "o1", "w1")).toEqual(["n2", "n3"]); // owns n2 (open) and n3
  });

  it("containment filters a cross-org owner (claims pin the org)", async () => {
    // m1 OWNS n4, but n4 is in org o2 while m1's session pins org o1 — so it is not visible.
    expect(await visibleTo("m1", "o1", "w1")).not.toContain("n4");
  });

  it("service_role (BYPASSRLS) reads past every policy — why it must stay off the request path", async () => {
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL ROLE service_role");
      // No claims set at all; BYPASSRLS ignores the policy and returns every row.
      const r = await client.query(listResourcesSQL(note), [null, 100]);
      expect(r.rows.map((x) => x.note_pk as string).sort()).toEqual(["n1", "n2", "n3", "n4"]);
    } finally {
      await client.query("COMMIT");
    }
  });
});
