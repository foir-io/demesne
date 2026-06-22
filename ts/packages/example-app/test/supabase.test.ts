import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildClaims, listResourcesSQL } from "@demesne/runtime";
import { claims, appSurface } from "../generated/supabase/projection.js";
import { pgCtlAvailable, startCluster, type Cluster } from "../src/pg.js";

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

      client = new Client({ connectionString: realUrl, ssl: { rejectUnauthorized: false } });
    } else {
      cluster = startCluster();
      client = new Client({ host: cluster.socketDir, user: "postgres", database: "postgres" });
    }
    await client.connect();

    await client.query(sqlFile("../sql/supabase-roles.sql"));
    await client.query(sqlFile("../sql/supabase-setup.sql"));
    await client.query(`
      INSERT INTO public.notes (note_pk, org_ref, ws_ref, owner_ref, visibility) VALUES
        ('n1', 'o1', 'w1', 'm1', 'private'),
        ('n2', 'o1', 'w1', 'm2', 'open'),
        ('n3', 'o1', 'w1', 'm2', 'private'),
        ('n4', 'o2', 'w9', 'm1', 'private')
    `);

    await client.query(sqlFile("../generated/supabase/policies.sql"));
    await client.query(sqlFile("../generated/supabase/hook.sql"));
    await client.query("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA demesne TO authenticated");
  }, 60_000);

  afterAll(async () => {
    if (client) {

      await client.query("DROP TABLE IF EXISTS public.note_acl, public.notes CASCADE").catch(() => {});
      await client.query("DROP SCHEMA IF EXISTS demesne CASCADE").catch(() => {});
      await client.query("DROP FUNCTION IF EXISTS public.demesne_access_token_hook(jsonb)").catch(() => {});
      await client.end();
    }
    cluster?.stop();
  });

  async function postHookClaims(member: string, org: string, ws: string): Promise<Record<string, unknown>> {
    const appMetadata = buildClaims(claims, { subject: "member", id: member, scopes: { org, workspace: ws } });
    const event = { claims: { role: "authenticated", app_metadata: appMetadata } };
    const r = await client.query<{ claims: Record<string, unknown> }>(
      "SELECT public.demesne_access_token_hook($1::jsonb) -> 'claims' AS claims",
      [JSON.stringify(event)],
    );
    return r.rows[0]!.claims;
  }

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

    expect(c["role"]).toBe("authenticated");
  });

  it("RLS enforces row reachability under the lifted claims (owner + open, same scope)", async () => {
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]);
    expect(await visibleTo("m2", "o1", "w1")).toEqual(["n2", "n3"]);
  });

  it("containment filters a cross-org owner (claims pin the org)", async () => {

    expect(await visibleTo("m1", "o1", "w1")).not.toContain("n4");
  });

  it("service_role (BYPASSRLS) reads past every policy — why it must stay off the request path", async () => {
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL ROLE service_role");

      const r = await client.query(listResourcesSQL(note), [null, 100]);
      expect(r.rows.map((x) => x.note_pk as string).sort()).toEqual(["n1", "n2", "n3", "n4"]);
    } finally {
      await client.query("COMMIT");
    }
  });
});
