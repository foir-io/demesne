import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { note, mint, sessionSetupSQL, check, checkHandler, Decision, type Querier } from "../generated/framework.js";
import { pgCtlAvailable, startCluster, type Cluster } from "../src/pg.js";

const haverun = pgCtlAvailable();
const suite = haverun ? describe : describe.skip;

const sqlFile = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

suite("Generated TS framework — equal-by-delegation under live RLS", () => {
  let cluster: Cluster;
  let client: Client;
  let q: Querier;

  beforeAll(async () => {
    cluster = startCluster();
    client = new Client({ host: cluster.socketDir, user: "postgres", database: "postgres" });
    await client.connect();
    q = { query: (text, params) => client.query(text, params) };

    await client.query(sqlFile("../sql/schema.sql"));
    await client.query(sqlFile("../generated/policies.sql"));
    await client.query(`
      INSERT INTO notes (note_pk, org_ref, ws_ref, owner_ref, visibility) VALUES
        ('n1', 'o1', 'w1', 'm1', 'private'),
        ('n2', 'o1', 'w1', 'm2', 'open'),
        ('n3', 'o1', 'w1', 'm2', 'private'),
        ('n4', 'o2', 'w9', 'm1', 'private')
    `);
  });

  afterAll(async () => {
    await client?.end();
    cluster?.stop();
  });

  async function asMember<T>(member: string, org: string, ws: string, fn: () => Promise<T>): Promise<T> {
    const minted = mint({ memberRef: member, org, ws });
    const [setRole, setClaims] = sessionSetupSQL(true);
    await client.query("BEGIN");
    try {
      await client.query(setRole);
      await client.query(setClaims, [minted]);
      return await fn();
    } finally {
      await client.query("COMMIT");
    }
  }

  it("canView delegates to the predicate RLS enforces (owner + open allow; cross-tenant + another's private deny)", async () => {
    await asMember("m1", "o1", "w1", async () => {
      expect(await note.canView(q, "n1")).toBe(Decision.Allow);
      expect(await note.canView(q, "n2")).toBe(Decision.Allow);
      expect(await note.canView(q, "n3")).toBe(Decision.Deny);
      expect(await note.canView(q, "n4")).toBe(Decision.Deny);
    });
  });

  it("listResources returns exactly the rows the session may read", async () => {
    const visible = (m: string, o: string, w: string) =>
      asMember(m, o, w, async () => (await note.listResources(q, null, 100)).sort());
    expect(await visible("m1", "o1", "w1")).toEqual(["n1", "n2"]);
    expect(await visible("m2", "o1", "w1")).toEqual(["n2", "n3"]);
  });

  it("checkMany returns the visible subset of a batch in one round-trip", async () => {
    await asMember("m1", "o1", "w1", async () => {
      expect((await note.checkMany(q, ["n1", "n2", "n3", "n4"])).sort()).toEqual(["n1", "n2"]);
    });
  });

  it("check() dispatches by object.verb; an ungoverned verb is NotGoverned", async () => {
    await asMember("m1", "o1", "w1", async () => {
      expect(await check(q, "note", "view", "n1")).toBe(Decision.Allow);
      expect(await check(q, "note", "view", "n3")).toBe(Decision.Deny);
      expect(await check(q, "note", "delete", "n1")).toBe(Decision.NotGoverned);
    });
  });

  it("checkHandler answers a fetch Request with the JSON decision", async () => {
    await asMember("m1", "o1", "w1", async () => {
      const handler = checkHandler(q);
      const allow = await handler(new Request("http://local/check?object=note&verb=view&id=n1"));
      expect(allow.headers.get("Content-Type")).toBe("application/json");
      expect(await allow.json()).toEqual({ decision: "allow" });
      const deny = await handler(new Request("http://local/check?object=note&verb=view&id=n3"));
      expect(await deny.json()).toEqual({ decision: "deny" });
    });
  });
});
