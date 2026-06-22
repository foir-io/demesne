import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  mintClaimsFor,
  sessionSetupSQL,
  checkSQL,
  checkManySQL,
  listResourcesSQL,
  resourceAccess,
} from "@demesne/runtime";
import { claims, appSurface, resourceAccess as resourceAccessProj } from "../generated/projection.js";
import { pgCtlAvailable, startCluster, type Cluster } from "../src/pg.js";

const haverun = pgCtlAvailable();
const suite = haverun ? describe : describe.skip;

const sqlFile = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

suite("Postgres round-trip — equal-by-delegation under live RLS", () => {
  let cluster: Cluster;
  let client: Client;
  const note = appSurface.find((o) => o.object === "note")!;
  const noteAcl = resourceAccessProj["note"]!;

  beforeAll(async () => {
    cluster = startCluster();
    client = new Client({ host: cluster.socketDir, user: "postgres", database: "postgres" });
    await client.connect();

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
    const minted = mintClaimsFor(claims, { subject: "member", id: member, scopes: { org, workspace: ws } });
    const [setRole, setClaims] = sessionSetupSQL(claims, true);
    await client.query("BEGIN");
    try {
      await client.query(setRole);
      await client.query(setClaims, [minted]);
      return await fn();
    } finally {
      await client.query("COMMIT");
    }
  }

  const visibleTo = (member: string, org: string, ws: string) =>
    asMember(member, org, ws, async () => {
      const r = await client.query(listResourcesSQL(note), [null, 100]);
      return r.rows.map((row) => row.note_pk as string).sort();
    });

  it("listResources returns exactly the rows RLS authorizes (owner + open, same scope)", async () => {
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]);
    expect(await visibleTo("m2", "o1", "w1")).toEqual(["n2", "n3"]);
  });

  it("checkSQL agrees with visibility; a cross-org owner is filtered by containment", async () => {
    await asMember("m1", "o1", "w1", async () => {
      const can = async (id: string) => (await client.query(checkSQL(note), [id])).rows[0].exists as boolean;
      expect(await can("n1")).toBe(true);
      expect(await can("n3")).toBe(false);
      expect(await can("n4")).toBe(false);
    });
  });

  it("checkMany returns the visible subset of a batch in one round-trip", async () => {
    await asMember("m1", "o1", "w1", async () => {
      const r = await client.query(checkManySQL(note), [["n1", "n2", "n3", "n4"]]);
      expect(r.rows.map((x) => x.note_pk as string).sort()).toEqual(["n1", "n2"]);
    });
  });

  it("accessorsSQL (Expand) enumerates a note's accessors via the trusted definer", async () => {
    await asMember("m1", "o1", "w1", async () => {
      const r = await client.query(resourceAccess.accessorsSQL(noteAcl), ["n2"]);

      const owner = r.rows.find((x) => x.source === "owner");
      expect(owner?.principal_id).toBe("m2");
    });
  });

  it("sharing a note via grantInsert makes it visible to the grantee (end-to-end)", async () => {
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]);

    const { sql, args } = resourceAccess.grantInsert(noteAcl, ["o1", "w1"], "n3", "member", "m1", "read");
    await asMember("m2", "o1", "w1", () => client.query(sql, args));

    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2", "n3"]);
  });
});
