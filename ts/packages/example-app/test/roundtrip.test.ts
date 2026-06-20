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

// The TypeScript worked example (EID-338). It stands up a real Postgres, applies the
// EMITTED RLS (generated/policies.sql) over a hand-written non-Foir schema, seeds a few
// rows as superuser, and then drives the @demesne/runtime builders AS the `authenticated`
// role under the subject's minted claims. Because the runtime returns SQL the live RLS
// predicate decides, "what listResources returns" IS "what the subject may SELECT" — the
// equal-by-delegation moat, proven end-to-end against a database.
//
// Skips cleanly where Postgres (pg_ctl) is unavailable.

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

    // Seed as superuser (bypasses RLS): four notes across two orgs.
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

  // Run fn inside a transaction under a member's session (the WithRLS envelope): assume
  // the RLS role, install the minted claims, then run. The DATABASE decides.
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
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]); // owns n1; n2 is open
    expect(await visibleTo("m2", "o1", "w1")).toEqual(["n2", "n3"]); // owns n2 (also open) and n3
  });

  it("checkSQL agrees with visibility; a cross-org owner is filtered by containment", async () => {
    await asMember("m1", "o1", "w1", async () => {
      const can = async (id: string) => (await client.query(checkSQL(note), [id])).rows[0].exists as boolean;
      expect(await can("n1")).toBe(true); // owns it
      expect(await can("n3")).toBe(false); // m2's private
      expect(await can("n4")).toBe(false); // m1 OWNS it, but it is in org o2 — claims pin o1
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
      // n2 is owned by m2 (and open); the owner row is enumerated.
      const owner = r.rows.find((x) => x.source === "owner");
      expect(owner?.principal_id).toBe("m2");
    });
  });

  it("sharing a note via grantInsert makes it visible to the grantee (end-to-end)", async () => {
    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2"]); // m1 cannot see n3 yet

    // Write the ACL grant (note_acl is not RLS-governed; authenticated may write it).
    const { sql, args } = resourceAccess.grantInsert(noteAcl, ["o1", "w1"], "n3", "member", "m1", "read");
    await asMember("m2", "o1", "w1", () => client.query(sql, args));

    expect(await visibleTo("m1", "o1", "w1")).toEqual(["n1", "n2", "n3"]); // now shared-read
  });
});
