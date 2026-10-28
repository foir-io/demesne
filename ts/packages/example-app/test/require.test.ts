import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mintClaimsFor, sessionSetupSQL, checkEditSQL } from "@foir/demesne";
import { claims, appSurface } from "../generated/require/projection.js";
import { pgCtlAvailable, startCluster, type Cluster } from "../src/pg.js";

const haverun = pgCtlAvailable();
const suite = haverun ? describe : describe.skip;

const sqlFile = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

suite("require — a RESTRICTIVE policy narrows what the permissive one admits", () => {
  let cluster: Cluster;
  let client: Client;
  const invitation = appSurface.find((o) => o.object === "invitation")!;

  beforeAll(async () => {
    cluster = startCluster();
    client = new Client({ host: cluster.socketDir, user: "postgres", database: "postgres" });
    await client.connect();

    await client.query(sqlFile("../sql/require-schema.sql"));
    await client.query(sqlFile("../generated/require/policies.sql"));

    await client.query(`
      INSERT INTO projects (id, tenant_id) VALUES ('p1','t1'), ('p2','t1'), ('pX','t2');
      INSERT INTO roles (id, key, permissions) VALUES ('r_owner','owner','{invitations:write}');
      INSERT INTO role_assignments (id, principal_kind, principal_id, tenant_id, project_id, role_id)
        VALUES ('a1','admin','u1','t1',NULL,'r_owner');
      INSERT INTO invitations (id, tenant_id, invited_by, email, project_ids)
        VALUES ('i_mine','t1','u1','a@example.com','{p1}'),
               ('i_theirs','t1','u2','b@example.com','{p1}');
    `);
  });

  afterAll(async () => {
    await client?.end();
    cluster?.stop();
  });

  async function asAdmin<T>(sub: string, tenant: string, fn: () => Promise<T>): Promise<T> {
    const minted = mintClaimsFor(claims, { subject: "admin", id: sub, scopes: { tenant } });
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

  const insertInvitation = (id: string, projects: string[]) =>
    asAdmin("u1", "t1", async () => {
      await client.query(
        "INSERT INTO invitations (id, tenant_id, invited_by, email, project_ids) VALUES ($1,'t1','u1',$2,$3)",
        [id, `${id}@example.com`, projects],
      );
    });

  const insertOutcome = async (id: string, projects: string[]) => {
    try {
      await insertInvitation(id, projects);
      return "accepted";
    } catch (e) {
      return (e as Error).message.includes("row-level security") ? "refused" : `error: ${(e as Error).message}`;
    }
  };

  it("POSITIVE CONTROL — u1 may write an invitation naming a project of their own tenant", async () => {
    expect(await insertOutcome("ok1", ["p1", "p2"])).toBe("accepted");
    expect(await insertOutcome("ok2", [])).toBe("accepted");
  });

  it("REFUSAL — the same tenant-wide holder may NOT name another tenant's project, which only the restrictive policy reads", async () => {
    expect(await insertOutcome("bad1", ["pX"])).toBe("refused");
    expect(await insertOutcome("bad2", ["p1", "pX"])).toBe("refused");
    expect(await insertOutcome("bad3", ["no-such-project"])).toBe("refused");
  });

  it("MUTATION — dropping the restrictive policy makes the identical write succeed", async () => {
    expect(await insertOutcome("mut_before", ["pX"])).toBe("refused");

    await client.query("DROP POLICY invitations_insert_require ON public.invitations");
    try {
      expect(await insertOutcome("mut_after", ["pX"])).toBe("accepted");
      expect(await insertOutcome("mut_control", ["p1"])).toBe("accepted");
    } finally {
      await client.query(sqlFile("../generated/require/policies.sql"));
    }

    expect(await insertOutcome("mut_restored", ["pX"])).toBe("refused");
  });

  it("a require is per-verb: `require create` leaves SELECT alone, so the row written without it stays readable", async () => {
    const rows = await asAdmin("u1", "t1", async () =>
      (await client.query("SELECT id FROM invitations WHERE id = 'mut_after'")).rows,
    );
    expect(rows).toHaveLength(1);
  });

  it("`require edit = @self(invited_by)` narrows UPDATE, and the app surface agrees", async () => {
    const revoke = (id: string) =>
      asAdmin("u1", "t1", async () =>
        (await client.query("UPDATE invitations SET email = 'revoked' WHERE id = $1", [id])).rowCount,
      );

    expect(await revoke("i_mine")).toBe(1);
    expect(await revoke("i_theirs")).toBe(0);

    const canEdit = (id: string) =>
      asAdmin("u1", "t1", async () => (await client.query(checkEditSQL(invitation), [id])).rows[0].exists as boolean);
    expect(await canEdit("i_mine")).toBe(true);
    expect(await canEdit("i_theirs")).toBe(false);
  });
});
