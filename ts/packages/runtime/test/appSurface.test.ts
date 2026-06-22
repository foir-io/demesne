import { describe, it, expect } from "vitest";
import {
  checkSQL,
  checkManySQL,
  listResourcesSQL,
  checkEditSQL,
  listResourcesFastSQL,
  type AppObjectSurface,
} from "../src/index.js";

const record: AppObjectSurface = {
  object: "record",
  table: "records",
  pk: "id",
  flatListFn: "",
  asyncCheckSQL: "",
  editCheckSQL: "",
};

describe("read builders ($1 = row id)", () => {
  it("checkSQL — the point read-check (== PointCheckSQL by construction)", () => {
    expect(checkSQL(record)).toBe("SELECT EXISTS (SELECT 1 FROM records WHERE id = $1)");
  });
  it("checkManySQL — the batched point-check", () => {
    expect(checkManySQL(record)).toBe("SELECT id FROM records WHERE id = ANY($1)");
  });
  it("listResourcesSQL — keyset-paginated, PKs cast to text", () => {
    expect(listResourcesSQL(record)).toBe(
      "SELECT id FROM records WHERE ($1::text IS NULL OR id::text > $1::text) ORDER BY id::text LIMIT $2",
    );
  });
});

describe("a non-`id` PK threads through every builder", () => {
  const doc: AppObjectSurface = { object: "doc", table: "docs", pk: "doc_id", flatListFn: "", asyncCheckSQL: "", editCheckSQL: "" };
  it("listResourcesSQL", () => {
    expect(listResourcesSQL(doc)).toBe(
      "SELECT doc_id FROM docs WHERE ($1::text IS NULL OR doc_id::text > $1::text) ORDER BY doc_id::text LIMIT $2",
    );
  });
});

describe("checkEditSQL — passthrough of the engine's precomputed edit predicate", () => {
  it("returns the inlined update predicate when present, distinct from the read check", () => {
    const editable: AppObjectSurface = {
      object: "doc",
      table: "docs",
      pk: "id",
      flatListFn: "",
      asyncCheckSQL: "",
      editCheckSQL: "SELECT EXISTS (SELECT 1 FROM docs WHERE id = $1 AND (owner_id = (current_setting('x')::json ->> 'customer_id')))",
    };
    expect(checkEditSQL(editable)).toBe(editable.editCheckSQL);
    expect(checkEditSQL(editable)).not.toBe(checkSQL(editable));
  });
  it("returns \"\" for a read-only object (no @rls update permission)", () => {
    expect(checkEditSQL(record)).toBe("");
  });
});

describe("listResourcesFastSQL — the materialized-flat fast path", () => {
  it("is \"\" when the object is not fast-path-eligible", () => {
    expect(listResourcesFastSQL(record)).toBe("");
  });
  it("narrows via <pk> IN (SELECT <flat>_resources()) when flatListFn is set", () => {
    const fast: AppObjectSurface = {
      object: "record",
      table: "records",
      pk: "id",
      flatListFn: "auth.records_team_flat_resources",
      asyncCheckSQL: "",
      editCheckSQL: "",
    };
    expect(listResourcesFastSQL(fast)).toBe(
      "SELECT id FROM records WHERE id IN (SELECT auth.records_team_flat_resources()) AND ($1::text IS NULL OR id::text > $1::text) ORDER BY id::text LIMIT $2",
    );
  });
});
