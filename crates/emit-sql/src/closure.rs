use crate::Sql;
use crate::genfn::GenFn;
use demesne_model::SpecExt;
use demesne_syntax::Repr;
use std::collections::HashSet;
use std::fmt::Write as _;

fn or_default<'a>(s: &'a str, d: &'a str) -> &'a str {
    if s.is_empty() { d } else { s }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosureTrigger {
    pub schema: String,
    pub table_schema: String,
    pub closure: String,
    pub ancestor: String,
    pub descendant: String,
    pub base: String,
    pub base_id: String,
    pub base_parent: String,
}

impl ClosureTrigger {
    fn fn_name(&self) -> String {
        format!("{}.{}_maintain", or_default(&self.schema, "auth"), self.closure)
    }

    #[must_use]
    pub fn function_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO {clo} ({anc}, {desc}) VALUES (NEW.{id}, NEW.{id}) ON CONFLICT DO NOTHING;
    IF NEW.{par} IS NOT NULL THEN
      INSERT INTO {clo} ({anc}, {desc})
        SELECT c.{anc}, NEW.{id} FROM {clo} c WHERE c.{desc} = NEW.{par}
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    DELETE FROM {clo} WHERE {desc} = OLD.{id} OR {anc} = OLD.{id};
    RETURN OLD;
  ELSIF (TG_OP = 'UPDATE') THEN
    IF (NEW.{par} IS DISTINCT FROM OLD.{par}) THEN
      DELETE FROM {clo}
        WHERE {desc} IN (SELECT {desc} FROM {clo} WHERE {anc} = NEW.{id})
          AND {anc} IN (SELECT {anc} FROM {clo} WHERE {desc} = NEW.{id} AND {anc} <> NEW.{id});
      IF NEW.{par} IS NOT NULL THEN
        INSERT INTO {clo} ({anc}, {desc})
          SELECT p.{anc}, sub.{desc}
            FROM (SELECT {anc} FROM {clo} WHERE {desc} = NEW.{par}) p
            CROSS JOIN (SELECT {desc} FROM {clo} WHERE {anc} = NEW.{id}) sub
          ON CONFLICT DO NOTHING;
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;",
            f = self.fn_name(),
            clo = self.closure,
            anc = self.ancestor,
            desc = self.descendant,
            id = self.base_id,
            par = self.base_parent
        )
    }

    #[must_use]
    pub fn trigger_sql(&self) -> String {
        let ts = or_default(&self.table_schema, "public");
        let mut b = String::new();
        for op in ["INSERT", "UPDATE", "DELETE"] {
            let name = format!("{}_maintain_{}", self.closure, op[..3].to_lowercase());
            writeln!(b, "DROP TRIGGER IF EXISTS {name} ON {ts}.{};", self.base).expect("fmt::Write for String never fails");
            writeln!(b, "CREATE TRIGGER {name} AFTER {op} ON {ts}.{} FOR EACH ROW EXECUTE FUNCTION {}();", self.base, self.fn_name())
                .expect("fmt::Write for String never fails");
        }
        b
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupTrigger {
    pub schema: String,
    pub table_schema: String,
    pub closure: String,
    pub group_col: String,
    pub member_col: String,
    pub edge: String,
    pub edge_member: String,
    pub edge_group: String,
}

impl GroupTrigger {
    fn fn_name(&self) -> String {
        format!("{}.{}_rebuild", or_default(&self.schema, "auth"), self.closure)
    }

    #[must_use]
    pub fn function_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- Fast path: nothing to close over and nothing stale to clear. Load-bearing
  -- beyond speed: a statement trigger fires even when the statement touched
  -- zero rows, so WITHOUT this exit every unrelated cascade into the edge
  -- table (deleting a member-able principal that has no memberships) reached
  -- for the rebuild lock while already holding the cascade's own lock on the
  -- closure, and two such sessions deadlocked on the upgrade.
  IF NOT EXISTS (SELECT 1 FROM {edge}) AND NOT EXISTS (SELECT 1 FROM {clo}) THEN
    RETURN NULL;
  END IF;
  -- Serialize concurrent rebuilds (CONCURRENCY): a full DELETE+INSERT under READ
  -- COMMITTED can otherwise lose a revocation — a second writer's DELETE cannot see the
  -- first writer's freshly-inserted (uncommitted) rows, so a revoked membership survives.
  -- This closure backs the via-group RLS floor (directly via <Closure>_member, and via any
  -- materialized flat built from it), so a stale survivor is a leak. An advisory
  -- transaction lock self-conflicts, so the second rebuild waits for the first COMMIT
  -- and its DELETE sees the first's rows (same guarantee a table lock gave), but unlike
  -- LOCK TABLE it is never an upgrade of the cascade's implicit lock on the closure,
  -- which is what deadlocked concurrent edge-cascading deletes. Readers are unaffected.
  PERFORM pg_advisory_xact_lock(hashtext('{clo}_rebuild'));
  DELETE FROM {clo};
  INSERT INTO {clo} ({gc}, {mc})
  WITH RECURSIVE tc AS (
    SELECT {eg} AS grp, {em} AS mem FROM {edge}
    UNION
    SELECT tc.grp, e.{em} FROM tc JOIN {edge} e ON e.{eg} = tc.mem
  )
  SELECT grp, mem FROM tc ON CONFLICT DO NOTHING;
  RETURN NULL;
END;
$$;",
            f = self.fn_name(),
            clo = self.closure,
            gc = self.group_col,
            mc = self.member_col,
            em = self.edge_member,
            eg = self.edge_group,
            edge = self.edge
        )
    }

    #[must_use]
    pub fn trigger_sql(&self) -> String {
        let ts = or_default(&self.table_schema, "public");
        let name = format!("{}_rebuild", self.closure);
        format!(
            "DROP TRIGGER IF EXISTS {name} ON {ts}.{e};\nCREATE TRIGGER {name} AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON {ts}.{e} FOR EACH STATEMENT EXECUTE FUNCTION {f}();\n",
            e = self.edge,
            f = self.fn_name()
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializedFlat {
    pub schema: String,
    pub table_schema: String,
    pub flat: String,
    pub obj_table: String,
    pub obj_pk: String,
    pub col: String,
    pub closure: String,
    pub group_col: String,
    pub member_col: String,
    pub kind: String,
    pub claim_expr: String,
    pub id_type: String,
}

impl MaterializedFlat {
    fn id_type(&self) -> &str {
        or_default(&self.id_type, "text")
    }
    fn schema(&self) -> &str {
        or_default(&self.schema, "auth")
    }
    fn table_schema(&self) -> &str {
        or_default(&self.table_schema, "public")
    }
    fn q_flat(&self) -> String {
        format!("{}.{}", self.schema(), self.flat)
    }
    fn fn_name(&self) -> String {
        format!("{}.{}_rebuild", self.schema(), self.flat)
    }
    fn reconcile_fn(&self) -> String {
        format!("{}.{}_reconcile", self.schema(), self.flat)
    }

    #[must_use]
    pub fn table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {q} (resource_id {t} NOT NULL, principal_kind text NOT NULL, principal_id {t} NOT NULL);\nCREATE INDEX IF NOT EXISTS {f}_res_idx ON {q} (resource_id);\nCREATE INDEX IF NOT EXISTS {f}_prin_idx ON {q} (principal_id);\n",
            q = self.q_flat(),
            f = self.flat,
            t = self.id_type()
        )
    }

    #[must_use]
    pub fn function_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- Serialize concurrent rebuilds (CONCURRENCY): a full DELETE+INSERT under READ
  -- COMMITTED can otherwise lose a revocation — a second writer's DELETE cannot see the
  -- first writer's freshly-inserted (uncommitted) rows, so a revoked row survives → the
  -- RLS floor reads a stale flat (a leak). SHARE ROW EXCLUSIVE self-conflicts so writers
  -- serialize, while the ACCESS SHARE reader (the <flat>_member SELECT) is NOT blocked.
  LOCK TABLE {q} IN SHARE ROW EXCLUSIVE MODE;
  DELETE FROM {q};
  INSERT INTO {q} (resource_id, principal_kind, principal_id)
  SELECT o.{pk}, '{kind}', c.{mc}
  FROM {ts}.{ot} o JOIN {ts}.{clo} c ON c.{gc} = o.{col};
  RETURN NULL;
END;
$$;",
            f = self.fn_name(),
            q = self.q_flat(),
            pk = self.obj_pk,
            kind = self.kind,
            mc = self.member_col,
            ts = self.table_schema(),
            ot = self.obj_table,
            clo = self.closure,
            gc = self.group_col,
            col = self.col
        )
    }

    #[must_use]
    pub fn reconcile_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = {s}
AS $$
DECLARE
  v_missing integer;
  v_stale integer;
BEGIN
  LOCK TABLE {q} IN SHARE ROW EXCLUSIVE MODE;
  WITH canon AS (
    SELECT o.{pk} AS resource_id, '{kind}'::text AS principal_kind, c.{mc} AS principal_id
    FROM {ts}.{ot} o JOIN {ts}.{clo} c ON c.{gc} = o.{col}
  )
  SELECT
    (SELECT count(*) FROM (SELECT resource_id, principal_kind, principal_id FROM canon
       EXCEPT SELECT resource_id, principal_kind, principal_id FROM {q}) d),
    (SELECT count(*) FROM (SELECT resource_id, principal_kind, principal_id FROM {q}
       EXCEPT SELECT resource_id, principal_kind, principal_id FROM canon) d)
  INTO v_missing, v_stale;
  IF v_missing > 0 OR v_stale > 0 THEN
    RAISE WARNING 'demesne: flat {q} drift — % missing, % stale (over-grant); self-healing', v_missing, v_stale;
    DELETE FROM {q};
    INSERT INTO {q} (resource_id, principal_kind, principal_id)
    SELECT o.{pk}, '{kind}', c.{mc}
    FROM {ts}.{ot} o JOIN {ts}.{clo} c ON c.{gc} = o.{col};
  END IF;
  RETURN v_missing + v_stale;
END;
$$;",
            f = self.reconcile_fn(),
            s = self.schema(),
            q = self.q_flat(),
            pk = self.obj_pk,
            kind = self.kind,
            mc = self.member_col,
            ts = self.table_schema(),
            ot = self.obj_table,
            clo = self.closure,
            gc = self.group_col,
            col = self.col
        )
    }

    #[must_use]
    pub fn member_definer(&self) -> GenFn {
        GenFn {
            schema: self.schema().into(),
            table_schema: self.table_schema().into(),
            name: format!("{}_member", self.flat),
            sig: format!("p_resource {t}, p_principal {t}", t = self.id_type()),
            body: format!("EXISTS (SELECT 1 FROM {} WHERE resource_id = p_resource AND principal_id = p_principal)", self.q_flat()),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn has_reverse(&self) -> bool {
        !self.claim_expr.is_empty()
    }

    #[must_use]
    pub fn resources_definer(&self) -> GenFn {
        GenFn {
            schema: self.schema().into(),
            table_schema: self.table_schema().into(),
            name: format!("{}_resources", self.flat),
            returns: "SETOF text".into(),
            raw_body: true,
            body: format!(
                "  SELECT o.{pk}\n  FROM {ts}.{ot} o JOIN {ts}.{clo} c ON c.{gc} = o.{col}\n  WHERE c.{mc} = {claim};",
                pk = self.obj_pk,
                ts = self.table_schema(),
                ot = self.obj_table,
                clo = self.closure,
                gc = self.group_col,
                col = self.col,
                mc = self.member_col,
                claim = self.claim_expr
            ),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn indexes_sql(&self) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {ot}_{col}_l1_idx ON {ts}.{ot} ({col});\nCREATE INDEX IF NOT EXISTS {clo}_{mc}_l2_idx ON {ts}.{clo} ({mc});\n",
            ot = self.obj_table,
            col = self.col,
            ts = self.table_schema(),
            clo = self.closure,
            mc = self.member_col
        )
    }

    #[must_use]
    pub fn trigger_sql(&self) -> String {
        let mut b = String::new();
        for tbl in [&self.obj_table, &self.closure] {
            let name = format!("{}_rebuild_{}", self.flat, tbl);
            writeln!(b, "DROP TRIGGER IF EXISTS {name} ON {}.{tbl};", self.table_schema()).expect("fmt::Write for String never fails");
            writeln!(
                b,
                "CREATE TRIGGER {name} AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON {}.{tbl} FOR EACH STATEMENT EXECUTE FUNCTION {}();",
                self.table_schema(),
                self.fn_name()
            )
            .expect("fmt::Write for String never fails");
        }
        b
    }
}

impl Sql<'_> {
    #[must_use]
    pub fn emit_triggers(&self) -> Vec<ClosureTrigger> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (_, r) in self.s.relations() {
            let Repr::Closure(c) = &r.repr else { continue };
            let Some(base) = &c.base else { continue };
            if !seen.insert(c.closure.clone()) {
                continue;
            }
            out.push(ClosureTrigger {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                closure: c.closure.clone(),
                ancestor: c.ancestor_col.clone(),
                descendant: c.descendant_col.clone(),
                base: base.clone(),
                base_id: c.base_id.clone().unwrap_or_default(),
                base_parent: c.base_parent.clone().unwrap_or_default(),
            });
        }
        out.sort_by(|a, b| a.closure.cmp(&b.closure));
        out
    }

    #[must_use]
    pub fn emit_group_triggers(&self) -> Vec<GroupTrigger> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (_, r) in self.s.relations() {
            if let Some(t) = self.group_trigger(&r.repr)
                && seen.insert(t.closure.clone())
            {
                out.push(t);
            }
        }
        out.sort_by(|a, b| a.closure.cmp(&b.closure));
        out
    }

    fn group_trigger(&self, repr: &Repr) -> Option<GroupTrigger> {
        let o = |v: &Option<String>| v.clone().unwrap_or_default();
        match repr {
            Repr::Group(g) => Some(GroupTrigger {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                closure: g.closure.clone(),
                group_col: g.group_col.clone(),
                member_col: g.member_col.clone(),
                edge: g.edge.clone(),
                edge_member: g.edge_member.clone(),
                edge_group: g.edge_group.clone(),
            }),
            Repr::Grant(g) => Some(GroupTrigger {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                closure: g.group_closure.clone()?,
                group_col: o(&g.group_group_col),
                member_col: o(&g.group_member_col),
                edge: o(&g.group_edge),
                edge_member: o(&g.group_edge_member),
                edge_group: o(&g.group_edge_group),
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn triggers_sql(&self) -> String {
        let trigs = self.emit_triggers();
        let groups = self.emit_group_triggers();
        if trigs.is_empty() && groups.is_empty() {
            return String::new();
        }
        let mut b = String::from(
            "-- ===== Closure maintenance (via closure / via group) =====\n-- COST: each of these triggers write-amplifies the base table — a change\n-- fans out to the transitive closure. This is the explicit, opt-in price of\n-- O(1) indexed reachability (`via closure`) / membership (`via group`).\n\n",
        );
        for c in &trigs {
            b.push_str(&c.function_sql());
            b.push_str("\n\n");
            b.push_str(&c.trigger_sql());
            b.push('\n');
        }
        for g in &groups {
            b.push_str(&g.function_sql());
            b.push_str("\n\n");
            b.push_str(&g.trigger_sql());
            b.push('\n');
        }
        b
    }

    #[must_use]
    pub fn emit_materialized_flats(&self) -> Vec<MaterializedFlat> {
        let mut out = Vec::new();
        for obj in &self.s.objects {
            let claim_expr = obj.scoped.last().and_then(|l| self.s.owner_subject(l)).map(|cust| self.id_claim(cust.identifies())).unwrap_or_default();
            let materialized = obj.relations.iter().filter_map(|r| match &r.repr {
                Repr::Group(g) if g.materialized => Some((r, g)),
                _ => None,
            });
            for (r, g) in materialized {
                out.push(MaterializedFlat {
                    schema: self.s.definer_schema().into(),
                    table_schema: self.s.table_schema().into(),
                    flat: format!("{}_{}_flat", obj.table, r.name),
                    obj_table: obj.table.clone(),
                    obj_pk: obj.pk().into(),
                    col: g.col.clone(),
                    closure: g.closure.clone(),
                    group_col: g.group_col.clone(),
                    member_col: g.member_col.clone(),
                    kind: r.types.first().cloned().unwrap_or_default(),
                    claim_expr: claim_expr.clone(),
                    id_type: self.s.id_type().into(),
                });
            }
        }
        out
    }

    #[must_use]
    pub fn flats_sql(&self) -> String {
        let flats = self.emit_materialized_flats();
        if flats.is_empty() {
            return String::new();
        }
        let mut b = String::from(
            "-- ===== Materialized via-group flats (via group ... materialized) =====\n-- COST: each flat is object ⋈ group-closure, rebuilt by an AFTER trigger INSIDE\n-- the writing transaction (staleness == 0). It trades write-amplification for an\n-- O(1) indexed membership probe on read — the RLS floor calls the SECURITY DEFINER\n-- <flat>_member(); the flat itself is never granted to the querying role.\n\n",
        );
        for f in &flats {
            b.push_str(&f.table_sql());
            b.push('\n');
            b.push_str(&f.indexes_sql());
            b.push('\n');
            b.push_str(&f.function_sql());
            b.push_str("\n\n");
            b.push_str(&f.reconcile_sql());
            b.push_str("\n\n");
            b.push_str(&f.trigger_sql());
            b.push('\n');
        }
        b
    }
}
