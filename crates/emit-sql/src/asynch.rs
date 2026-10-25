use crate::Sql;
use demesne_gocompat::sort_slice;
use demesne_model::SpecExt;
use demesne_syntax::Repr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsyncIndex {
    pub schema: String,
    pub table_schema: String,
    pub changelog: String,
    pub cursor: String,
    pub base: String,
    pub grant_table: String,
    pub record_col: String,
    pub kind_col: String,
    pub principal_col: String,
    pub discrim_col: String,
    pub discrim_val: String,
    pub id_type: String,
}

impl AsyncIndex {
    fn id_type(&self) -> &str {
        if self.id_type.is_empty() { "text" } else { &self.id_type }
    }

    fn index_key(&self) -> &str {
        let prefix = format!("{}.", self.schema);
        self.base.strip_prefix(prefix.as_str()).unwrap_or(&self.base)
    }

    fn rel_const(&self) -> &str {
        if self.discrim_col.is_empty() { &self.grant_table } else { &self.discrim_val }
    }

    fn table_schema(&self) -> &str {
        if self.table_schema.is_empty() { "public" } else { &self.table_schema }
    }

    #[must_use]
    pub fn table_sql(&self) -> String {
        let idx = self.index_key().replace('.', "_");
        format!(
            "CREATE TABLE IF NOT EXISTS {b} (\n  resource_id {t} NOT NULL,\n  principal_kind text NOT NULL,\n  principal_id {t} NOT NULL,\n  PRIMARY KEY (resource_id, principal_kind, principal_id)\n);\nCREATE INDEX IF NOT EXISTS {idx}_prin_idx ON {b} (principal_kind, principal_id);\n",
            b = self.base,
            t = self.id_type()
        )
    }

    fn fn_name(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.base)
    }

    #[must_use]
    pub fn apply_fn_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE
  h xid8 := pg_snapshot_xmin(pg_current_snapshot());
  prev xid8;
  ev record;
BEGIN
  INSERT INTO {cur} (index_name) VALUES ('{key}') ON CONFLICT (index_name) DO NOTHING;
  SELECT applied_horizon INTO prev FROM {cur} WHERE index_name = '{key}' FOR UPDATE;
  FOR ev IN
    SELECT op, resource_id, principal_kind, principal_id
    FROM {cl}
    WHERE rel = '{rel}' AND txid >= prev AND txid < h
    ORDER BY seq
  LOOP
    IF ev.op = 'grant' THEN
      INSERT INTO {b} (resource_id, principal_kind, principal_id)
        VALUES (ev.resource_id, ev.principal_kind, ev.principal_id)
        ON CONFLICT DO NOTHING;
    ELSIF ev.op = 'revoke' THEN
      DELETE FROM {b}
        WHERE resource_id = ev.resource_id AND principal_kind = ev.principal_kind AND principal_id = ev.principal_id;
    END IF;
  END LOOP;
  UPDATE {cur} SET applied_horizon = (CASE WHEN h > applied_horizon THEN h ELSE applied_horizon END), updated_at = now()
    WHERE index_name = '{key}';
  RETURN h;
END;
$$;",
            f = self.fn_name("apply"),
            cur = self.cursor,
            key = self.index_key(),
            cl = self.changelog,
            rel = self.rel_const(),
            b = self.base
        )
    }

    #[must_use]
    pub fn rebuild_fn_sql(&self) -> String {
        let where_ = if self.discrim_col.is_empty() { String::new() } else { format!(" WHERE {} = '{}'", self.discrim_col, self.discrim_val) };
        format!(
            r"CREATE OR REPLACE FUNCTION {f}()
RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE h xid8 := pg_snapshot_xmin(pg_current_snapshot());
BEGIN
  INSERT INTO {cur} (index_name) VALUES ('{key}') ON CONFLICT (index_name) DO NOTHING;
  PERFORM 1 FROM {cur} WHERE index_name = '{key}' FOR UPDATE;
  DELETE FROM {b};
  INSERT INTO {b} (resource_id, principal_kind, principal_id)
    SELECT DISTINCT {rc}, {kc}, {pc} FROM {ts}.{gt}{w}
    ON CONFLICT DO NOTHING;
  UPDATE {cur} SET applied_horizon = (CASE WHEN h > applied_horizon THEN h ELSE applied_horizon END), updated_at = now()
    WHERE index_name = '{key}';
  RETURN h;
END;
$$;",
            f = self.fn_name("rebuild"),
            cur = self.cursor,
            key = self.index_key(),
            b = self.base,
            rc = self.record_col,
            kc = self.kind_col,
            pc = self.principal_col,
            ts = self.table_schema(),
            gt = self.grant_table,
            w = where_
        )
    }

    #[must_use]
    pub fn affordance_fn_sql(&self) -> String {
        format!(
            r"CREATE OR REPLACE FUNCTION {f}(p_resource {t}, p_kind text, p_principal {t})
RETURNS TABLE(allowed boolean, as_of xid8)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS(SELECT 1 FROM {b} WHERE resource_id = p_resource AND principal_kind = p_kind AND principal_id = p_principal),
         COALESCE((SELECT applied_horizon FROM {cur} WHERE index_name = '{key}'), '0'::xid8);
$$;",
            f = self.fn_name("affordance"),
            b = self.base,
            cur = self.cursor,
            key = self.index_key(),
            t = self.id_type()
        )
    }

    #[must_use]
    pub fn watermark_fn_sql(&self) -> String {
        format!(
            "CREATE OR REPLACE FUNCTION {f}()\nRETURNS xid8\nLANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public\nAS $$ SELECT COALESCE((SELECT applied_horizon FROM {cur} WHERE index_name = '{key}'), '0'::xid8); $$;",
            f = self.fn_name("watermark"),
            cur = self.cursor,
            key = self.index_key()
        )
    }
}

impl Sql<'_> {
    fn async_cursor_table(&self) -> String {
        format!("{}._authz_async_cursor", self.s.definer_schema())
    }

    #[must_use]
    pub fn async_cursor_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (\n  index_name text PRIMARY KEY,\n  applied_horizon xid8 NOT NULL DEFAULT '0'::xid8,\n  updated_at timestamptz NOT NULL DEFAULT now()\n);\n",
            self.async_cursor_table()
        )
    }

    #[must_use]
    pub fn emit_async_indexes(&self) -> Vec<AsyncIndex> {
        let mut out = Vec::new();
        for (obj, r) in self.s.relations() {
            let Repr::Grant(g) = &r.repr else { continue };
            if !g.is_async {
                continue;
            }
            out.push(AsyncIndex {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                changelog: format!("{}._authz_changelog", self.s.definer_schema()),
                cursor: self.async_cursor_table(),
                base: self.s.async_index_base(&obj.table, &r.name),
                grant_table: g.table.clone(),
                record_col: g.record_col.clone(),
                kind_col: g.kind_col.clone(),
                principal_col: g.principal_col.clone(),
                discrim_col: g.discrim_col.clone().unwrap_or_default(),
                discrim_val: g.discrim_val.clone().unwrap_or_default(),
                id_type: self.s.id_type().into(),
            });
        }
        sort_slice(&mut out, |a, b| a.base < b.base);
        out
    }

    #[must_use]
    pub fn async_sql(&self) -> String {
        let idxs = self.emit_async_indexes();
        if idxs.is_empty() {
            return String::new();
        }
        let mut b = String::from(
            "-- ===== Async affordance tier (via grant ... tracked async) =====\n-- Eventually-consistent affordance indexes, maintained off the changelog and read\n-- ONLY by the affordance Check path — NEVER the RLS floor (the WS4 fail-closed\n-- asymmetry; the V12 validator proves it). A stale cache mis-renders a hint at worst.\n\n",
        );
        b.push_str(&self.async_cursor_sql());
        b.push('\n');
        for a in &idxs {
            b.push_str(&a.table_sql());
            b.push('\n');
            b.push_str(&a.apply_fn_sql());
            b.push_str("\n\n");
            b.push_str(&a.rebuild_fn_sql());
            b.push_str("\n\n");
            b.push_str(&a.affordance_fn_sql());
            b.push_str("\n\n");
            b.push_str(&a.watermark_fn_sql());
            b.push_str("\n\n");
        }
        b
    }
}
