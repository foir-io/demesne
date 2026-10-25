use crate::Sql;
use demesne_gocompat::sort_slice;
use demesne_model::SpecExt;
use demesne_syntax::Repr;
use std::collections::HashSet;
use std::fmt::Write as _;

pub const CHANGELOG_CHANNEL: &str = "demesne_authz_changelog";

fn or_default<'a>(s: &'a str, d: &'a str) -> &'a str {
    if s.is_empty() { d } else { s }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangelogTrigger {
    pub schema: String,
    pub table_schema: String,
    pub changelog: String,
    pub table: String,
    pub record_col: String,
    pub kind_col: String,
    pub principal_col: String,
    pub discrim_col: String,
}

impl ChangelogTrigger {
    fn fn_name(&self) -> String {
        format!("{}.{}_changelog", or_default(&self.schema, "auth"), self.table)
    }

    fn rel_expr(&self, row_var: &str) -> String {
        if !self.discrim_col.is_empty() {
            return format!("{row_var}.{}", self.discrim_col);
        }
        format!("'{}'", self.table)
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
    INSERT INTO {cl} (rel, resource_id, principal_kind, principal_id, op)
      VALUES ({new_rel}, NEW.{rc}, NEW.{kc}, NEW.{pc}, 'grant');
    PERFORM pg_notify('{ch}', json_build_object('rel', {new_rel}, 'resource_id', NEW.{rc}, 'principal_kind', NEW.{kc}, 'principal_id', NEW.{pc}, 'op', 'grant')::text);
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    INSERT INTO {cl} (rel, resource_id, principal_kind, principal_id, op)
      VALUES ({old_rel}, OLD.{rc}, OLD.{kc}, OLD.{pc}, 'revoke');
    PERFORM pg_notify('{ch}', json_build_object('rel', {old_rel}, 'resource_id', OLD.{rc}, 'principal_kind', OLD.{kc}, 'principal_id', OLD.{pc}, 'op', 'revoke')::text);
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;",
            f = self.fn_name(),
            cl = self.changelog,
            new_rel = self.rel_expr("NEW"),
            rc = self.record_col,
            kc = self.kind_col,
            pc = self.principal_col,
            old_rel = self.rel_expr("OLD"),
            ch = CHANGELOG_CHANNEL
        )
    }

    #[must_use]
    pub fn trigger_sql(&self) -> String {
        let name = format!("{}_changelog", self.table);
        let ts = or_default(&self.table_schema, "public");
        format!(
            "DROP TRIGGER IF EXISTS {name} ON {ts}.{t};\nCREATE TRIGGER {name} AFTER INSERT OR DELETE ON {ts}.{t} FOR EACH ROW EXECUTE FUNCTION {f}();\n",
            t = self.table,
            f = self.fn_name()
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectChangelogTrigger {
    pub schema: String,
    pub table_schema: String,
    pub changelog: String,
    pub table: String,
    pub rel: String,
    pub pk: String,
    pub owner_id_col: String,
    pub owner_kind_col: String,
    pub mode_col: String,
}

impl ObjectChangelogTrigger {
    fn fn_name(&self) -> String {
        format!("{}.{}_obj_changelog", or_default(&self.schema, "auth"), self.table)
    }

    fn tracked_cols(&self) -> Vec<String> {
        let mut cols = Vec::new();
        if !self.owner_id_col.is_empty() {
            cols.push(self.owner_id_col.clone());
            cols.push(self.owner_kind_col.clone());
        }
        if !self.mode_col.is_empty() {
            cols.push(self.mode_col.clone());
        }
        cols
    }

    #[must_use]
    pub fn function_sql(&self) -> String {
        let cols = "(rel, resource_id, principal_kind, principal_id, op)";
        let (cl, rel, pk, ch) = (&self.changelog, &self.rel, &self.pk, CHANGELOG_CHANNEL);
        let mut body = String::new();
        if !self.owner_id_col.is_empty() {
            let (id, kind) = (&self.owner_id_col, &self.owner_kind_col);
            writeln!(body, "  IF (OLD.{id} IS DISTINCT FROM NEW.{id}) OR (OLD.{kind} IS DISTINCT FROM NEW.{kind}) THEN")
                .expect("fmt::Write for String never fails");
            writeln!(body, "    IF OLD.{id} IS NOT NULL THEN").expect("fmt::Write for String never fails");
            writeln!(body, "      INSERT INTO {cl} {cols}").expect("fmt::Write for String never fails");
            writeln!(body, "        VALUES ('{rel}', NEW.{pk}, COALESCE(OLD.{kind}, ''), OLD.{id}, 'revoke');").expect("fmt::Write for String never fails");
            writeln!(body,
                "      PERFORM pg_notify('{ch}', json_build_object('rel', '{rel}', 'resource_id', NEW.{pk}, 'principal_kind', COALESCE(OLD.{kind}, ''), 'principal_id', OLD.{id}, 'op', 'revoke')::text);"
            ).expect("fmt::Write for String never fails");
            body.push_str("    END IF;\n");
            writeln!(body, "    IF NEW.{id} IS NOT NULL THEN").expect("fmt::Write for String never fails");
            writeln!(body, "      INSERT INTO {cl} {cols}").expect("fmt::Write for String never fails");
            writeln!(body, "        VALUES ('{rel}', NEW.{pk}, COALESCE(NEW.{kind}, ''), NEW.{id}, 'grant');").expect("fmt::Write for String never fails");
            writeln!(body,
                "      PERFORM pg_notify('{ch}', json_build_object('rel', '{rel}', 'resource_id', NEW.{pk}, 'principal_kind', COALESCE(NEW.{kind}, ''), 'principal_id', NEW.{id}, 'op', 'grant')::text);"
            ).expect("fmt::Write for String never fails");
            body.push_str("    END IF;\n");
            body.push_str("  END IF;\n");
        }
        if !self.mode_col.is_empty() {
            let m = &self.mode_col;
            writeln!(body, "  IF (OLD.{m} IS DISTINCT FROM NEW.{m}) THEN").expect("fmt::Write for String never fails");
            writeln!(body, "    INSERT INTO {cl} {cols}").expect("fmt::Write for String never fails");
            writeln!(body, "      VALUES ('{rel}', NEW.{pk}, '', '', 'visibility');").expect("fmt::Write for String never fails");
            writeln!(body,
                "    PERFORM pg_notify('{ch}', json_build_object('rel', '{rel}', 'resource_id', NEW.{pk}, 'principal_kind', '', 'principal_id', '', 'op', 'visibility')::text);"
            ).expect("fmt::Write for String never fails");
            body.push_str("  END IF;\n");
        }
        format!(
            "CREATE OR REPLACE FUNCTION {}()\nRETURNS trigger\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\nAS $$\nBEGIN\n{}  RETURN NEW;\nEND;\n$$;",
            self.fn_name(),
            body
        )
    }

    #[must_use]
    pub fn trigger_sql(&self) -> String {
        let name = format!("{}_obj_changelog", self.table);
        let ts = or_default(&self.table_schema, "public");
        format!(
            "DROP TRIGGER IF EXISTS {name} ON {ts}.{t};\nCREATE TRIGGER {name} AFTER UPDATE OF {cols} ON {ts}.{t} FOR EACH ROW EXECUTE FUNCTION {f}();\n",
            t = self.table,
            cols = self.tracked_cols().join(", "),
            f = self.fn_name()
        )
    }
}

impl Sql<'_> {
    fn changelog_table(&self) -> String {
        format!("{}._authz_changelog", self.s.definer_schema())
    }

    #[must_use]
    pub fn changelog_table_sql(&self) -> String {
        let t = self.changelog_table();
        let txid = if self.s.has_async() { ",\n  txid xid8 NOT NULL DEFAULT pg_current_xact_id()" } else { "" };
        let mut base = format!(
            "CREATE TABLE IF NOT EXISTS {t} (\n  seq bigserial PRIMARY KEY,\n  rel text NOT NULL,\n  resource_id text NOT NULL,\n  principal_kind text NOT NULL,\n  principal_id text NOT NULL,\n  op text NOT NULL,\n  at timestamptz NOT NULL DEFAULT now(){txid}\n);\nCREATE INDEX IF NOT EXISTS _authz_changelog_seq_idx ON {t} (seq);\nCREATE INDEX IF NOT EXISTS _authz_changelog_principal_idx ON {t} (principal_kind, principal_id);\n"
        );
        if self.s.has_async() {
            writeln!(base, "CREATE INDEX IF NOT EXISTS _authz_changelog_rel_txid_idx ON {t} (rel, txid);").expect("fmt::Write for String never fails");
        }
        base
    }

    #[must_use]
    pub fn emit_changelog_triggers(&self) -> Vec<ChangelogTrigger> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (_, r) in self.s.relations() {
            let Repr::Grant(g) = &r.repr else { continue };
            if !g.tracked || !seen.insert(g.table.clone()) {
                continue;
            }
            out.push(ChangelogTrigger {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                changelog: self.changelog_table(),
                table: g.table.clone(),
                record_col: g.record_col.clone(),
                kind_col: g.kind_col.clone(),
                principal_col: g.principal_col.clone(),
                discrim_col: g.discrim_col.clone().unwrap_or_default(),
            });
        }
        sort_slice(&mut out, |a, b| a.table < b.table);
        out
    }

    #[must_use]
    pub fn emit_object_changelog_triggers(&self) -> Vec<ObjectChangelogTrigger> {
        let mut out = Vec::new();
        for obj in &self.s.objects {
            if !obj.track_owner && !obj.track_visibility {
                continue;
            }
            let mut t = ObjectChangelogTrigger {
                schema: self.s.definer_schema().into(),
                table_schema: self.s.table_schema().into(),
                changelog: self.changelog_table(),
                table: obj.table.clone(),
                rel: obj.name.clone(),
                pk: obj.pk().into(),
                ..Default::default()
            };
            if obj.track_owner
                && let Some((id, kind)) = obj.owner_changelog_cols()
            {
                t.owner_id_col = id.into();
                t.owner_kind_col = kind.into();
            }
            if obj.track_visibility
                && let Some(m) = obj.mode_changelog_col()
            {
                t.mode_col = m.into();
            }
            out.push(t);
        }
        sort_slice(&mut out, |a, b| a.table < b.table);
        out
    }

    #[must_use]
    pub fn changelog_sql(&self) -> String {
        let grant_trigs = self.emit_changelog_triggers();
        let obj_trigs = self.emit_object_changelog_triggers();
        if grant_trigs.is_empty() && obj_trigs.is_empty() {
            return String::new();
        }
        let mut b = String::from(
            "-- ===== Authz changelog (via grant ... tracked + track owner/visibility) =====\n-- An ordered (seq = zookie) feed of grant/revoke + owner/visibility events on the\n-- tracked stores/objects — the source a consumer Watches to react to access changes\n-- (WS5 realtime force-drop). It never feeds the RLS floor (the WS4 fail-closed asymmetry).\n\n",
        );
        b.push_str(&self.changelog_table_sql());
        b.push('\n');
        for c in &grant_trigs {
            b.push_str(&c.function_sql());
            b.push_str("\n\n");
            b.push_str(&c.trigger_sql());
            b.push('\n');
        }
        for c in &obj_trigs {
            b.push_str(&c.function_sql());
            b.push_str("\n\n");
            b.push_str(&c.trigger_sql());
            b.push('\n');
        }
        b
    }
}
