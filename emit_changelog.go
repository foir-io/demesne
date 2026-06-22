package demesne

import (
	"fmt"
	"sort"
	"strings"
)

func (s *Spec) changelogTable() string { return s.definerSchema() + "._authz_changelog" }

func (s *Spec) ChangelogTableSQL() string {
	t := s.changelogTable()
	base := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %[1]s (\n"+
			"  seq bigserial PRIMARY KEY,\n"+
			"  rel text NOT NULL,\n"+
			"  resource_id text NOT NULL,\n"+
			"  principal_kind text NOT NULL,\n"+
			"  principal_id text NOT NULL,\n"+
			"  op text NOT NULL,\n"+
			"  at timestamptz NOT NULL DEFAULT now()%[2]s\n"+
			");\n"+
			"CREATE INDEX IF NOT EXISTS _authz_changelog_seq_idx ON %[1]s (seq);\n"+
			"CREATE INDEX IF NOT EXISTS _authz_changelog_principal_idx ON %[1]s (principal_kind, principal_id);\n",
		t, s.changelogTxidColumn())
	if s.hasAsync() {

		base += fmt.Sprintf("CREATE INDEX IF NOT EXISTS _authz_changelog_rel_txid_idx ON %[1]s (rel, txid);\n", t)
	}
	return base
}

func (s *Spec) changelogTxidColumn() string {
	if !s.hasAsync() {
		return ""
	}
	return ",\n  txid xid8 NOT NULL DEFAULT pg_current_xact_id()"
}

type ChangelogTrigger struct {
	Schema       string
	TableSchema  string
	Changelog    string
	Table        string
	RecordCol    string
	KindCol      string
	PrincipalCol string
	DiscrimCol   string
}

func (c ChangelogTrigger) schema() string {
	if c.Schema != "" {
		return c.Schema
	}
	return "auth"
}
func (c ChangelogTrigger) tableSchema() string {
	if c.TableSchema != "" {
		return c.TableSchema
	}
	return "public"
}
func (c ChangelogTrigger) fnName() string { return c.schema() + "." + c.Table + "_changelog" }

func (c ChangelogTrigger) relExpr(rowVar string) string {
	if c.DiscrimCol != "" {
		return rowVar + "." + c.DiscrimCol
	}
	return "'" + c.Table + "'"
}

const ChangelogChannel = "demesne_authz_changelog"

func (c ChangelogTrigger) FunctionSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO %[2]s (rel, resource_id, principal_kind, principal_id, op)
      VALUES (%[3]s, NEW.%[4]s, NEW.%[5]s, NEW.%[6]s, 'grant');
    PERFORM pg_notify('%[8]s', json_build_object('rel', %[3]s, 'resource_id', NEW.%[4]s, 'principal_kind', NEW.%[5]s, 'principal_id', NEW.%[6]s, 'op', 'grant')::text);
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    INSERT INTO %[2]s (rel, resource_id, principal_kind, principal_id, op)
      VALUES (%[7]s, OLD.%[4]s, OLD.%[5]s, OLD.%[6]s, 'revoke');
    PERFORM pg_notify('%[8]s', json_build_object('rel', %[7]s, 'resource_id', OLD.%[4]s, 'principal_kind', OLD.%[5]s, 'principal_id', OLD.%[6]s, 'op', 'revoke')::text);
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;`, c.fnName(), c.Changelog, c.relExpr("NEW"), c.RecordCol, c.KindCol, c.PrincipalCol, c.relExpr("OLD"), ChangelogChannel)
}

func (c ChangelogTrigger) TriggerSQL() string {
	name := c.Table + "_changelog"
	var b strings.Builder
	fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, c.tableSchema(), c.Table)
	fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER INSERT OR DELETE ON %s.%s FOR EACH ROW EXECUTE FUNCTION %s();\n", name, c.tableSchema(), c.Table, c.fnName())
	return b.String()
}

func (s *Spec) EmitChangelogTriggers() []ChangelogTrigger {
	seen := map[string]bool{}
	var out []ChangelogTrigger
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGrant)
			if !ok || !g.Tracked || seen[g.Table] {
				continue
			}
			seen[g.Table] = true
			out = append(out, ChangelogTrigger{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(),
				Changelog: s.changelogTable(), Table: g.Table,
				RecordCol: g.RecordCol, KindCol: g.KindCol, PrincipalCol: g.PrincipalCol,
				DiscrimCol: g.DiscrimCol,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

type ObjectChangelogTrigger struct {
	Schema       string
	TableSchema  string
	Changelog    string
	Table        string
	Rel          string
	PK           string
	OwnerIDCol   string
	OwnerKindCol string
	ModeCol      string
}

func (c ObjectChangelogTrigger) schema() string {
	if c.Schema != "" {
		return c.Schema
	}
	return "auth"
}
func (c ObjectChangelogTrigger) tableSchema() string {
	if c.TableSchema != "" {
		return c.TableSchema
	}
	return "public"
}
func (c ObjectChangelogTrigger) fnName() string { return c.schema() + "." + c.Table + "_obj_changelog" }

func (c ObjectChangelogTrigger) trackedCols() []string {
	var cols []string
	if c.OwnerIDCol != "" {
		cols = append(cols, c.OwnerIDCol, c.OwnerKindCol)
	}
	if c.ModeCol != "" {
		cols = append(cols, c.ModeCol)
	}
	return cols
}

func (c ObjectChangelogTrigger) FunctionSQL() string {
	cols := "(rel, resource_id, principal_kind, principal_id, op)"
	var body strings.Builder
	if c.OwnerIDCol != "" {

		fmt.Fprintf(&body, "  IF (OLD.%[1]s IS DISTINCT FROM NEW.%[1]s) OR (OLD.%[2]s IS DISTINCT FROM NEW.%[2]s) THEN\n", c.OwnerIDCol, c.OwnerKindCol)
		fmt.Fprintf(&body, "    IF OLD.%s IS NOT NULL THEN\n", c.OwnerIDCol)
		fmt.Fprintf(&body, "      INSERT INTO %s %s\n", c.Changelog, cols)
		fmt.Fprintf(&body, "        VALUES ('%s', NEW.%s, COALESCE(OLD.%s, ''), OLD.%s, 'revoke');\n", c.Rel, c.PK, c.OwnerKindCol, c.OwnerIDCol)
		fmt.Fprintf(&body, "      PERFORM pg_notify('%s', json_build_object('rel', '%s', 'resource_id', NEW.%s, 'principal_kind', COALESCE(OLD.%s, ''), 'principal_id', OLD.%s, 'op', 'revoke')::text);\n", ChangelogChannel, c.Rel, c.PK, c.OwnerKindCol, c.OwnerIDCol)
		body.WriteString("    END IF;\n")
		fmt.Fprintf(&body, "    IF NEW.%s IS NOT NULL THEN\n", c.OwnerIDCol)
		fmt.Fprintf(&body, "      INSERT INTO %s %s\n", c.Changelog, cols)
		fmt.Fprintf(&body, "        VALUES ('%s', NEW.%s, COALESCE(NEW.%s, ''), NEW.%s, 'grant');\n", c.Rel, c.PK, c.OwnerKindCol, c.OwnerIDCol)
		fmt.Fprintf(&body, "      PERFORM pg_notify('%s', json_build_object('rel', '%s', 'resource_id', NEW.%s, 'principal_kind', COALESCE(NEW.%s, ''), 'principal_id', NEW.%s, 'op', 'grant')::text);\n", ChangelogChannel, c.Rel, c.PK, c.OwnerKindCol, c.OwnerIDCol)
		body.WriteString("    END IF;\n")
		body.WriteString("  END IF;\n")
	}
	if c.ModeCol != "" {

		fmt.Fprintf(&body, "  IF (OLD.%[1]s IS DISTINCT FROM NEW.%[1]s) THEN\n", c.ModeCol)
		fmt.Fprintf(&body, "    INSERT INTO %s %s\n", c.Changelog, cols)
		fmt.Fprintf(&body, "      VALUES ('%s', NEW.%s, '', '', 'visibility');\n", c.Rel, c.PK)
		fmt.Fprintf(&body, "    PERFORM pg_notify('%s', json_build_object('rel', '%s', 'resource_id', NEW.%s, 'principal_kind', '', 'principal_id', '', 'op', 'visibility')::text);\n", ChangelogChannel, c.Rel, c.PK)
		body.WriteString("  END IF;\n")
	}
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
%s  RETURN NEW;
END;
$$;`, c.fnName(), body.String())
}

func (c ObjectChangelogTrigger) TriggerSQL() string {
	name := c.Table + "_obj_changelog"
	var b strings.Builder
	fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, c.tableSchema(), c.Table)
	fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER UPDATE OF %s ON %s.%s FOR EACH ROW EXECUTE FUNCTION %s();\n",
		name, strings.Join(c.trackedCols(), ", "), c.tableSchema(), c.Table, c.fnName())
	return b.String()
}

func (s *Spec) EmitObjectChangelogTriggers() []ObjectChangelogTrigger {
	var out []ObjectChangelogTrigger
	for _, obj := range s.Objects {
		if !obj.TrackOwner && !obj.TrackVisibility {
			continue
		}
		t := ObjectChangelogTrigger{
			Schema: s.definerSchema(), TableSchema: s.tableSchema(),
			Changelog: s.changelogTable(), Table: obj.Table,
			Rel: obj.Name, PK: obj.pk(),
		}
		if obj.TrackOwner {
			if idCol, kindCol, ok := obj.ownerChangelogCols(); ok {
				t.OwnerIDCol, t.OwnerKindCol = idCol, kindCol
			}
		}
		if obj.TrackVisibility {
			if modeCol, ok := obj.modeChangelogCol(); ok {
				t.ModeCol = modeCol
			}
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

func (s *Spec) ChangelogSQL() string {
	grantTrigs := s.EmitChangelogTriggers()
	objTrigs := s.EmitObjectChangelogTriggers()
	if len(grantTrigs) == 0 && len(objTrigs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("-- ===== Authz changelog (via grant ... tracked + track owner/visibility) =====\n")
	b.WriteString("-- An ordered (seq = zookie) feed of grant/revoke + owner/visibility events on the\n")
	b.WriteString("-- tracked stores/objects — the source a consumer Watches to react to access changes\n")
	b.WriteString("-- (WS5 realtime force-drop). It never feeds the RLS floor (the WS4 fail-closed asymmetry).\n\n")
	b.WriteString(s.ChangelogTableSQL())
	b.WriteString("\n")
	for _, c := range grantTrigs {
		b.WriteString(c.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(c.TriggerSQL())
		b.WriteString("\n")
	}
	for _, c := range objTrigs {
		b.WriteString(c.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(c.TriggerSQL())
		b.WriteString("\n")
	}
	return b.String()
}
