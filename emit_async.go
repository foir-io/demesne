package demesne

import (
	"fmt"
	"sort"
	"strings"
)

func relationIsAsync(r *Relation) bool {
	g, ok := r.Repr.(ViaGrant)
	return ok && g.Async
}

func (s *Spec) asyncIndexBase(objTable, relName string) string {
	return s.definerSchema() + "." + objTable + "_" + relName + "_async"
}

func (s *Spec) hasAsync() bool {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			if relationIsAsync(r) {
				return true
			}
		}
	}
	return false
}

func (s *Spec) asyncSurfaceTokens() []string {
	var toks []string
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			if relationIsAsync(r) {
				toks = append(toks, s.asyncIndexBase(obj.Table, r.Name))
			}
		}
	}
	return toks
}

func (s *Spec) asyncCursorTable() string { return s.definerSchema() + "._authz_async_cursor" }

type AsyncIndex struct {
	Schema       string
	TableSchema  string
	Changelog    string
	Cursor       string
	Base         string
	GrantTable   string
	RecordCol    string
	KindCol      string
	PrincipalCol string
	DiscrimCol   string
	DiscrimVal   string
}

func (a AsyncIndex) applyFn() string      { return a.Base + "_apply" }
func (a AsyncIndex) rebuildFn() string    { return a.Base + "_rebuild" }
func (a AsyncIndex) affordanceFn() string { return a.Base + "_affordance" }
func (a AsyncIndex) watermarkFn() string  { return a.Base + "_watermark" }

func (a AsyncIndex) indexKey() string { return strings.TrimPrefix(a.Base, a.Schema+".") }

func (a AsyncIndex) relConst() string {
	if a.DiscrimCol != "" {
		return a.DiscrimVal
	}
	return a.GrantTable
}

func (a AsyncIndex) tableSchema() string {
	if a.TableSchema != "" {
		return a.TableSchema
	}
	return "public"
}

func (a AsyncIndex) TableSQL() string {
	idx := strings.ReplaceAll(a.indexKey(), ".", "_")
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %[1]s (\n"+
			"  resource_id text NOT NULL,\n"+
			"  principal_kind text NOT NULL,\n"+
			"  principal_id text NOT NULL,\n"+
			"  PRIMARY KEY (resource_id, principal_kind, principal_id)\n"+
			");\n"+
			"CREATE INDEX IF NOT EXISTS %[2]s_prin_idx ON %[1]s (principal_kind, principal_id);\n",
		a.Base, idx)
}

func (a AsyncIndex) ApplyFnSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE
  h xid8 := pg_snapshot_xmin(pg_current_snapshot());
  prev xid8;
  ev record;
BEGIN
  INSERT INTO %[2]s (index_name) VALUES ('%[3]s') ON CONFLICT (index_name) DO NOTHING;
  SELECT applied_horizon INTO prev FROM %[2]s WHERE index_name = '%[3]s' FOR UPDATE;
  FOR ev IN
    SELECT op, resource_id, principal_kind, principal_id
    FROM %[4]s
    WHERE rel = '%[5]s' AND txid >= prev AND txid < h
    ORDER BY seq
  LOOP
    IF ev.op = 'grant' THEN
      INSERT INTO %[6]s (resource_id, principal_kind, principal_id)
        VALUES (ev.resource_id, ev.principal_kind, ev.principal_id)
        ON CONFLICT DO NOTHING;
    ELSIF ev.op = 'revoke' THEN
      DELETE FROM %[6]s
        WHERE resource_id = ev.resource_id AND principal_kind = ev.principal_kind AND principal_id = ev.principal_id;
    END IF;
  END LOOP;
  UPDATE %[2]s SET applied_horizon = (CASE WHEN h > applied_horizon THEN h ELSE applied_horizon END), updated_at = now()
    WHERE index_name = '%[3]s';
  RETURN h;
END;
$$;`, a.applyFn(), a.Cursor, a.indexKey(), a.Changelog, a.relConst(), a.Base)
}

func (a AsyncIndex) RebuildFnSQL() string {
	where := ""
	if a.DiscrimCol != "" {
		where = fmt.Sprintf(" WHERE %s = '%s'", a.DiscrimCol, a.DiscrimVal)
	}
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE h xid8 := pg_snapshot_xmin(pg_current_snapshot());
BEGIN
  INSERT INTO %[2]s (index_name) VALUES ('%[3]s') ON CONFLICT (index_name) DO NOTHING;
  PERFORM 1 FROM %[2]s WHERE index_name = '%[3]s' FOR UPDATE;
  DELETE FROM %[4]s;
  INSERT INTO %[4]s (resource_id, principal_kind, principal_id)
    SELECT DISTINCT %[5]s, %[6]s, %[7]s FROM %[8]s.%[9]s%[10]s
    ON CONFLICT DO NOTHING;
  UPDATE %[2]s SET applied_horizon = (CASE WHEN h > applied_horizon THEN h ELSE applied_horizon END), updated_at = now()
    WHERE index_name = '%[3]s';
  RETURN h;
END;
$$;`, a.rebuildFn(), a.Cursor, a.indexKey(), a.Base,
		a.RecordCol, a.KindCol, a.PrincipalCol, a.tableSchema(), a.GrantTable, where)
}

func (a AsyncIndex) AffordanceFnSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s(p_resource text, p_kind text, p_principal text)
RETURNS TABLE(allowed boolean, as_of xid8)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS(SELECT 1 FROM %[2]s WHERE resource_id = p_resource AND principal_kind = p_kind AND principal_id = p_principal),
         COALESCE((SELECT applied_horizon FROM %[3]s WHERE index_name = '%[4]s'), '0'::xid8);
$$;`, a.affordanceFn(), a.Base, a.Cursor, a.indexKey())
}

func (a AsyncIndex) WatermarkFnSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS xid8
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$ SELECT COALESCE((SELECT applied_horizon FROM %[2]s WHERE index_name = '%[3]s'), '0'::xid8); $$;`,
		a.watermarkFn(), a.Cursor, a.indexKey())
}

func (s *Spec) AsyncCursorSQL() string {
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %[1]s (\n"+
			"  index_name text PRIMARY KEY,\n"+
			"  applied_horizon xid8 NOT NULL DEFAULT '0'::xid8,\n"+
			"  updated_at timestamptz NOT NULL DEFAULT now()\n"+
			");\n",
		s.asyncCursorTable())
}

func (s *Spec) EmitAsyncIndexes() []AsyncIndex {
	var out []AsyncIndex
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGrant)
			if !ok || !g.Async {
				continue
			}
			out = append(out, AsyncIndex{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(),
				Changelog: s.changelogTable(), Cursor: s.asyncCursorTable(),
				Base:       s.asyncIndexBase(obj.Table, r.Name),
				GrantTable: g.Table, RecordCol: g.RecordCol, KindCol: g.KindCol,
				PrincipalCol: g.PrincipalCol, DiscrimCol: g.DiscrimCol, DiscrimVal: g.DiscrimVal,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Base < out[j].Base })
	return out
}

func (s *Spec) AsyncSQL() string {
	idxs := s.EmitAsyncIndexes()
	if len(idxs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("-- ===== Async affordance tier (via grant ... tracked async) =====\n")
	b.WriteString("-- Eventually-consistent affordance indexes, maintained off the changelog and read\n")
	b.WriteString("-- ONLY by the affordance Check path — NEVER the RLS floor (the WS4 fail-closed\n")
	b.WriteString("-- asymmetry; the V12 validator proves it). A stale cache mis-renders a hint at worst.\n\n")
	b.WriteString(s.AsyncCursorSQL())
	b.WriteString("\n")
	for _, a := range idxs {
		b.WriteString(a.TableSQL())
		b.WriteString("\n")
		b.WriteString(a.ApplyFnSQL())
		b.WriteString("\n\n")
		b.WriteString(a.RebuildFnSQL())
		b.WriteString("\n\n")
		b.WriteString(a.AffordanceFnSQL())
		b.WriteString("\n\n")
		b.WriteString(a.WatermarkFnSQL())
		b.WriteString("\n\n")
	}
	return b.String()
}
