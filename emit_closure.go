package demesne

import (
	"fmt"
	"sort"
	"strings"
)

type ClosureTrigger struct {
	Schema      string
	TableSchema string
	Closure     string
	Ancestor    string
	Descendant  string
	Base        string
	BaseID      string
	BaseParent  string
}

func (c ClosureTrigger) schema() string {
	if c.Schema != "" {
		return c.Schema
	}
	return "auth"
}

func (c ClosureTrigger) tableSchema() string {
	if c.TableSchema != "" {
		return c.TableSchema
	}
	return "public"
}

func (c ClosureTrigger) fnName() string { return c.schema() + "." + c.Closure + "_maintain" }

func (c ClosureTrigger) FunctionSQL() string {
	clo, anc, desc := c.Closure, c.Ancestor, c.Descendant
	id, par := c.BaseID, c.BaseParent
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO %[2]s (%[3]s, %[4]s) VALUES (NEW.%[5]s, NEW.%[5]s) ON CONFLICT DO NOTHING;
    IF NEW.%[6]s IS NOT NULL THEN
      INSERT INTO %[2]s (%[3]s, %[4]s)
        SELECT c.%[3]s, NEW.%[5]s FROM %[2]s c WHERE c.%[4]s = NEW.%[6]s
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    DELETE FROM %[2]s WHERE %[4]s = OLD.%[5]s OR %[3]s = OLD.%[5]s;
    RETURN OLD;
  ELSIF (TG_OP = 'UPDATE') THEN
    IF (NEW.%[6]s IS DISTINCT FROM OLD.%[6]s) THEN
      DELETE FROM %[2]s
        WHERE %[4]s IN (SELECT %[4]s FROM %[2]s WHERE %[3]s = NEW.%[5]s)
          AND %[3]s IN (SELECT %[3]s FROM %[2]s WHERE %[4]s = NEW.%[5]s AND %[3]s <> NEW.%[5]s);
      IF NEW.%[6]s IS NOT NULL THEN
        INSERT INTO %[2]s (%[3]s, %[4]s)
          SELECT p.%[3]s, sub.%[4]s
            FROM (SELECT %[3]s FROM %[2]s WHERE %[4]s = NEW.%[6]s) p
            CROSS JOIN (SELECT %[4]s FROM %[2]s WHERE %[3]s = NEW.%[5]s) sub
          ON CONFLICT DO NOTHING;
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;`, c.fnName(), clo, anc, desc, id, par)
}

func (c ClosureTrigger) TriggerSQL() string {
	var b strings.Builder
	for _, op := range []string{"INSERT", "UPDATE", "DELETE"} {
		name := fmt.Sprintf("%s_maintain_%s", c.Closure, strings.ToLower(op[:3]))
		fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, c.tableSchema(), c.Base)
		fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER %s ON %s.%s FOR EACH ROW EXECUTE FUNCTION %s();\n", name, op, c.tableSchema(), c.Base, c.fnName())
	}
	return b.String()
}

func (s *Spec) EmitTriggers() []ClosureTrigger {
	seen := map[string]bool{}
	var out []ClosureTrigger
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			c, ok := r.Repr.(ViaClosure)
			if !ok || seen[c.Closure] {
				continue
			}
			seen[c.Closure] = true
			out = append(out, ClosureTrigger{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(), Closure: c.Closure,
				Ancestor: c.AncestorCol, Descendant: c.DescendantCol,
				Base: c.Base, BaseID: c.BaseID, BaseParent: c.BaseParent,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Closure < out[j].Closure })
	return out
}

func (s *Spec) TriggersSQL() string {
	trigs := s.EmitTriggers()
	groups := s.EmitGroupTriggers()
	if len(trigs) == 0 && len(groups) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("-- ===== Closure maintenance (via closure / via group) =====\n")
	b.WriteString("-- COST: each of these triggers write-amplifies the base table — a change\n")
	b.WriteString("-- fans out to the transitive closure. This is the explicit, opt-in price of\n")
	b.WriteString("-- O(1) indexed reachability (`via closure`) / membership (`via group`).\n\n")
	for _, c := range trigs {
		b.WriteString(c.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(c.TriggerSQL())
		b.WriteString("\n")
	}
	for _, g := range groups {
		b.WriteString(g.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(g.TriggerSQL())
		b.WriteString("\n")
	}
	return b.String()
}

type GroupTrigger struct {
	Schema      string
	TableSchema string
	Closure     string
	GroupCol    string
	MemberCol   string
	Edge        string
	EdgeMember  string
	EdgeGroup   string
}

func (g GroupTrigger) schema() string {
	if g.Schema != "" {
		return g.Schema
	}
	return "auth"
}

func (g GroupTrigger) tableSchema() string {
	if g.TableSchema != "" {
		return g.TableSchema
	}
	return "public"
}

func (g GroupTrigger) fnName() string { return g.schema() + "." + g.Closure + "_rebuild" }

func (g GroupTrigger) FunctionSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- Serialize concurrent rebuilds (CONCURRENCY): a full DELETE+INSERT under READ
  -- COMMITTED can otherwise lose a revocation — a second writer's DELETE cannot see the
  -- first writer's freshly-inserted (uncommitted) rows, so a revoked membership survives.
  -- This closure backs the via-group RLS floor (directly via <Closure>_member, and via any
  -- materialized flat built from it), so a stale survivor is a leak. SHARE ROW EXCLUSIVE
  -- self-conflicts so writers serialize, while ACCESS SHARE readers are NOT blocked.
  LOCK TABLE %[2]s IN SHARE ROW EXCLUSIVE MODE;
  DELETE FROM %[2]s;
  INSERT INTO %[2]s (%[3]s, %[4]s)
  WITH RECURSIVE tc AS (
    SELECT %[6]s AS grp, %[5]s AS mem FROM %[7]s
    UNION
    SELECT tc.grp, e.%[5]s FROM tc JOIN %[7]s e ON e.%[6]s = tc.mem
  )
  SELECT grp, mem FROM tc ON CONFLICT DO NOTHING;
  RETURN NULL;
END;
$$;`, g.fnName(), g.Closure, g.GroupCol, g.MemberCol, g.EdgeMember, g.EdgeGroup, g.Edge)
}

func (g GroupTrigger) TriggerSQL() string {
	name := g.Closure + "_rebuild"
	var b strings.Builder
	fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, g.tableSchema(), g.Edge)
	fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s.%s FOR EACH STATEMENT EXECUTE FUNCTION %s();\n", name, g.tableSchema(), g.Edge, g.fnName())
	return b.String()
}

func (s *Spec) EmitGroupTriggers() []GroupTrigger {
	seen := map[string]bool{}
	var out []GroupTrigger
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGroup)
			if !ok || seen[g.Closure] {
				continue
			}
			seen[g.Closure] = true
			out = append(out, GroupTrigger{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(), Closure: g.Closure,
				GroupCol: g.GroupCol, MemberCol: g.MemberCol,
				Edge: g.Edge, EdgeMember: g.EdgeMember, EdgeGroup: g.EdgeGroup,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Closure < out[j].Closure })
	return out
}

type MaterializedFlat struct {
	Schema      string
	TableSchema string
	Flat        string
	ObjTable    string
	ObjPK       string
	Col         string
	Closure     string
	GroupCol    string
	MemberCol   string
	Kind        string

	ClaimExpr string
}

func (m MaterializedFlat) schema() string {
	if m.Schema != "" {
		return m.Schema
	}
	return "auth"
}
func (m MaterializedFlat) tableSchema() string {
	if m.TableSchema != "" {
		return m.TableSchema
	}
	return "public"
}
func (m MaterializedFlat) qFlat() string       { return m.schema() + "." + m.Flat }
func (m MaterializedFlat) fnName() string      { return m.schema() + "." + m.Flat + "_rebuild" }
func (m MaterializedFlat) reconcileFn() string { return m.schema() + "." + m.Flat + "_reconcile" }

func (m MaterializedFlat) TableSQL() string {
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %[1]s (resource_id text NOT NULL, principal_kind text NOT NULL, principal_id text NOT NULL);\n"+
			"CREATE INDEX IF NOT EXISTS %[2]s_res_idx ON %[1]s (resource_id);\n"+
			"CREATE INDEX IF NOT EXISTS %[2]s_prin_idx ON %[1]s (principal_id);\n",
		m.qFlat(), m.Flat)
}

func (m MaterializedFlat) FunctionSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
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
  LOCK TABLE %[2]s IN SHARE ROW EXCLUSIVE MODE;
  DELETE FROM %[2]s;
  INSERT INTO %[2]s (resource_id, principal_kind, principal_id)
  SELECT o.%[3]s, '%[4]s', c.%[5]s
  FROM %[6]s.%[7]s o JOIN %[6]s.%[8]s c ON c.%[9]s = o.%[10]s;
  RETURN NULL;
END;
$$;`, m.fnName(), m.qFlat(), m.ObjPK, m.Kind, m.MemberCol, m.tableSchema(), m.ObjTable, m.Closure, m.GroupCol, m.Col)
}

func (m MaterializedFlat) ReconcileSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = %[2]s
AS $$
DECLARE
  v_missing integer;
  v_stale integer;
BEGIN
  LOCK TABLE %[3]s IN SHARE ROW EXCLUSIVE MODE;
  WITH canon AS (
    SELECT o.%[4]s AS resource_id, '%[5]s'::text AS principal_kind, c.%[6]s AS principal_id
    FROM %[7]s.%[8]s o JOIN %[7]s.%[9]s c ON c.%[10]s = o.%[11]s
  )
  SELECT
    (SELECT count(*) FROM (SELECT resource_id, principal_kind, principal_id FROM canon
       EXCEPT SELECT resource_id, principal_kind, principal_id FROM %[3]s) d),
    (SELECT count(*) FROM (SELECT resource_id, principal_kind, principal_id FROM %[3]s
       EXCEPT SELECT resource_id, principal_kind, principal_id FROM canon) d)
  INTO v_missing, v_stale;
  IF v_missing > 0 OR v_stale > 0 THEN
    RAISE WARNING 'demesne: flat %[3]s drift — %% missing, %% stale (over-grant); self-healing', v_missing, v_stale;
    DELETE FROM %[3]s;
    INSERT INTO %[3]s (resource_id, principal_kind, principal_id)
    SELECT o.%[4]s, '%[5]s', c.%[6]s
    FROM %[7]s.%[8]s o JOIN %[7]s.%[9]s c ON c.%[10]s = o.%[11]s;
  END IF;
  RETURN v_missing + v_stale;
END;
$$;`, m.reconcileFn(), m.schema(), m.qFlat(), m.ObjPK, m.Kind, m.MemberCol, m.tableSchema(), m.ObjTable, m.Closure, m.GroupCol, m.Col)
}

func (m MaterializedFlat) MemberDefiner() GenFn {
	return GenFn{
		Schema:      m.schema(),
		TableSchema: m.tableSchema(),
		Name:        m.Flat + "_member",
		Sig:         "p_resource text, p_principal text",
		Body:        fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE resource_id = p_resource AND principal_id = p_principal)", m.qFlat()),
	}
}

func (m MaterializedFlat) resourcesFn() string { return m.schema() + "." + m.Flat + "_resources" }

func (m MaterializedFlat) HasReverse() bool { return m.ClaimExpr != "" }

func (m MaterializedFlat) ResourcesDefiner() GenFn {
	return GenFn{
		Schema:      m.schema(),
		TableSchema: m.tableSchema(),
		Name:        m.Flat + "_resources",
		Returns:     "SETOF text",
		RawBody:     true,
		Body: fmt.Sprintf("  SELECT o.%[1]s\n  FROM %[2]s.%[3]s o JOIN %[2]s.%[4]s c ON c.%[5]s = o.%[6]s\n  WHERE c.%[7]s = %[8]s;",
			m.ObjPK, m.tableSchema(), m.ObjTable, m.Closure, m.GroupCol, m.Col, m.MemberCol, m.ClaimExpr),
	}
}

func (m MaterializedFlat) IndexesSQL() string {
	return fmt.Sprintf(
		"CREATE INDEX IF NOT EXISTS %[1]s_%[2]s_l1_idx ON %[3]s.%[1]s (%[2]s);\n"+
			"CREATE INDEX IF NOT EXISTS %[4]s_%[5]s_l2_idx ON %[3]s.%[4]s (%[5]s);\n",
		m.ObjTable, m.Col, m.tableSchema(), m.Closure, m.MemberCol)
}

func (m MaterializedFlat) TriggerSQL() string {
	var b strings.Builder
	for _, tbl := range []string{m.ObjTable, m.Closure} {
		name := m.Flat + "_rebuild_" + tbl
		fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, m.tableSchema(), tbl)

		fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s.%s FOR EACH STATEMENT EXECUTE FUNCTION %s();\n", name, m.tableSchema(), tbl, m.fnName())
	}
	return b.String()
}

func (s *Spec) EmitMaterializedFlats() []MaterializedFlat {
	var out []MaterializedFlat
	for _, obj := range s.Objects {
		claimExpr := ""
		if len(obj.Scoped) > 0 {
			if cust := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1]); cust != nil {
				claimExpr = s.claim(cust.Identifies)
			}
		}
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGroup)
			if !ok || !g.Materialized {
				continue
			}
			kind := ""
			if len(r.Types) > 0 {
				kind = r.Types[0]
			}
			out = append(out, MaterializedFlat{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(),
				Flat:     obj.Table + "_" + r.Name + "_flat",
				ObjTable: obj.Table, ObjPK: obj.pk(), Col: g.Col,
				Closure: g.Closure, GroupCol: g.GroupCol, MemberCol: g.MemberCol,
				Kind: kind, ClaimExpr: claimExpr,
			})
		}
	}
	return out
}

func (s *Spec) FlatsSQL() string {
	flats := s.EmitMaterializedFlats()
	if len(flats) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("-- ===== Materialized via-group flats (via group ... materialized) =====\n")
	b.WriteString("-- COST: each flat is object ⋈ group-closure, rebuilt by an AFTER trigger INSIDE\n")
	b.WriteString("-- the writing transaction (staleness == 0). It trades write-amplification for an\n")
	b.WriteString("-- O(1) indexed membership probe on read — the RLS floor calls the SECURITY DEFINER\n")
	b.WriteString("-- <flat>_member(); the flat itself is never granted to the querying role.\n\n")
	for _, f := range flats {
		b.WriteString(f.TableSQL())
		b.WriteString("\n")
		b.WriteString(f.IndexesSQL())
		b.WriteString("\n")
		b.WriteString(f.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(f.ReconcileSQL())
		b.WriteString("\n\n")
		b.WriteString(f.TriggerSQL())
		b.WriteString("\n")
	}
	return b.String()
}
