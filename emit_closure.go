package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// Closure maintenance (WS3 Phase C): the compiler generates a trigger that keeps
// a transitive-reflexive closure table in sync with a self-referential hierarchy
// (the base table). This is the RLS-native analogue of Zanzibar's Leopard index —
// reachability becomes an indexed read (the <closure>_reachable definer) instead
// of a recursive walk, at the cost of write-amplification on the hierarchy. That
// cost is the EXPLICIT, opt-in `via closure` decision; nothing here is emitted
// unless a relation asks for it.

// ClosureTrigger is the generated maintenance for one closure table: a plpgsql
// trigger function plus its AFTER INSERT/UPDATE/DELETE bindings on the base table.
type ClosureTrigger struct {
	Schema      string
	TableSchema string // schema of the base table the trigger binds ON ("" ⇒ "public")
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

// tableSchema returns the base table's schema (default "public") — the trigger binds
// ON the adopter's table, which may live outside the definer schema.
func (c ClosureTrigger) tableSchema() string {
	if c.TableSchema != "" {
		return c.TableSchema
	}
	return "public"
}

func (c ClosureTrigger) fnName() string { return c.schema() + "." + c.Closure + "_maintain" }

// FunctionSQL renders the CREATE OR REPLACE FUNCTION that maintains the closure.
// The algorithm is the standard incremental closure maintenance:
//   - INSERT: add the self pair, then inherit every ancestor of the new parent.
//   - DELETE: drop every pair touching the node (as ancestor or descendant).
//   - UPDATE (reparent): detach the moved subtree from the node's OLD ancestors,
//     then re-attach it under the NEW parent's ancestors (the parent included).
func (c ClosureTrigger) FunctionSQL() string {
	clo, anc, desc := c.Closure, c.Ancestor, c.Descendant
	id, par := c.BaseID, c.BaseParent
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s()
RETURNS trigger
LANGUAGE plpgsql
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

// TriggerSQL renders the DROP/CREATE TRIGGER bindings (one per op).
func (c ClosureTrigger) TriggerSQL() string {
	var b strings.Builder
	for _, op := range []string{"INSERT", "UPDATE", "DELETE"} {
		name := fmt.Sprintf("%s_maintain_%s", c.Closure, strings.ToLower(op[:3]))
		fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, c.tableSchema(), c.Base)
		fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER %s ON %s.%s FOR EACH ROW EXECUTE FUNCTION %s();\n", name, op, c.tableSchema(), c.Base, c.fnName())
	}
	return b.String()
}

// EmitTriggers returns the closure-maintenance trigger for every distinct closure
// table referenced by a `via closure` relation, sorted by closure name. Empty
// when the spec declares no closure relation (so a non-closure spec — like Foir —
// generates nothing here, and its output is unchanged).
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

// TriggersSQL renders the full closure-maintenance layer (functions then trigger
// bindings) for the spec, prefixed with a COST banner so the write-amplification
// is visible in the generated output. Returns "" when there are no closures.
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

// GroupTrigger is the generated nested-group membership maintenance (v3 WS2): a
// statement-level trigger that REBUILDS the transitive-membership closure from the
// M2M membership edge via a recursive CTE. Unlike the single-parent closure
// (which maintains incrementally), group membership is a DAG, so a full recompute
// per membership-edge change is the simple, always-correct choice — and the
// write-amplification is the explicit, opt-in price (group memberships are
// low-write relative to the data they gate).
type GroupTrigger struct {
	Schema      string
	TableSchema string // schema of the edge table the trigger binds ON ("" ⇒ "public")
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

// tableSchema returns the edge table's schema (default "public") — the trigger binds
// ON the adopter's edge table, which may live outside the definer schema.
func (g GroupTrigger) tableSchema() string {
	if g.TableSchema != "" {
		return g.TableSchema
	}
	return "public"
}

func (g GroupTrigger) fnName() string { return g.schema() + "." + g.Closure + "_rebuild" }

// FunctionSQL renders the recursive-CTE closure rebuild.
func (g GroupTrigger) FunctionSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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

// TriggerSQL renders the statement-level binding (recompute once per statement).
func (g GroupTrigger) TriggerSQL() string {
	name := g.Closure + "_rebuild"
	var b strings.Builder
	fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, g.tableSchema(), g.Edge)
	fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE ON %s.%s FOR EACH STATEMENT EXECUTE FUNCTION %s();\n", name, g.tableSchema(), g.Edge, g.fnName())
	return b.String()
}

// EmitGroupTriggers returns the membership-rebuild trigger for every distinct
// group closure referenced by a `via group` relation, sorted by closure name.
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
