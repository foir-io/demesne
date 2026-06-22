package demesne

import (
	"strings"
	"testing"
)

const closureSpec = `
topology { level org level project parent org }
vocabulary v { permission self:read }
subject member { anchor project reach self identifies folder_id roles configurable v binds owner }
object doc {
  table  docs
  scoped org > project
  relation infolder: member via closure folder_closure(ancestor_id, descendant_id) base folders(id, parent_id) on folder_id
  permission view = infolder @rls maps select
}
`

func TestClosure_ReachabilityLookupAndTrigger(t *testing.T) {
	s, err := Parse(closureSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var rel *Relation
	for _, r := range s.Objects[0].Relations {
		if r.Name == "infolder" {
			rel = r
		}
	}
	if rel == nil || rel.CostClass() != Closure {
		t.Fatalf("infolder cost class = %v, want closure", rel.CostClass())
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sel := findPolicy(rls, "docs_select")
	if sel == nil {
		t.Fatalf("no docs_select (unsupported: %v)", rls.Unsupported)
	}
	want := "auth.folder_closure_reachable((current_setting('request.jwt.claims', true)::json ->> 'folder_id'), folder_id)"
	if !strings.Contains(sel.Using, want) {
		t.Errorf("docs_select missing the closure reachability call:\n%s", sel.Using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var reach *GenFn
	for i := range defs {
		if defs[i].Name == "folder_closure_reachable" {
			reach = &defs[i]
		}
	}
	if reach == nil {
		t.Fatal("no folder_closure_reachable definer generated")
	}
	if reach.Body != "EXISTS (SELECT 1 FROM folder_closure WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant)" {
		t.Errorf("reachability body = %q", reach.Body)
	}
	if !strings.Contains(reach.CreateSQL(), "SECURITY DEFINER") {
		t.Error("reachability lookup is not SECURITY DEFINER")
	}

	trigs := s.EmitTriggers()
	if len(trigs) != 1 || trigs[0].Closure != "folder_closure" || trigs[0].Base != "folders" {
		t.Fatalf("EmitTriggers = %+v, want one for folder_closure on folders", trigs)
	}
	fn := trigs[0].FunctionSQL()
	for _, frag := range []string{
		"CREATE OR REPLACE FUNCTION auth.folder_closure_maintain()",
		"RETURNS trigger",
		"SECURITY DEFINER",

		"TG_OP = 'INSERT'",
		"VALUES (NEW.id, NEW.id)",
		"WHERE c.descendant_id = NEW.parent_id",
		"TG_OP = 'DELETE'",
		"TG_OP = 'UPDATE'",
		"NEW.parent_id IS DISTINCT FROM OLD.parent_id",
	} {
		if !strings.Contains(fn, frag) {
			t.Errorf("maintenance function missing %q:\n%s", frag, fn)
		}
	}
	trg := trigs[0].TriggerSQL()
	for _, frag := range []string{
		"AFTER INSERT ON public.folders",
		"AFTER UPDATE ON public.folders",
		"AFTER DELETE ON public.folders",
		"EXECUTE FUNCTION auth.folder_closure_maintain()",
	} {
		if !strings.Contains(trg, frag) {
			t.Errorf("trigger bindings missing %q:\n%s", frag, trg)
		}
	}

	if !strings.Contains(s.TriggersSQL(), "COST:") {
		t.Error("TriggersSQL does not surface the write-amplification cost")
	}
}

func TestClosure_AbsentWhenUnused(t *testing.T) {
	s := mustSpec(t, `
		topology { level a }
		subject x { anchor a reach self identifies sub roles none }
		object o { table t scoped a relation owner: x via cid permission view = owner @rls maps select }`)
	if got := s.TriggersSQL(); got != "" {
		t.Errorf("a closure-free spec emitted trigger SQL:\n%s", got)
	}
	if got := s.EmitTriggers(); len(got) != 0 {
		t.Errorf("a closure-free spec emitted %d triggers", len(got))
	}
}
