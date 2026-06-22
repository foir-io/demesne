package demesne

import (
	"strings"
	"testing"
)

const groupSpec = `
topology { level tenant level project parent tenant }
vocabulary v { permission self:read }
subject member { anchor project reach self identifies uid roles configurable v binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation viewer: member via group group_closure(grp, mem) edge group_members(member_id, group_id) on viewer_group
  permission view = viewer @rls maps select
}
`

func TestGroup_NestedMembership(t *testing.T) {
	s, err := Parse(groupSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var rel *Relation
	for _, r := range s.Objects[0].Relations {
		if r.Name == "viewer" {
			rel = r
		}
	}
	if rel == nil || rel.CostClass() != Closure {
		t.Fatalf("viewer cost class = %v, want closure", rel.CostClass())
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sel := findPolicy(rls, "docs_select")
	if sel == nil {
		t.Fatalf("no docs_select (unsupported: %v)", rls.Unsupported)
	}
	want := "auth.group_closure_member(viewer_group, (current_setting('request.jwt.claims', true)::json ->> 'uid'))"
	if !strings.Contains(sel.Using, want) {
		t.Errorf("docs_select missing the membership lookup:\n%s", sel.Using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	var mem *GenFn
	for i := range defs {
		if defs[i].Name == "group_closure_member" {
			mem = &defs[i]
		}
	}
	if mem == nil {
		t.Fatal("no group_closure_member definer")
	}
	if mem.Body != "EXISTS (SELECT 1 FROM group_closure WHERE grp = p_group AND mem = p_member)" {
		t.Errorf("membership body = %q", mem.Body)
	}

	gts := s.EmitGroupTriggers()
	if len(gts) != 1 || gts[0].Closure != "group_closure" || gts[0].Edge != "group_members" {
		t.Fatalf("EmitGroupTriggers = %+v", gts)
	}
	fn := gts[0].FunctionSQL()
	for _, frag := range []string{
		"CREATE OR REPLACE FUNCTION auth.group_closure_rebuild()",
		"SECURITY DEFINER",

		"DELETE FROM group_closure;",
		"WITH RECURSIVE tc AS (",
		"SELECT group_id AS grp, member_id AS mem FROM group_members",
		"SELECT tc.grp, e.member_id FROM tc JOIN group_members e ON e.group_id = tc.mem",
	} {
		if !strings.Contains(fn, frag) {
			t.Errorf("rebuild fn missing %q:\n%s", frag, fn)
		}
	}
	if !strings.Contains(gts[0].TriggerSQL(), "AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.group_members FOR EACH STATEMENT") {
		t.Errorf("trigger not statement-level (with TRUNCATE) on the edge:\n%s", gts[0].TriggerSQL())
	}
	if !strings.Contains(s.TriggersSQL(), "via group") {
		t.Error("TriggersSQL COST banner does not mention via group")
	}
}
