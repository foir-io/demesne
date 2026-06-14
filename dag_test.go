package demesne

import (
	"strings"
	"testing"
)

// WS3 Phase B — a level may have MULTIPLE parents (a DAG): `item` is filed under
// a team OR a folder, both under org. An object at a multi-parent leaf pins its
// ancestor columns along EACH lineage, OR'd together — column-backed and
// sargable, never a single chain that would force one container.
const dagSpec = `
topology {
  level org
  level team   parent org
  level folder parent org
  level item   parents team, folder
}
object widget {
  table  widgets
  scoped org > team > folder > item
  permission view = @scoped @rls maps select
}
`

func TestDAG_MultiParentContainmentIsOrOfPaths(t *testing.T) {
	s, err := Parse(dagSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate (a multi-parent DAG must be valid): %v", err)
	}

	paths, err := s.Topology.AncestorPaths("item")
	if err != nil {
		t.Fatalf("AncestorPaths(item): %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("item should have 2 ancestor paths (via team, via folder), got %d", len(paths))
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	p := findPolicy(rls, "widgets_select")
	if p == nil {
		t.Fatalf("no widgets_select (unsupported: %v)", rls.Unsupported)
	}
	team := "(org_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id') AND team_id = (current_setting('request.jwt.claims', true)::json ->> 'team_id') AND item_id = (current_setting('request.jwt.claims', true)::json ->> 'item_id'))"
	folder := "(org_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id') AND folder_id = (current_setting('request.jwt.claims', true)::json ->> 'folder_id') AND item_id = (current_setting('request.jwt.claims', true)::json ->> 'item_id'))"
	if !strings.Contains(p.Using, team) {
		t.Errorf("widgets_select missing the team-lineage branch:\n%s", p.Using)
	}
	if !strings.Contains(p.Using, folder) {
		t.Errorf("widgets_select missing the folder-lineage branch:\n%s", p.Using)
	}
	if !strings.Contains(p.Using, team+" OR "+folder) && !strings.Contains(p.Using, folder+" OR "+team) {
		t.Errorf("the two lineages must be OR'd as separate sargable branches:\n%s", p.Using)
	}
	// Neither lineage conflates the sibling container's column inside one AND-group.
	for _, branch := range []string{team, folder} {
		bad := strings.Contains(branch, "team_id") && strings.Contains(branch, "folder_id")
		if bad {
			t.Errorf("a single containment branch mixes both sibling columns:\n%s", branch)
		}
	}
}

// The Phase B bound: multi-parent is for OBJECT containment. A SUBJECT may not
// anchor at a multi-parent level (its pinned columns would be ambiguous) — it
// must fail closed rather than silently pick a lineage.
func TestDAG_SubjectAtMultiParentRejected(t *testing.T) {
	src := dagSpec + `
vocabulary v { permission self:read }
subject s { anchor item reach self identifies sid roles configurable v binds owner }
`
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "multi-parent") {
		t.Errorf("a subject anchored at a multi-parent level should fail closed, got: %v", err)
	}
}
