package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonical_FolderDocumentInheritance(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("examples", "canonical", "inheritance.demesne"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s, err := Parse(string(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var rel *Relation
	for _, r := range s.Objects[0].Relations {
		if r.Name == "in_folder" {
			rel = r
		}
	}
	if rel == nil {
		t.Fatal("missing in_folder relation")
	}
	if rel.CostClass() != Closure {
		t.Fatalf("in_folder cost class = %v, want closure", rel.CostClass())
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sel := findPolicy(rls, "documents_select")
	if sel == nil {
		t.Fatalf("no documents_select (unsupported: %v)", rls.Unsupported)
	}
	viewerFolder := "(current_setting('request.jwt.claims', true)::json ->> 'viewer_folder')"
	reach := "auth.folder_closure_reachable(" + viewerFolder + ", folder_id)"
	if !strings.Contains(sel.Using, reach) {
		t.Errorf("documents_select does not reach through the folder ancestry:\n%s", sel.Using)
	}
	for _, frag := range []string{
		"org_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id')",
		"workspace_id = (current_setting('request.jwt.claims', true)::json ->> 'workspace_id')",
	} {
		if !strings.Contains(sel.Using, frag) {
			t.Errorf("documents_select missing tenancy containment %q in:\n%s", frag, sel.Using)
		}
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var reachDef *GenFn
	for i := range defs {
		if defs[i].Name == "folder_closure_reachable" {
			reachDef = &defs[i]
		}
	}
	if reachDef == nil {
		t.Fatal("no folder_closure_reachable definer generated")
	}
	if reachDef.Body != "EXISTS (SELECT 1 FROM folder_closure WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant)" {
		t.Errorf("reachability body = %q", reachDef.Body)
	}
	if !strings.Contains(reachDef.CreateSQL(), "SECURITY DEFINER") {
		t.Error("reachability lookup is not SECURITY DEFINER")
	}

	trigs := s.EmitTriggers()
	if len(trigs) != 1 || trigs[0].Closure != "folder_closure" || trigs[0].Base != "folders" {
		t.Fatalf("EmitTriggers = %+v, want one for folder_closure on folders", trigs)
	}
	fn := trigs[0].FunctionSQL()
	for _, frag := range []string{
		"VALUES (NEW.id, NEW.id)",
		"WHERE c.descendant_id = NEW.parent_id",
		"NEW.parent_id IS DISTINCT FROM OLD.parent_id",
	} {
		if !strings.Contains(fn, frag) {
			t.Errorf("closure maintenance missing the unbounded-ancestry fragment %q:\n%s", frag, fn)
		}
	}
}
