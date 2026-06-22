package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadCanonicalGroups(t *testing.T) *Spec {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "canonical", "groups.demesne"))
	if err != nil {
		t.Fatalf("read groups example: %v", err)
	}
	s, err := Parse(string(src))
	if err != nil {
		t.Fatalf("parse groups example: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate groups example: %v", err)
	}
	return s
}

func TestCanonicalGroups_NestedMembership(t *testing.T) {
	s := loadCanonicalGroups(t)

	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	doc := findPolicy(res, "docs_select")
	if doc == nil {
		t.Fatalf("no docs_select policy (unsupported: %v)", res.Unsupported)
	}

	memberClaim := s.claim("member_id")
	groupTerm := "auth.group_closure_member(audience_group, " + memberClaim + ")"
	if !strings.Contains(doc.Using, groupTerm) {
		t.Errorf("docs_select does not consult the group closure; want %q in:\n%s", groupTerm, doc.Using)
	}

	if !strings.Contains(doc.Using, "owner_id = "+memberClaim+" OR ") {
		t.Errorf("docs_select missing the owner-OR-group union in:\n%s", doc.Using)
	}

	if !strings.Contains(doc.Using, "tenant_id = "+s.claim("tenant_id")+" AND workspace_id = "+s.claim("workspace_id")) {
		t.Errorf("docs_select group grant escaped tenancy containment in:\n%s", doc.Using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var member *GenFn
	for i := range defs {
		if defs[i].Name == "group_closure_member" {
			member = &defs[i]
		}
	}
	if member == nil {
		t.Fatal("no group_closure_member definer emitted")
	}
	if want := "EXISTS (SELECT 1 FROM group_closure WHERE grp = p_group AND mem = p_member)"; !strings.Contains(member.Body, want) {
		t.Errorf("group_closure_member is not an EXISTS over the closure; want %q in:\n%s", want, member.Body)
	}

	trig := s.TriggersSQL()
	for _, want := range []string{
		"WITH RECURSIVE tc AS (",
		"SELECT group_id AS grp, member_id AS mem FROM group_memberships",
		"SELECT tc.grp, e.member_id FROM tc JOIN group_memberships e ON e.group_id = tc.mem",
		"INSERT INTO group_closure (grp, mem)",
	} {
		if !strings.Contains(trig, want) {
			t.Errorf("group closure rebuild missing transitive step %q in:\n%s", want, trig)
		}
	}
}
