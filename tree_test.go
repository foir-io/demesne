package demesne

import (
	"strings"
	"testing"
)

const treeSpec = `
topology {
  level org
  level team   parent org
  level client parent org
}
vocabulary v { permission self:read }
subject tmember { anchor team   reach self identifies tmem_id roles configurable v binds owner }
subject cmember { anchor client reach self identifies cmem_id roles configurable v binds owner }
object doc {
  table  docs
  scoped org > team
  relation owner: tmember via owner_id
  permission view = owner @rls maps select
}
object invoice {
  table  invoices
  scoped org > client
  relation owner: cmember via owner_id
  permission view = owner @rls maps select
}
`

func TestTree_BranchingForkCompiles(t *testing.T) {
	s, err := Parse(treeSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate (a branching tree must be valid): %v", err)
	}

	if p, _ := s.Topology.AncestorPath("team"); len(p) != 2 || p[0].Name != "org" || p[1].Name != "team" {
		t.Errorf("AncestorPath(team) = %v, want [org team]", names(p))
	}
	if p, _ := s.Topology.AncestorPath("client"); len(p) != 2 || p[1].Name != "client" {
		t.Errorf("AncestorPath(client) = %v, want [org client]", names(p))
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	doc := findPolicy(rls, "docs_select")
	inv := findPolicy(rls, "invoices_select")
	if doc == nil || inv == nil {
		t.Fatalf("missing policies (unsupported: %v)", rls.Unsupported)
	}

	for _, want := range []string{"org_id = ", "team_id = ", "owner_id = "} {
		if !strings.Contains(doc.Using, want) {
			t.Errorf("docs_select missing %q (team branch):\n%s", want, doc.Using)
		}
	}
	if strings.Contains(doc.Using, "client_id") {
		t.Errorf("docs_select leaked the sibling-branch client_id:\n%s", doc.Using)
	}
	for _, want := range []string{"org_id = ", "client_id = "} {
		if !strings.Contains(inv.Using, want) {
			t.Errorf("invoices_select missing %q (client branch):\n%s", want, inv.Using)
		}
	}
	if strings.Contains(inv.Using, "team_id") {
		t.Errorf("invoices_select leaked the sibling-branch team_id:\n%s", inv.Using)
	}
}

func TestTree_ClaimsCoverAllBranches(t *testing.T) {
	s := mustSpec(t, treeSpec)
	claims, err := s.ClaimsContract()
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	for _, want := range []string{"org_id", "team_id", "client_id"} {
		if !contains(claims, want) {
			t.Errorf("claims contract %v missing %q", claims, want)
		}
	}
}

func names(ls []*Level) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.Name
	}
	return out
}
