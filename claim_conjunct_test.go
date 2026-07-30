package demesne

import (
	"strings"
	"testing"
)

const claimConjunctSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via owner_id where owner_kind = "customer"
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view = owner + (@kind("admin") and grantee:read) @rls maps select
}
`

func TestClaimConjunct_ComposesInsideAccessorTree(t *testing.T) {
	s := mustSpec(t, claimConjunctSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("(@kind(...) and grantee:read) must validate — the claim conjunct is neutral in reverse: %v", err)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var acc *GenFn
	for i := range defs {
		if defs[i].Name == "docs_accessors" {
			acc = &defs[i]
		}
	}
	if acc == nil {
		t.Fatal("no docs_accessors definer generated")
	}
	for _, want := range []string{"'grant'::text", "FROM dacl", "resource_type = 'doc'", "owner_id"} {
		if !strings.Contains(acc.Body, want) {
			t.Errorf("docs_accessors must enumerate the grant and owner branches, missing %q:\n%s", want, acc.Body)
		}
	}
	if strings.Contains(acc.Body, "IN (SELECT b.") {
		t.Errorf("the claim conjunct must be dropped in reverse, not intersected:\n%s", acc.Body)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sel := findPolicy(rls, "docs_select")
	if sel == nil {
		t.Fatalf("no docs_select policy (unsupported: %v)", rls.Unsupported)
	}
	kindFrag := "(current_setting('request.jwt.claims', true)::json ->> 'kind') = 'admin'"
	if !strings.Contains(sel.Using, "("+kindFrag+") AND (") {
		t.Errorf("the forward RLS must still AND the @kind conjunct onto the grant branch:\n%s", sel.Using)
	}
	if !strings.Contains(sel.Using, "'read'") {
		t.Errorf("the grant branch lost its access class:\n%s", sel.Using)
	}
}

func TestClaimConjunct_OnlyClaimTermsFailClosed(t *testing.T) {
	bad := strings.Replace(claimConjunctSpec,
		"permission view = owner + (@kind(\"admin\") and grantee:read) @rls maps select",
		"permission view = owner + (@kind(\"admin\") and @scoped) @rls maps select", 1)
	s := mustSpec(t, bad)
	err := Validate(s)
	if err == nil {
		t.Fatal("a conjunction with no relational positive must fail closed")
	}
	for _, want := range []string{"claim-side", "@kind"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should name the dropped builtins (%q), got:\n%v", want, err)
		}
	}
}
