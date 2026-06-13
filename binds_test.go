package demesne

import (
	"strings"
	"testing"
)

// The owner and admin planes are bound EXPLICITLY (EID-265 WS2 `binds owner|admin`),
// not inferred from subject shape. The binding decides which claim the owner axis
// and the role definers resolve against — even when the claim keys are unusual and
// no shape heuristic could disambiguate.
const bindsSpec = `
topology { level tenant level project parent tenant }
vocabulary adminv { permission a:b  preset p @ project = a:b }
vocabulary custv  { permission self:read }
rolestore adminv {
  assignments ra
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject staff { anchor tenant  reach descendants identifies admin_sub  roles configurable adminv binds admin }
subject owner { anchor project reach self        identifies owner_claim roles configurable custv  binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner: owner via owner_col
  relation mgr:   staff via role
  permission view = owner + mgr @rls maps select
}
`

func TestBinds_ExplicitPlaneBindingDrivesClaims(t *testing.T) {
	s, err := Parse(bindsSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := s.ownerSubject("project"); got == nil || got.Name != "owner" {
		t.Fatalf("ownerSubject(project) = %v, want the `binds owner` subject", got)
	}
	if got := s.adminIdentify(); got != "admin_sub" {
		t.Fatalf("adminIdentify() = %q, want the `binds admin` claim", got)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	var sel *Policy
	for i := range rls.Policies {
		if rls.Policies[i].Name == "docs_select" {
			sel = &rls.Policies[i]
		}
	}
	if sel == nil {
		t.Fatal("no docs_select policy")
	}
	// The owner axis resolves the bound owner claim; the role definer the bound
	// admin claim — neither inferred from shape.
	if !strings.Contains(sel.Using, "owner_col = (current_setting('request.jwt.claims', true)::json ->> 'owner_claim')") {
		t.Errorf("owner axis did not use the bound owner claim:\n%s", sel.Using)
	}
	if !strings.Contains(sel.Using, "->> 'admin_sub'") {
		t.Errorf("role definer did not use the bound admin claim:\n%s", sel.Using)
	}
}

// Ambiguity is an error: the binding replaces the former first-match shape pick,
// so two owners at one level (or an unknown binding) must fail closed.
func TestBinds_AmbiguityAndUnknownRejected(t *testing.T) {
	dup := `
topology { level tenant level project parent tenant }
vocabulary v { permission self:read }
subject a { anchor project reach self identifies c1 roles configurable v binds owner }
subject b { anchor project reach self identifies c2 roles configurable v binds owner }
`
	if err := validateSrc(t, dup); err == nil || !strings.Contains(err.Error(), "unambiguous") {
		t.Errorf("two `binds owner` at one level should fail as ambiguous, got: %v", err)
	}
	unknown := `
topology { level tenant }
vocabulary v { permission self:read }
subject a { anchor tenant reach self identifies c roles configurable v binds frobnicate }
`
	if err := validateSrc(t, unknown); err == nil || !strings.Contains(err.Error(), "unknown binding") {
		t.Errorf("unknown binding should be rejected, got: %v", err)
	}
}

func validateSrc(t *testing.T, src string) error {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		return err
	}
	return Validate(s)
}
