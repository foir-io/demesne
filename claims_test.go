package demesne

import (
	"strings"
	"testing"
)

// The claims accessor is spec-declared: a non-Foir deployment can read claims
// from a different GUC / cast without the engine assuming request.jwt.claims+json.
const claimsSpec = `
claims via "app.context" jsonb
topology {
  level tenant
  level project parent tenant
}
vocabulary member { permission self:read }
subject member { anchor project; reach self; identifies customer_id; roles configurable member }
object thing {
  table  things
  scoped tenant > project
  relation owner: member via customer_id
  permission view = owner @rls maps select
}
`

func TestClaims_AccessorIsSpecDeclared(t *testing.T) {
	s, err := Parse(claimsSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Claims == nil || s.Claims.Setting != "app.context" || s.Claims.Cast != "jsonb" {
		t.Fatalf("claims not parsed: %+v", s.Claims)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	var sel *Policy
	for i := range rls.Policies {
		if rls.Policies[i].Name == "things_select" {
			sel = &rls.Policies[i]
		}
	}
	if sel == nil {
		t.Fatal("no things_select policy")
	}
	if !strings.Contains(sel.Using, "current_setting('app.context', true)::jsonb ->> 'customer_id'") {
		t.Errorf("policy did not use the declared accessor:\n%s", sel.Using)
	}
	if strings.Contains(sel.Using, "request.jwt.claims") {
		t.Errorf("policy still hard-codes the Foir GUC:\n%s", sel.Using)
	}
}

// Omitting the block keeps Foir's exact JSON-GUC form (byte-identical default).
func TestClaims_DefaultIsForirJSONGUC(t *testing.T) {
	s := &Spec{}
	if got := s.claim("sub"); got != "(current_setting('request.jwt.claims', true)::json ->> 'sub')" {
		t.Errorf("default claim accessor = %q", got)
	}
}
