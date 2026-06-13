package demesne

import (
	"strings"
	"testing"
)

// The SECURITY DEFINER kernel schema is spec-declared: a non-Foir deployment can
// host the generated trusted functions in its own schema without the engine
// assuming "auth". `definers schema "authz"` must flip every qualification —
// policy call sites, generated CREATE statements, and the V11 closure check —
// in lockstep, so the closure still holds.
func TestDefinerSchema_IsSpecDeclared(t *testing.T) {
	spec := `definers schema "authz"` + "\n" + grantSpec
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.DefinerSchema != "authz" {
		t.Fatalf("definer schema not parsed: %q", s.DefinerSchema)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate (closure must hold under the declared schema): %v", err)
	}

	// (1) Generated definers are created in the declared schema.
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var ta GenFn
	for _, d := range defs {
		if d.schema() != "authz" {
			t.Errorf("definer %q schema = %q, want authz", d.Name, d.schema())
		}
		if d.Name == "is_tenant_admin" {
			ta = d
		}
	}
	if !strings.HasPrefix(ta.CreateSQL(), "CREATE OR REPLACE FUNCTION authz.is_tenant_admin(") {
		t.Errorf("CreateSQL not qualified with declared schema:\n%s", ta.CreateSQL())
	}
	// The intra-kernel recursion call is qualified with the declared schema too.
	if !strings.Contains(ta.Body, "authz.impersonation_grants_reach(") {
		t.Errorf("recursion call not requalified:\n%s", ta.Body)
	}
	if strings.Contains(ta.Body, "auth.") {
		t.Errorf("definer body still references the default auth schema:\n%s", ta.Body)
	}

	// (2) Emitted policies call the kernel in the declared schema, never "auth.".
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range rls.Policies {
		for _, pred := range []string{p.Using, p.Check} {
			if strings.Contains(pred, "auth.") {
				t.Errorf("policy %s still calls the default auth schema:\n%s", p.Name, pred)
			}
		}
	}
	var recSelect *Policy
	for i := range rls.Policies {
		if rls.Policies[i].Name == "records_select" {
			recSelect = &rls.Policies[i]
		}
	}
	if recSelect == nil {
		t.Fatal("no records_select policy emitted")
	}
	if !strings.Contains(recSelect.Using, "authz.impersonation_grants_reach(") {
		t.Errorf("records_select must call the grant reach in the declared schema:\n%s", recSelect.Using)
	}
}

// Omitting the block keeps Foir's exact "auth" schema (byte-identical default).
func TestDefinerSchema_DefaultIsAuth(t *testing.T) {
	if (&Spec{}).definerSchema() != "auth" {
		t.Errorf("default definer schema = %q, want auth", (&Spec{}).definerSchema())
	}
	if (GenFn{}).schema() != "auth" {
		t.Errorf("default GenFn schema = %q, want auth", (GenFn{}).schema())
	}
}
