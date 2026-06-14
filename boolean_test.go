package demesne

import (
	"strings"
	"testing"
)

// v3 WS1 — the permission algebra is no longer union-only: intersection (`and`),
// exclusion (`and not`), parentheses, and precedence all compile to RLS. A
// union-only spec is unchanged (proven byte-identically by the existing emit
// tests); these prove the new operators.
const boolSpec = `
topology { level tenant level project parent tenant }
vocabulary v { permission self:read }
subject customer { anchor project reach self identifies cust roles configurable v binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:  customer via owner_id
  relation shared: customer via shared_with
  relation banned: customer via banned_id
  permission view = owner and shared            @rls maps select
  permission edit = owner and not banned        @rls maps update
  permission del  = (owner + shared) and not banned  @rls maps delete
}
`

func TestBoolean_IntersectionExclusionPrecedence(t *testing.T) {
	s, err := Parse(boolSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Parse structure: view = AND(owner, shared); edit = AND(owner, NOT banned);
	// del = AND(OR(owner, shared), NOT banned).
	perms := map[string]*Perm{}
	for _, pm := range s.Objects[0].Perms {
		perms[pm.Verb] = pm
	}
	if perms["view"].Tree.Op != "and" || len(perms["view"].Tree.Kids) != 2 {
		t.Errorf("view tree = %+v, want and(2)", perms["view"].Tree)
	}
	if perms["edit"].Tree.Op != "and" || perms["edit"].Tree.Kids[1].Op != "not" {
		t.Errorf("edit tree = %+v, want and(owner, not)", perms["edit"].Tree)
	}
	if perms["del"].Tree.Op != "and" || perms["del"].Tree.Kids[0].Op != "or" {
		t.Errorf("del tree = %+v, want and(or(...), not)", perms["del"].Tree)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	by := map[string]string{}
	for _, p := range rls.Policies {
		by[p.Name] = p.Using + p.Check
	}
	c := "(current_setting('request.jwt.claims', true)::json ->> 'cust')"

	// (1) intersection → AND of both predicates.
	if !strings.Contains(by["docs_select"], "(owner_id = "+c+") AND (shared_with = "+c+")") {
		t.Errorf("intersection not emitted:\n%s", by["docs_select"])
	}
	// (2) exclusion → fail-closed NOT COALESCE (an indeterminate banned denies).
	if !strings.Contains(by["docs_update"], "(owner_id = "+c+") AND (NOT COALESCE(banned_id = "+c+", true))") {
		t.Errorf("exclusion not emitted fail-closed:\n%s", by["docs_update"])
	}
	// (3) precedence: the parenthesised union binds before the exclusion.
	if !strings.Contains(by["docs_delete"], "(owner_id = "+c+" OR shared_with = "+c+") AND (NOT COALESCE(banned_id = "+c+", true))") {
		t.Errorf("precedence/grouping wrong:\n%s", by["docs_delete"])
	}
}

// A union-only permission still produces a flat OR with no extra parens (the
// byte-identity guarantee for existing specs, at the node level).
func TestBoolean_UnionStaysFlat(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		vocabulary v { permission self:read }
		subject customer { anchor project reach self identifies cust roles configurable v binds owner }
		object doc {
		  table docs scoped tenant > project
		  relation owner: customer via owner_id
		  relation shared: customer via shared_with
		  permission view = owner + shared @rls maps select
		}`)
	rls, _ := s.EmitRLS()
	c := "(current_setting('request.jwt.claims', true)::json ->> 'cust')"
	for _, p := range rls.Policies {
		if p.Name == "docs_select" {
			// The block (inside the containment wrapper) is a flat OR — the two
			// owner fragments are not per-leaf parenthesised, and no AND/NOT/COALESCE
			// structure is introduced by a union.
			want := "owner_id = " + c + " OR shared_with = " + c
			if !strings.Contains(p.Using, want) {
				t.Errorf("union not a flat OR:\n%s", p.Using)
			}
			if strings.Contains(p.Using, "COALESCE") {
				t.Errorf("union introduced spurious negation:\n%s", p.Using)
			}
		}
	}
}
