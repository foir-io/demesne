package demesne

import (
	"strings"
	"testing"
)

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

	if !strings.Contains(by["docs_select"], "(owner_id = "+c+") AND (shared_with = "+c+")") {
		t.Errorf("intersection not emitted:\n%s", by["docs_select"])
	}

	if !strings.Contains(by["docs_update"], "(owner_id = "+c+") AND ((banned_id = "+c+") IS NOT TRUE)") {
		t.Errorf("exclusion not emitted correctly:\n%s", by["docs_update"])
	}

	if !strings.Contains(by["docs_delete"], "(owner_id = "+c+" OR shared_with = "+c+") AND ((banned_id = "+c+") IS NOT TRUE)") {
		t.Errorf("precedence/grouping wrong:\n%s", by["docs_delete"])
	}
}

func TestBoolean_PolarityFailsClosed(t *testing.T) {
	head := `topology { level a }
		vocabulary v { permission self:read }
		subject s { anchor a reach self identifies sub roles configurable v binds owner }
		object o { table t scoped a relation x: s via xc relation y: s via yc `
	for _, bad := range []string{
		"permission view = not x @rls maps select }",
		"permission view = x or not y @rls maps select }",
	} {
		spec, err := Parse(head + bad)
		if err != nil {
			t.Fatalf("parse %q: %v", bad, err)
		}
		if err := Validate(spec); err == nil || !strings.Contains(err.Error(), "positively gated") {
			t.Errorf("%q should be rejected as not positively gated, got: %v", bad, err)
		}
	}

	ok, err := Parse(head + "permission view = x and not y @rls maps select }")
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(ok); err != nil {
		t.Errorf("`x and not y` should be accepted: %v", err)
	}
}

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
