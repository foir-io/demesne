package demesne

import (
	"strings"
	"testing"
)

// A disjunct that admits readers the enumeration cannot name makes the object
// enumerate conditionally. @claim is one such term (see claim_term_test.go);
// these are the other two, and they were being dropped in silence long before
// @claim existed.

// condSpec builds a readable object whose read is `body`, with a grant relation
// (what makes an object enumerate at all) and a mode column to test against.
func condSpec(body string) string {
	return `
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
subject operator { anchor tenant reach self identifies operator_id roles configurable v binds admin }
object doc {
  table docs
  scoped tenant
  relation owner:       member via member_id
  relation admin_owner: operator via admin_owner_id
  relation grantee:     member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = ` + body + `
}`
}

func TestConditional_AppScopeOnADisjunctIsNamed(t *testing.T) {
	sp := validSpec(t, condSpec(`@app_scope + owner + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors"]; ok {
		t.Error("docs_accessors must not be emitted: @app_scope admits every caller presenting no subject claim, and the listing names none of them")
	}
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "SELECT 'app_scope'::text, NULL::text, NULL::") {
		t.Errorf("expected an app_scope row naming nobody:\n%s", cond.Body)
	}
	// The app_scope row is the REMAINDER, not a replacement: where a rolestore
	// exists, roleAccessorBranch still names the callers that can be named and
	// stands beside this row. TestPureRecord_EmitsGrantDefinersAndAccessor is
	// the fixture with one, and asserts both appear together.
}

// @app_scope(exclude R) carries a ROW test, so the row it contributes is
// anchored on it and appears only when the row really does admit that way.
func TestConditional_AppScopeExclusionAnchorsTheRow(t *testing.T) {
	sp := validSpec(t, condSpec(`@app_scope(exclude admin_owner) + owner + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "FROM docs WHERE id = p_id AND admin_owner_id IS NULL") {
		t.Errorf("the exclusion is a row test and must anchor the app_scope row:\n%s", cond.Body)
	}
}

func TestConditional_ModeOnADisjunctIsNamedAndRowAnchored(t *testing.T) {
	sp := validSpec(t, condSpec(`owner + mode access_mode = "public" + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors"]; ok {
		t.Error("docs_accessors must not be emitted: a public row is readable by callers the listing names nowhere")
	}
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	// Anchored, so a private row's listing carries no mode row at all — which
	// is strictly more informative than a flag beside the function.
	if !strings.Contains(cond.Body, "SELECT 'mode'::text, NULL::text, NULL::") ||
		!strings.Contains(cond.Body, "FROM docs WHERE id = p_id AND access_mode = 'public'") {
		t.Errorf("expected a row-anchored mode row:\n%s", cond.Body)
	}
}

// `for <subject>` narrows the mode to one plane, so the kind IS known and only
// the id is not.
func TestConditional_ModeForASubjectNamesTheKind(t *testing.T) {
	sp := validSpec(t, condSpec(`owner + mode access_mode = "public" for operator + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "SELECT 'mode'::text, 'operator'::text, NULL::") {
		t.Errorf("`for operator` must fill principal_kind — only the id is unknowable:\n%s", cond.Body)
	}
}

// The other direction, and the reason the rule is about position rather than
// about which terms are "special": on a conjunct a mode narrows, so dropping it
// over-reports and the plain enumerator stays sound and stays emitted.
func TestConditional_ModeOnAConjunctLeavesTheEnumeratorPlain(t *testing.T) {
	sp := validSpec(t, condSpec(`(owner + grantee:read) and mode access_mode = "public"   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors_conditional"]; ok {
		t.Error("a narrowing mode must not force the conditional form: dropping it over-reports, which is the safe direction")
	}
	if _, ok := fns["docs_accessors"]; !ok {
		t.Fatalf("expected docs_accessors, have: %s", have)
	}
}

// An object with nothing but relational disjuncts keeps the plain enumerator
// and the four columns. This is the control: without it, a bug that made every
// object conditional would pass every other test in this file.
func TestConditional_RelationalDisjunctsOnlyStayPlain(t *testing.T) {
	sp := validSpec(t, condSpec(`owner + admin_owner + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	plain, ok := fns["docs_accessors"]
	if !ok {
		t.Fatalf("expected docs_accessors, have: %s", have)
	}
	if strings.Contains(plain.Returns, "via_claim_key") {
		t.Errorf("a plain enumerator keeps its four columns: %s", plain.Returns)
	}
	if _, ok := fns["docs_accessors_conditional"]; ok {
		t.Error("nothing here admits a reader the enumeration cannot name")
	}
}

// TTS-970's shape: a mode disjunct used to make the whole tree un-enumerable
// the moment any `and` appeared, because the tree path REFUSED the mode leaf
// rather than skipping it. Now the mode becomes a conditional row and the
// conjunction enumerates from its relational term.
func TestConditional_ModeDisjunctNoLongerBlocksAConjunctionElsewhere(t *testing.T) {
	sp := validSpec(t, condSpec(`admin_owner + owner + mode access_mode = "public" + (@kind("operator") and grantee:read)   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "'grant'::text") {
		t.Errorf("the @kind-gated grant branch must still enumerate:\n%s", cond.Body)
	}
	if !strings.Contains(cond.Body, "SELECT 'mode'::text") {
		t.Errorf("the mode disjunct must appear as its own row:\n%s", cond.Body)
	}
}
