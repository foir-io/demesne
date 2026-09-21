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

// @app_scope(exclude a, b) subtracts MORE THAN ONE owner plane.
//
// A table can be owned on more than one plane — an admin-owned row and a
// customer-owned row are both somebody's private data — and a trusted caller
// presenting no subject of its own has no business reading either. One
// exclusion could only ever name one of them, which is why the adopter that
// needed both had to filter the second in application code.
func TestConditional_AppScopeExcludesEveryNamedPlane(t *testing.T) {
	sp := validSpec(t, condSpec(`@app_scope(exclude admin_owner, owner) + owner + grantee:read   @rls maps select`))

	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	var using string
	for _, p := range res.Policies {
		if strings.Contains(p.Name, "docs_select") {
			using = p.Using
		}
	}
	for _, want := range []string{"admin_owner_id IS NULL", "member_id IS NULL"} {
		if !strings.Contains(using, want) {
			t.Errorf("the plane must subtract %s:\n%s", want, using)
		}
	}

	// And the conditional row is anchored on BOTH, so it appears only where the
	// plane really admits. Anchoring on the first alone would put a row in the
	// listing for a row the plane does not admit at all.
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "admin_owner_id IS NULL AND member_id IS NULL") {
		t.Errorf("the app_scope row must be anchored on every exclusion:\n%s", cond.Body)
	}
}

// A conjunction of ONLY conditional terms is one admission that names nobody,
// not a refusal.
//
// v0.85.0 handled a conditional term standing alone on a disjunct and left this
// case to accessorAndSQL, which looks for a relational term to enumerate from,
// finds none, and refuses. The refusal was wrong: the conjunction admits
// readers perfectly well, it simply names no subject — which is the case the
// conditional enumerator exists for.
//
// Both shapes here are real adopter needs. The first confines a plane to one
// caller kind; the second subtracts a credential from it.
func TestConditional_ConjunctionOfOnlyConditionalTermsIsOneAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantSource, wantAnchor string
	}{
		{
			name:       "plane narrowed to a caller kind",
			body:       `(@app_scope(exclude admin_owner) and @kind("service")) + owner + grantee:read   @rls maps select`,
			wantSource: "'app_scope'::text",
			wantAnchor: "FROM docs WHERE id = p_id AND admin_owner_id IS NULL",
		},
		{
			name:       "plane with a credential subtracted",
			body:       `(@app_scope(exclude admin_owner) and not @claim("credential", "public")) + owner + grantee:read   @rls maps select`,
			wantSource: "'app_scope'::text",
			wantAnchor: "FROM docs WHERE id = p_id AND admin_owner_id IS NULL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := validSpec(t, condSpec(tc.body))
			fns, have := claimDefiners(t, sp)
			cond, ok := fns["docs_accessors_conditional"]
			if !ok {
				t.Fatalf("expected docs_accessors_conditional, have: %s", have)
			}
			if !strings.Contains(cond.Body, tc.wantSource) {
				t.Errorf("the admitting term must name the row's source:\n%s", cond.Body)
			}
			// The row-side half of the conjunction still anchors it; the
			// request-side half is what makes the row conditional at all.
			if !strings.Contains(cond.Body, tc.wantAnchor) {
				t.Errorf("expected the anchor %q:\n%s", tc.wantAnchor, cond.Body)
			}
			// The relational disjuncts are untouched — folding the conjunction
			// must not swallow the branches that CAN be enumerated.
			for _, want := range []string{"'owner'::text", "'grant'::text"} {
				if !strings.Contains(cond.Body, want) {
					t.Errorf("folding the conjunction dropped the %s branch:\n%s", want, cond.Body)
				}
			}
		})
	}
}

// The control: a conjunction containing a RELATIONAL term is enumerable and
// must NOT be folded into a nameless row. Without this, the fold above could
// swallow every conjunction in the spec and the listing would name nobody.
func TestConditional_ConjunctionWithARelationalTermStaysEnumerated(t *testing.T) {
	// The conjunction must carry BOTH a relational term and an ADMITTING
	// conditional one. An earlier version paired the relation with @kind, which
	// admits nothing on its own, so the fold never triggered and the test passed
	// whether or not the guard was there — a mutation removing the guard went
	// unkilled. @app_scope admits, so removing the guard now folds this
	// conjunction and loses the grantee branch, which is the defect.
	sp := validSpec(t, condSpec(`(grantee:read and @app_scope(exclude admin_owner)) + owner   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	if _, ok := fns["docs_accessors_conditional"]; ok {
		t.Error("a conjunction with a relational term is enumerable — folding it into a " +
			"nameless row would lose the grantees it can actually name")
	}
	if _, ok := fns["docs_accessors"]; !ok {
		t.Fatalf("expected docs_accessors, have: %s", have)
	}
}
