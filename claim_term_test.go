package demesne

import (
	"strings"
	"testing"
)

// A claim is the one permission term that names a CONDITION on the request
// rather than a subject, so these tests are mostly about what that costs the
// reverse direction: an accessor enumeration reads subjects back off a row, and
// there is no row anywhere recording who satisfies a condition.

// claimSpec builds a readable object whose read is `body`. It carries a grant
// relation because that is what makes an object enumerate accessors at all.
func claimSpec(body string) string {
	return `
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
object doc {
  table docs
  scoped tenant
  relation owner:   member via member_id
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = ` + body + `
}`
}

func validSpec(t *testing.T, src string) *Spec {
	t.Helper()
	sp := mustSpec(t, src)
	if err := Validate(sp); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return sp
}

func claimDefiners(t *testing.T, sp *Spec) (map[string]GenFn, string) {
	t.Helper()
	fns, err := sp.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	byName := map[string]GenFn{}
	for _, f := range fns {
		byName[f.Name] = f
	}
	return byName, definerNames(fns)
}

func TestClaim_ReachesTheRowPredicate(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + @claim("list_all", "true")   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if !strings.Contains(p.Name, "docs_select") {
			continue
		}
		if !strings.Contains(p.Using, "'list_all'") || !strings.Contains(p.Using, "= 'true'") {
			t.Fatalf("the claim test did not reach the row predicate: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestClaim_RefusesAnEmptyKeyOrValue(t *testing.T) {
	for _, body := range []string{
		`owner + @claim("", "true")   @rls maps select`,
		`owner + @claim("list_all", "")   @rls maps select`,
	} {
		sp, err := Parse(claimSpec(body))
		if err != nil {
			t.Fatalf("parse %q: %v", body, err)
		}
		err = Validate(sp)
		if err == nil {
			t.Fatalf("%q: an empty key or value must be refused", body)
		}
		if !strings.Contains(err.Error(), "empty key or value") {
			t.Errorf("%q: refusal should say what is empty, got: %v", body, err)
		}
	}
}

// A claim is read from the request at the ROW layer. A permission that does not
// compile to a policy has no row layer to read it in, so the decision point
// would silently ignore the term.
func TestClaim_RefusesAPermissionThatIsNotRLS(t *testing.T) {
	sp, err := Parse(`
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
object doc {
  table docs
  scoped tenant
  relation owner: member via member_id
  permission view   = owner                                @rls maps select
  permission manage = owner + @claim("list_all", "true")   @pdp
}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(sp)
	if err == nil {
		t.Fatal("a non-@rls permission carrying a claim must be refused")
	}
	if !strings.Contains(err.Error(), "@rls") {
		t.Errorf("refusal should name @rls, got: %v", err)
	}
}

// THE POINT OF THE CONSTRUCT. On a disjunct the claim ADMITS readers no other
// branch admits, so an enumeration that leaves it out is not a shorter answer
// but a wrong one. The object loses its plain enumerator and gains a conditional
// one, so a caller that has not been updated asks for a function that is not
// there instead of being handed a confident, incomplete list.
func TestClaim_OnADisjunctMakesTheEnumeratorConditional(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + grantee:read + @claim("list_all", "true")   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors"]; ok {
		t.Error("docs_accessors must NOT be emitted: it would list the owner and the grantees and silently omit every reader the claim admits")
	}
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	for _, col := range []string{"via_claim_key text", "via_claim_value text"} {
		if !strings.Contains(cond.Returns, col) {
			t.Errorf("conditional enumerator must return %s, got %s", col, cond.Returns)
		}
	}
	// The claim row names nobody, and says which claim that is.
	if !strings.Contains(cond.Body, "'claim'::text, NULL::text, NULL::") {
		t.Errorf("the claim row must carry a NULL principal, not a sentinel that renders as a person:\n%s", cond.Body)
	}
	if !strings.Contains(cond.Body, "'list_all'::text, 'true'::text") {
		t.Errorf("the claim row must name the claim that admits the reader:\n%s", cond.Body)
	}
	// The identity half survives intact.
	for _, want := range []string{"'owner'::text", "'grant'::text"} {
		if !strings.Contains(cond.Body, want) {
			t.Errorf("conditional enumerator dropped the %s branch:\n%s", want, cond.Body)
		}
	}
	// An id naming no row still enumerates to nothing, as the plain one did.
	if !strings.Contains(cond.Body, "FROM docs WHERE id = p_id") {
		t.Errorf("the claim row must be anchored to the row, so a missing id lists nothing:\n%s", cond.Body)
	}
}

// The mirror image, and the reason the direction is the whole argument. On a
// conjunct the claim NARROWS: dropping it can only add names to the listing,
// never remove one, so the plain enumerator stays sound and stays emitted.
func TestClaim_OnAConjunctLeavesTheEnumeratorPlain(t *testing.T) {
	sp := validSpec(t, claimSpec(`(owner + grantee:read) and @claim("list_all", "true")   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors_conditional"]; ok {
		t.Error("a narrowing claim must not force the conditional form: dropping it over-reports, which is the safe direction")
	}
	plain, ok := fns["docs_accessors"]
	if !ok {
		t.Fatalf("expected docs_accessors, have: %s", have)
	}
	if strings.Contains(plain.Body, "list_all") {
		t.Errorf("a narrowing claim is enforced by the policy, not the enumeration:\n%s", plain.Body)
	}
}

// A borrow compiles to a call to the other object's plain enumerator. An object
// that enumerates conditionally has none, and its conditional one answers a
// different question, so the borrow is refused rather than quietly taking the
// identity half and losing the rest.
func TestClaim_BorrowingAConditionalObjectIsRefused(t *testing.T) {
	src := `
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
object doc {
  table docs
  scoped tenant
  relation owner:   member via member_id
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = owner + grantee:read + @claim("list_all", "true")   @rls maps select
}
object comment {
  table comments
  scoped tenant
  relation parent:  doc via object doc->view on doc_id
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "comment" tracked
  permission view = parent + grantee:read   @rls maps select
}`
	sp, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// V11 closes the definer set at validation, so the adopter meets this when
	// they write the spec rather than when something queries the function.
	err = Validate(sp)
	if err == nil {
		t.Fatal("borrowing an object that enumerates conditionally must be refused")
	}
	if !strings.Contains(err.Error(), "list_all") {
		t.Errorf("refusal should name the claim responsible, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no plain accessor to borrow") {
		t.Errorf("refusal should say why the borrow cannot stand, got: %v", err)
	}
}

// An admit arm shares the permission parser, so a claim composes there too. It
// must NOT make the object conditional: an admit arm is documented as outside
// the accessor listing (the listing names people, not the tokens an arm
// admits), so the listing was never claiming to cover it.
func TestClaim_InAnAdmitArmLeavesTheEnumeratorAlone(t *testing.T) {
	sp := validSpec(t, `
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
object doc {
  table docs
  scoped tenant
  relation owner:   member via member_id
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = owner + grantee:read   @rls maps select
  admit select = @kind("robot") and @claim("robot_read_all", "true")
}`)
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
	if !strings.Contains(using, "'robot_read_all') = 'true'") {
		t.Errorf("the admit arm's claim must reach the policy: %s", using)
	}

	fns, have := claimDefiners(t, sp)
	if _, ok := fns["docs_accessors"]; !ok {
		t.Errorf("an admit arm does not change what the listing claims to cover, so the plain enumerator stays; have: %s", have)
	}
	if _, ok := fns["docs_accessors_conditional"]; ok {
		t.Error("an admit arm must not force the conditional form")
	}
}

func TestClaim_ResourceAccessSurfaceRefusesTheConditionalObject(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + grantee:read + @claim("list_all", "true")   @rls maps select`))

	if _, err := sp.ResourceAccessSurface("doc"); err == nil {
		t.Error("ResourceAccessSurface must refuse an object whose read admits a claim")
	}
	r, err := sp.ConditionalResourceAccessSurface("doc")
	if err != nil {
		t.Fatalf("ConditionalResourceAccessSurface: %v", err)
	}
	if !r.IsConditional() {
		t.Error("the surface should report itself conditional")
	}
	sql := r.AccessorsSQL()
	if !strings.Contains(sql, "via_claim_key") || !strings.Contains(sql, "_accessors_conditional") {
		t.Errorf("a conditional surface must select the claim columns from the conditional function, got: %s", sql)
	}
}

func TestClaim_PlainObjectKeepsThePlainSurface(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + grantee:read   @rls maps select`))
	r, err := sp.ResourceAccessSurface("doc")
	if err != nil {
		t.Fatalf("an object with no claim must still have a plain surface: %v", err)
	}
	if r.IsConditional() {
		t.Error("an object with no claim is not conditional")
	}
	if strings.Contains(r.AccessorsSQL(), "via_claim") {
		t.Errorf("a plain surface must keep its four columns, got: %s", r.AccessorsSQL())
	}
}
