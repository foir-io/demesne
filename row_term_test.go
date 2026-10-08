package demesne

import (
	"strings"
	"testing"
)

func rowPolicy(t *testing.T, sp *Spec, name string) string {
	t.Helper()
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name == name {
			return p.Using
		}
	}
	t.Fatalf("no %s policy emitted", name)
	return ""
}

func TestRow_NarrowsTheTermItStandsBeside(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + (grantee:read and @row(status, "open"))   @rls maps select`))
	using := rowPolicy(t, sp, "docs_select")
	if !strings.Contains(using, "docs.id, 'read')) AND (status = 'open')") {
		t.Fatalf("the row term did not narrow the relation in the policy: %s", using)
	}
}

func TestRow_NegatedAdmitsARowWithNoValue(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + (grantee:read and not @row(status, "sealed"))   @rls maps select`))
	using := rowPolicy(t, sp, "docs_select")
	if !strings.Contains(using, "(status = 'sealed') IS NOT TRUE") {
		t.Fatalf("a negated row term must admit a row whose column is NULL, not refuse it: %s", using)
	}
}

func TestRow_BesideARelationIsDroppedFromTheListing(t *testing.T) {
	for _, body := range []string{
		`owner + (grantee:read and @row(status, "open"))   @rls maps select`,
		`owner + (grantee:read and not @row(status, "sealed"))   @rls maps select`,
	} {
		sp := validSpec(t, claimSpec(body))
		fns, have := claimDefiners(t, sp)
		if _, ok := fns["docs_accessors_conditional"]; ok {
			t.Errorf("%s: a row term names nobody, so it must not force the conditional form", body)
		}
		plain, ok := fns["docs_accessors"]
		if !ok {
			t.Fatalf("%s: expected docs_accessors, have: %s", body, have)
		}
		if strings.Contains(plain.Body, "status") {
			t.Errorf("%s: the row term is enforced by the policy, not reversed into the listing:\n%s", body, plain.Body)
		}
		if !strings.Contains(plain.Body, "resource_acl") {
			t.Errorf("%s: the relation the row term narrowed must still be listed:\n%s", body, plain.Body)
		}
	}
}

func TestRow_BesideAClaimAnchorsTheConditionalRow(t *testing.T) {
	sp := validSpec(t, claimSpec(`owner + grantee:read + (@claim("stands", "project") and @row(status, "open") and not @row(kind, "private"))   @rls maps select`))
	using := rowPolicy(t, sp, "docs_select")
	for _, want := range []string{"'stands') = 'project'", "status = 'open'", "(kind = 'private') IS NOT TRUE"} {
		if !strings.Contains(using, want) {
			t.Errorf("the policy is missing %q: %s", want, using)
		}
	}
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	want := "'stands'::text, 'project'::text\n    FROM docs WHERE id = p_id AND status = 'open' AND (kind = 'private') IS NOT TRUE"
	if !strings.Contains(cond.Body, want) {
		t.Errorf("the claim's row must appear exactly where the conjunction admits:\n%s", cond.Body)
	}
}

func TestRow_IsNotTheObjectsVisibility(t *testing.T) {
	spec := strings.Replace(trackedObjectSpec,
		`permission view = owner + mode access_mode = "public" + grantee:read @rls maps select`,
		`permission view = (grantee:read and not @row(owner_kind, "customer")) + owner + mode access_mode = "public" @rls maps select`, 1)
	sp := validSpec(t, spec)
	var tracked ObjectChangelogTrigger
	for _, tr := range sp.EmitObjectChangelogTriggers() {
		if tr.Table == "docs" {
			tracked = tr
		}
	}
	if tracked.ModeCol != "access_mode" {
		t.Fatalf("the visibility column is %q, want access_mode: a row term tests a column and is not the object's mode", tracked.ModeCol)
	}
	surface, err := sp.ConditionalResourceAccessSurface("doc")
	if err != nil {
		t.Fatalf("resource access: %v", err)
	}
	if surface.ModeCol != "access_mode" {
		t.Errorf("the access surface's mode column is %q, want access_mode", surface.ModeCol)
	}
	if surface.IsReadMode("customer") {
		t.Error("a row term's value was taken for a visibility the object can be set to")
	}
}

func TestRow_RefusesToAdmitByItself(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"a branch of the union", `owner + @row(status, "open")   @rls maps select`},
		{"the only term", `@row(status, "open")   @rls maps select`},
		{"negated, in the union", `owner + not @row(status, "sealed")   @rls maps select`},
		{"beside a negation alone", `owner + (@row(status, "open") and not @claim("credential", "public"))   @rls maps select`},
		{"beside another row term alone", `owner + (@row(status, "open") and not @row(kind, "private"))   @rls maps select`},
		{"under a union inside an and", `owner + (grantee:read and (owner + @row(status, "open")))   @rls maps select`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := Parse(claimSpec(tc.body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(sp)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if !strings.Contains(err.Error(), "only narrows another term") && !strings.Contains(err.Error(), "not positively gated") {
				t.Fatalf("refusal %q does not say a row term only narrows", err.Error())
			}
		})
	}
}

func TestRow_RefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, body, says string }{
		{"no value", `owner + (grantee:read and @row(status, ""))   @rls maps select`, "empty column or value"},
		{"no row predicate", `doc:read and @row(status, "open")   @pdp`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := Parse(claimSpec(tc.body))
			if err != nil {
				if tc.says == "" {
					return
				}
				t.Fatalf("parse: %v", err)
			}
			err = Validate(sp)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refusal %q does not say %q", err.Error(), tc.says)
			}
		})
	}
}

func TestRow_NarrowsARequire(t *testing.T) {
	sp := validSpec(t, strings.Replace(claimSpec(`owner + grantee:read   @rls maps select`), "\n}", "\n  require view = owner and not @row(status, \"sealed\")\n}", 1))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name == "docs_select_require" {
			if !strings.Contains(p.Using, "(status = 'sealed') IS NOT TRUE") {
				t.Fatalf("the row term did not narrow the require: %s", p.Using)
			}
			return
		}
	}
	t.Fatal("no docs_select_require policy emitted")
}
