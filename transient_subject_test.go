package demesne

import (
	"strings"
	"testing"
)

func transientSpec(subject, relation, body string) string {
	return `
topology { level tenant }
vocabulary v { permission doc:read }
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
` + subject + `
object doc {
  table docs
  scoped tenant
  relation owner:   member via owner_id where owner_kind = "member"
  ` + relation + `
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = ` + body + `
}`
}

const (
	delegateSubject  = `subject delegate { anchor tenant reach self identifies acting_for roles none transient }`
	delegateRelation = `relation acting_for: delegate via owner_id where owner_kind = "member"`
)

func TestTransient_ComparesTheColumnToItsClaimInThePolicy(t *testing.T) {
	sp := validSpec(t, transientSpec(delegateSubject, delegateRelation, `owner + acting_for + grantee:read   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name != "docs_select" {
			continue
		}
		if !strings.Contains(p.Using, "owner_id = (current_setting('request.jwt.claims', true)::json ->> 'acting_for') AND owner_kind = 'member'") {
			t.Fatalf("the transient relation did not reach the row predicate: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestTransient_IsListedAsAClaimRatherThanAPrincipal(t *testing.T) {
	sp := validSpec(t, transientSpec(delegateSubject, delegateRelation, `owner + acting_for + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)

	if _, ok := fns["docs_accessors"]; ok {
		t.Error("docs_accessors must not be emitted: the transient relation admits any request carrying the claim, and the listing names none of them")
	}
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if strings.Contains(cond.Body, "'delegate'::text") {
		t.Errorf("a transient subject names no principal, so it must not appear as a principal kind:\n%s", cond.Body)
	}
	want := "SELECT 'claim'::text, NULL::text, NULL::text, 'read'::text, 'acting_for'::text, owner_id::text\n    FROM docs WHERE id = p_id AND owner_id IS NOT NULL AND owner_kind = 'member'"
	if !strings.Contains(cond.Body, want) {
		t.Errorf("expected a claim row keyed on the transient claim and valued from the row's column:\n%s", cond.Body)
	}
	if !strings.Contains(cond.Body, "'member'::text AS principal_kind, owner_id AS principal_id") {
		t.Errorf("the standing owner must still be named:\n%s", cond.Body)
	}
}

func TestTransient_UnderAConjunctionFoldsToOneAdmission(t *testing.T) {
	sp := validSpec(t, transientSpec(delegateSubject, delegateRelation, `owner + (@app_scope and not @claim("credential", "public")) + acting_for + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	if !strings.Contains(cond.Body, "'acting_for'::text, owner_id::text") {
		t.Errorf("the transient admission must survive beside a conjunction:\n%s", cond.Body)
	}
}

func TestTransient_RefusesWhatAStandingPrincipalHolds(t *testing.T) {
	for _, tc := range []struct {
		name, subject, relation, says string
	}{
		{"roles", `subject delegate { anchor tenant reach self identifies acting_for roles configurable v transient }`, delegateRelation, "must be `roles none`"},
		{"binds", `subject delegate { anchor tenant reach self identifies acting_for roles none binds admin transient }`, delegateRelation, "cannot bind a plane"},
		{"reach", `subject delegate { anchor tenant reach descendants identifies acting_for roles none transient }`, delegateRelation, "must `reach self`"},
		{"mixed", delegateSubject, `relation acting_for: delegate | member via owner_id where owner_kind = "member"`, "mixes a transient subject with standing ones"},
		{"grant", delegateSubject, `relation acting_for: delegate via grant other_acl(resource_id, principal_kind, principal_id, access)`, "a transient subject is a claim compared to a column"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := Parse(transientSpec(tc.subject, tc.relation, `owner + grantee:read   @rls maps select`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(sp)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refusal %q does not say %q", err.Error(), tc.says)
			}
		})
	}
}

const (
	readerSubject  = `subject reader { anchor tenant reach self identifies reads_all roles none transient set }`
	readerRelation = `relation reads_all: reader via kind`
)

func TestTransientSet_ComparesTheColumnToEachValueOfItsClaim(t *testing.T) {
	sp := validSpec(t, transientSpec(readerSubject, readerRelation, `owner + reads_all + grantee:read   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name != "docs_select" {
			continue
		}
		want := "kind = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text((current_setting('request.jwt.claims', true)::json ->> 'reads_all')::jsonb) e))"
		if !strings.Contains(p.Using, want) {
			t.Fatalf("the set relation did not reach the row predicate as a membership test: %s", p.Using)
		}
		if strings.Contains(p.Using, "kind = (current_setting('request.jwt.claims', true)::json ->> 'reads_all')") {
			t.Fatalf("the set relation was compared to its claim as one value: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestTransientSet_KeepsTheRelationsDiscriminator(t *testing.T) {
	sp := validSpec(t, transientSpec(readerSubject, `relation reads_all: reader via owner_id where owner_kind = "member"`, `owner + reads_all + grantee:read   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name != "docs_select" {
			continue
		}
		want := "(owner_id = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text((current_setting('request.jwt.claims', true)::json ->> 'reads_all')::jsonb) e)) AND owner_kind = 'member')"
		if !strings.Contains(p.Using, want) {
			t.Fatalf("the set relation lost its discriminator: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestTransientSet_CastsEachValueToTheIdentifierType(t *testing.T) {
	sp := validSpec(t, "identifiers uuid\n"+transientSpec(readerSubject, `relation reads_all: reader via owner_id`, `owner + reads_all + grantee:read   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name != "docs_select" {
			continue
		}
		if !strings.Contains(p.Using, "owner_id = ANY(ARRAY(SELECT e::uuid FROM jsonb_array_elements_text(") {
			t.Fatalf("the set's values were not cast to the identifier type: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestTransientSet_LeavesAOneValueTransientAsItWas(t *testing.T) {
	sp := validSpec(t, transientSpec(delegateSubject+"\n"+readerSubject, delegateRelation+"\n  "+readerRelation, `owner + acting_for + reads_all + grantee:read   @rls maps select`))
	res, err := sp.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range res.Policies {
		if p.Name != "docs_select" {
			continue
		}
		if !strings.Contains(p.Using, "owner_id = (current_setting('request.jwt.claims', true)::json ->> 'acting_for') AND owner_kind = 'member'") {
			t.Fatalf("a one-value transient relation beside a set was not compared to its claim: %s", p.Using)
		}
		return
	}
	t.Fatal("no docs_select policy emitted")
}

func TestTransientSet_IsListedAsAClaimValuedFromTheRow(t *testing.T) {
	sp := validSpec(t, transientSpec(readerSubject, readerRelation, `owner + reads_all + grantee:read   @rls maps select`))
	fns, have := claimDefiners(t, sp)
	if _, ok := fns["docs_accessors"]; ok {
		t.Error("docs_accessors must not be emitted: the set admits any request whose claim lists the row's value")
	}
	cond, ok := fns["docs_accessors_conditional"]
	if !ok {
		t.Fatalf("expected docs_accessors_conditional, have: %s", have)
	}
	want := "SELECT 'claim'::text, NULL::text, NULL::text, 'read'::text, 'reads_all'::text, kind::text\n    FROM docs WHERE id = p_id AND kind IS NOT NULL"
	if !strings.Contains(cond.Body, want) {
		t.Errorf("expected a claim row keyed on the set's claim and valued from the row's column:\n%s", cond.Body)
	}
}

func TestTransientSet_RefusesWhatItCannotMean(t *testing.T) {
	for _, tc := range []struct {
		name, subject, relation, says string
	}{
		{"beside another transient", delegateSubject + "\n" + readerSubject, `relation reads_all: reader | delegate via kind`, "names the transient set"},
		{"beside a standing subject", readerSubject, `relation reads_all: reader | member via kind`, "mixes a transient subject with standing ones"},
		{"through a grant", readerSubject, `relation reads_all: reader via grant other_acl(resource_id, principal_kind, principal_id, access)`, "a transient subject is a claim compared to a column"},
		{"holding roles", `subject reader { anchor tenant reach self identifies reads_all roles configurable v transient set }`, readerRelation, "must be `roles none`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := Parse(transientSpec(tc.subject, tc.relation, `owner + grantee:read   @rls maps select`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(sp)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refusal %q does not say %q", err.Error(), tc.says)
			}
		})
	}
}

func TestTransientSet_IsOnlySaidOfATransientSubject(t *testing.T) {
	_, err := Parse(transientSpec(`subject reader { anchor tenant reach self identifies reads_all roles none set }`, readerRelation, `owner + grantee:read   @rls maps select`))
	if err == nil {
		t.Fatal("`set` with no `transient` before it was accepted")
	}
}
