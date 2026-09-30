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
