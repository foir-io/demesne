package demesne

import (
	"strings"
	"testing"
)

// The descriptor's owner principal is spec-declared (EID-265 WS2): the generated
// grant list + realtime-gate definers name the spec's ACTUAL owner principal and
// match its claim — they no longer assume a "customer". A member-owned object
// yields member_can_access_* / p_member_id, not customer_can_access_* /
// p_customer_id. (A spec whose owner principal IS "customer" emits the prior SQL
// byte-identically, which the Foir oracle proves.)
const memberOwnedSpec = `
topology {
  level tenant
  level project parent tenant
}
vocabulary member { permission self:read }
subject member { anchor project; reach self; identifies member_id; roles configurable member }
object doc {
  table  docs
  scoped tenant > project
  relation owner: member via member_id
  descriptor {
    owner  member via member_id
    mode   via visibility
    modes  private + read "public" + list "member"
    grants via edge doc_acl(doc_id, principal_kind, principal_id, access)
  }
  permission view = @descriptor @rls,kernel maps select
  permission edit = @descriptor @rls maps update
}
`

func TestPrincipalKinds_OwnerPrincipalDrivesSignatures(t *testing.T) {
	s, err := Parse(memberOwnedSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	by := map[string]GenFn{}
	for _, d := range defs {
		by[d.Name] = d
	}

	// (1) The realtime gate is named for the member principal, with a p_member_id
	//     param matched against the owner column — never "customer".
	k, ok := by["member_can_access_doc"]
	if !ok {
		t.Fatalf("no member_can_access_doc definer; got %v", keysOf(by))
	}
	if k.Sig != "p_member_id text, p_doc_id text, p_access text" {
		t.Errorf("kernel sig = %q, want p_member_id-led", k.Sig)
	}
	if !strings.Contains(k.Body, "r.member_id = p_member_id") {
		t.Errorf("kernel body does not match the member claim:\n%s", k.Body)
	}
	if _, bad := by["customer_can_access_doc"]; bad {
		t.Error("emitted a customer_can_access gate for a member-owned object — the 'customer' assumption survived")
	}

	// (2) The grant list checks the member claim against the spec-declared kind.
	g, ok := by["doc_acl_grants"]
	if !ok {
		t.Fatalf("no doc_acl_grants definer; got %v", keysOf(by))
	}
	if g.Sig != "p_member_id text, p_doc_id text, p_access text" {
		t.Errorf("grants sig = %q, want p_member_id-led", g.Sig)
	}
	if !strings.Contains(g.Body, "principal_kind = 'member'") || !strings.Contains(g.Body, "principal_id = p_member_id") {
		t.Errorf("grants body does not filter the member principal:\n%s", g.Body)
	}
}
