package demesne

import (
	"strings"
	"testing"
)

// A grant relation naming two kinds emits one fragment per kind, each keyed on
// that kind's own claim. The claims are not symmetrical: `customer_id` is
// minted for owner-plane callers and nobody else, but `sub` is the generic
// subject an adopter may also mint for an owner-plane caller. Without a plane
// guard, a grant row naming the ADMIN kind is reachable by an owner-plane
// caller whose id happens to equal that row's principal_id — two id spaces that
// never meet, joined by a claim that carried the wrong one.
const twoKindGrantSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin { permission c:r  preset pa @ project = c:r }
vocabulary cust  { permission self:read }
rolestore admin {
  assignments ra
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object note {
  table  notes
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: KINDS via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note"
  permission view = owner + grantee:read @rls maps select
}
`

func notesSelectPredicate(t *testing.T, kinds string) string {
	t.Helper()
	s := mustSpec(t, strings.Replace(twoKindGrantSpec, "KINDS", kinds, 1))
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pols, err := s.EmitRLS()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pols.Policies {
		if p.Name == "notes_select" {
			return p.Using
		}
	}
	t.Fatal("no notes_select policy")
	return ""
}

func TestGrantKindIsBoundToItsCallerPlane(t *testing.T) {
	pred := notesSelectPredicate(t, "customer | admin")

	adminFrag := "auth.resource_acl_grants_note_admin(" + planeClaim("sub") + ", notes.id, 'read')"
	wantGuarded := "(" + adminFrag + " AND " + planeClaim("customer_id") + " IS NULL)"
	if !strings.Contains(pred, wantGuarded) {
		t.Fatalf("the admin-kind grant fragment is not bound to the admin plane\n got: %s\nwant it to contain: %s", pred, wantGuarded)
	}

	// The owner-plane kind is NOT given the mirror test: its fragment's own
	// argument is that claim, so a caller without it matches no row already.
	custFrag := "auth.resource_acl_grants_note(" + planeClaim("customer_id") + ", notes.id, 'read')"
	if !strings.Contains(pred, custFrag) {
		t.Fatalf("the customer-kind grant fragment changed shape\n got: %s\nwant it to contain: %s", pred, custFrag)
	}
	if strings.Contains(pred, custFrag+" AND ") {
		t.Fatalf("the customer-kind fragment was given a redundant plane test: %s", pred)
	}
}

// The positive control: a single-kind grant on the owner plane is the common
// shape and must be left exactly as it was, or this guard is silently rewriting
// every adopter's policies rather than the one case it is for.
func TestSingleOwnerPlaneGrantIsUnguarded(t *testing.T) {
	pred := notesSelectPredicate(t, "customer")
	if strings.Contains(pred, "IS NULL") {
		t.Fatalf("a single owner-plane grant gained a plane test it does not need: %s", pred)
	}
}

func planeClaim(key string) string {
	return "(current_setting('request.jwt.claims', true)::json ->> '" + key + "')"
}
