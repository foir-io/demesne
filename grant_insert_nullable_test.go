package demesne

import "testing"

// A `wildcard` level is nullable by definition — `(col IS NULL OR col = claim)`
// is what the marker emits — so an adopter that declares one has a containment
// column whose commonest legitimate value is SQL NULL. GrantInsert takes
// []string, so the only thing a caller can put there is "", and '' satisfies
// neither disjunct: the insert's own WITH CHECK refuses it with 42501, naming a
// column the caller never mentioned.
const wildcardGrantSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
  level org      parent project
}
vocabulary admin { permission c:r preset pa @ project = c:r }
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
object record {
  table  records
  scoped tenant > project > org wildcard
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view = owner + grantee:read @rls maps select
}
`

func wildcardSurface(t *testing.T) *ResourceAccessSurface {
	t.Helper()
	s := mustSpec(t, wildcardGrantSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	r, err := s.ConditionalResourceAccessSurface("record")
	if err != nil {
		t.Fatalf("surface: %v", err)
	}
	return r
}

func TestGrantInsertBindsAnAbsentWildcardLevelAsNull(t *testing.T) {
	r := wildcardSurface(t)
	_, args := r.GrantInsert([]string{"t1", "p1", ""}, "rec1", "customer", "cust9", "read")

	if len(args) < 3 {
		t.Fatalf("args = %v", args)
	}
	if args[2] != nil {
		t.Fatalf("the absent org level bound as %#v, not SQL NULL — '' satisfies neither `org_id IS NULL` nor `org_id = <claim>`, so the grant's own WITH CHECK refuses it", args[2])
	}
	// The levels that are NOT wildcards must be untouched, or a genuinely
	// missing tenant would be papered over as NULL instead of failing against
	// NOT NULL.
	if args[0] != "t1" || args[1] != "p1" {
		t.Fatalf("pinned levels changed: %#v, %#v", args[0], args[1])
	}
}

func TestGrantInsertLeavesANonWildcardEmptyValueAlone(t *testing.T) {
	r := wildcardSurface(t)
	_, args := r.GrantInsert([]string{"t1", "", "o1"}, "rec1", "customer", "cust9", "read")
	if args[1] != "" {
		t.Fatalf("a non-wildcard empty value was rewritten to %#v; it must still fail loudly against NOT NULL", args[1])
	}
	if args[2] != "o1" {
		t.Fatalf("a present wildcard value was not passed through: %#v", args[2])
	}
}
