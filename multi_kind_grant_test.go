package demesne

import (
	"strings"
	"testing"
)

// A descriptor may grant to SEVERAL principal kinds at once (Increment 2C): a
// record shared with BOTH customers and admins (operators). Each kind gets its
// own grant definer keyed on that kind's claim, and the descriptor predicate ORs
// a term per kind. The OWNER-principal kind keeps the unsuffixed legacy definer
// name; additional kinds are suffixed by the kind.
const multiKindGrantSpec = `
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
subject service  { anchor project reach self identifies sub roles none }
object record {
  table  records
  scoped tenant > project
  descriptor {
    owner       customer | service via customer_id
    admin owner admin via admin_owner_id
    mode        via access_mode
    modes       private + read "public_project" + list "customer" + list "admin"
    grants      via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view = @app_scope + @descriptor @rls maps select
}
`

func TestMultiKindGrant(t *testing.T) {
	s, err := Parse(multiKindGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	dfns, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	defs := DefinersSQL(dfns)
	sql := res.PolicySQL("authenticated")

	// Two grant definers: the customer (owner-principal, unsuffixed legacy name) and
	// the admin (kind-suffixed), each filtering its own principal_kind.
	for _, want := range []string{
		"FUNCTION auth.resource_acl_grants_record(",
		"FUNCTION auth.resource_acl_grants_record_admin(",
		"principal_kind = 'customer'",
		"principal_kind = 'admin'",
	} {
		if !strings.Contains(defs, want) {
			t.Errorf("definers missing %q:\n%s", want, defs)
		}
	}

	// The select predicate ORs a grant term per kind — customer read against the
	// customer_id claim, admin read against the sub claim.
	if !strings.Contains(sql, "auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id')") {
		t.Errorf("missing customer-grant term:\n%s", sql)
	}
	if !strings.Contains(sql, "auth.resource_acl_grants_record_admin((current_setting('request.jwt.claims', true)::json ->> 'sub')") {
		t.Errorf("missing admin-grant term:\n%s", sql)
	}
}

// A single-kind (customer-only) descriptor is byte-identical to the pre-2C engine:
// one unsuffixed definer, no admin term — the capability is purely additive.
func TestMultiKindGrant_SingleKindUnchanged(t *testing.T) {
	s, err := Parse(reachGrantSpec) // record descriptor, list "customer" only
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dfns, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	defs := DefinersSQL(dfns)
	if strings.Contains(defs, "_grants_record_admin(") {
		t.Errorf("single-kind descriptor leaked an admin grant definer:\n%s", defs)
	}
}

// A list kind that names no claim-bearing subject is rejected — the grant would
// emit a term that can never match (fail-closed on misconfig).
func TestMultiKindGrant_UnknownKindRejected(t *testing.T) {
	spec := strings.Replace(multiKindGrantSpec, `list "admin"`, `list "ghost"`, 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil {
		t.Fatal("expected validation error for list kind with no claim-bearing subject")
	} else if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the bad kind: %v", err)
	}
}
