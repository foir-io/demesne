package demesne

import (
	"strings"
	"testing"
)

// The unified owner shape: both owner axes read ONE id column (owner_id) gated by
// a kind column (owner_kind) — `via owner_id where owner_kind = "<kind>"` — the
// same (kind, id) principal reference the grant edge uses, instead of two
// type-specific owner columns.
const ownerDiscriminatedSpec = `
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
    owner       customer | service via owner_id where owner_kind = "customer"
    admin owner admin via owner_id where owner_kind = "admin"
    mode        via access_mode
    modes       private + read "public" + list "customer"
    grants      via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view = @app_scope + @descriptor @rls maps select
}
`

func TestDescriptorOwnerDiscriminated(t *testing.T) {
	s, err := Parse(ownerDiscriminatedSpec)
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
	sql := res.PolicySQL("authenticated")

	// Customer owner: owner_id matched against the customer claim, gated by kind.
	if !strings.Contains(sql, "(owner_id = (current_setting('request.jwt.claims', true)::json ->> 'customer_id') AND owner_kind = 'customer')") {
		t.Errorf("missing discriminated customer-owner term:\n%s", sql)
	}
	// Admin owner: the SAME owner_id column matched against the sub claim, kind 'admin'.
	if !strings.Contains(sql, "(owner_id = (current_setting('request.jwt.claims', true)::json ->> 'sub') AND owner_kind = 'admin')") {
		t.Errorf("missing discriminated admin-owner term:\n%s", sql)
	}
	// Broad operator reach excludes admin-owned rows via the kind column (a NULL
	// owner_kind — the unowned plane — still passes).
	if !strings.Contains(sql, "(current_setting('request.jwt.claims', true)::json ->> 'customer_id') IS NULL AND owner_kind IS DISTINCT FROM 'admin'") {
		t.Errorf("@app_scope not gated by owner_kind IS DISTINCT FROM 'admin':\n%s", sql)
	}
	// No stale legacy owner columns.
	if strings.Contains(sql, "customer_id = (current_setting") || strings.Contains(sql, "admin_owner_id") {
		t.Errorf("leaked a legacy owner column:\n%s", sql)
	}
}

// The accessor (Expand) enumerates both owner axes off owner_id, kind-gated.
func TestDescriptorOwnerDiscriminated_Accessor(t *testing.T) {
	defs := findAccessor(t, ownerDiscriminatedSpec, "records")
	if !strings.Contains(defs, "owner_id IS NOT NULL AND owner_kind = 'customer'") {
		t.Errorf("accessor missing kind-gated customer owner branch:\n%s", defs)
	}
	if !strings.Contains(defs, "owner_id IS NOT NULL AND owner_kind = 'admin'") {
		t.Errorf("accessor missing kind-gated admin owner branch:\n%s", defs)
	}
}
