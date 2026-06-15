package demesne

import (
	"strings"
	"testing"
)

// The descriptor's ADMIN owner axis: a record owned by the admin who created it
// (admin_owner_id = the admin's claim) is operator-PRIVATE — the broad app/service
// reach (@app_scope) is gated to exclude admin-owned rows, while the owning admin
// still reaches its own.
const adminOwnerSpec = `
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
    modes       private + read "public_project" + list "customer"
    grants      via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view = @app_scope + @descriptor @rls maps select
}
`

func TestDescriptorAdminOwner(t *testing.T) {
	s, err := Parse(adminOwnerSpec)
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

	// The owning admin reaches its own admin-owned record.
	if !strings.Contains(sql, "admin_owner_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')") {
		t.Errorf("missing admin-owner term:\n%s", sql)
	}
	// The broad app/service reach is gated to EXCLUDE admin-owned rows.
	if !strings.Contains(sql, "(current_setting('request.jwt.claims', true)::json ->> 'customer_id') IS NULL AND admin_owner_id IS NULL") {
		t.Errorf("@app_scope not gated by admin_owner_id IS NULL:\n%s", sql)
	}
}

// Without an admin owner axis, @app_scope is the bare customer-claim check
// (byte-identical to before) — the capability is purely additive.
func TestDescriptorAdminOwner_BareUnchanged(t *testing.T) {
	s, err := Parse(reachGrantSpec) // record descriptor, no admin owner
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sql := res.PolicySQL("authenticated")
	if strings.Contains(sql, "admin_owner_id") {
		t.Errorf("bare descriptor leaked an admin_owner term:\n%s", sql)
	}
}
