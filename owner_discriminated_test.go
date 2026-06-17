package demesne

import (
	"strings"
	"testing"
)

// The ViaColumn discriminator (the unified owner_id/owner_kind shape) on PURE owner
// relations: several owner kinds share one id column, each gated by a constant in a
// kind column. `relation owner: customer via owner_id where owner_kind = "customer"`.
// This is the owner-axis counterpart of the discriminated grant store, and what the
// owner_id+owner_kind unification adopts.
const discriminatedOwnerSpec = `
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
  relation owner:       customer | service via owner_id where owner_kind = "customer"
  relation admin_owner: admin via owner_id where owner_kind = "admin"
  relation grantee:     customer | admin via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view = @app_scope(exclude admin_owner) + owner + admin_owner + mode access_mode = "public" + grantee:read   @rls maps select
  permission edit = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:write                               @rls maps update
}
`

func TestDiscriminatedOwnerColumn(t *testing.T) {
	s, err := Parse(discriminatedOwnerSpec)
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
	sel := policyByCmd(res, "records", "SELECT").Using

	// The owner terms gate the shared owner_id column by the kind column.
	for _, want := range []string{
		"(owner_id = (current_setting('request.jwt.claims', true)::json ->> 'customer_id') AND owner_kind = 'customer')",
		"(owner_id = (current_setting('request.jwt.claims', true)::json ->> 'sub') AND owner_kind = 'admin')",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("select policy missing owner term %q:\n%s", want, sel)
		}
	}
	// @app_scope(exclude admin_owner) excludes admin-owned rows by the kind column —
	// existence-negation (operator-private), NOT a principal match.
	if !strings.Contains(sel, "owner_kind IS DISTINCT FROM 'admin'") {
		t.Errorf("select policy missing the discriminated admin-owner exclusion:\n%s", sel)
	}

	// The accessor enumerator reports both owner kinds, present-gated by the kind col.
	acc := grantFnByName(t, s, "records_accessors")
	for _, want := range []string{
		"'customer'::text AS principal_kind, owner_id AS principal_id",
		"owner_id IS NOT NULL AND owner_kind = 'customer'",
		"owner_id IS NOT NULL AND owner_kind = 'admin'",
	} {
		if !strings.Contains(acc, want) {
			t.Errorf("accessor missing %q:\n%s", want, acc)
		}
	}
}
