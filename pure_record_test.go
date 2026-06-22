package demesne

import (
	"strings"
	"testing"
)

const pureRecTargetSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin { permission c:r  preset pa @ project = c:r }
vocabulary cust  { permission self:read }
grant impersonation at tenant via edge impersonation_grants(grantee_id, tenant_id) active revoked_at expires expires_at
rolestore admin {
  assignments ra
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject operator { anchor platform reach via grant impersonation identifies sub roles none }
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
subject service  { anchor project reach self identifies sub roles none }
object record {
  table  records
  scoped tenant > project
  relation owner:       customer | service via customer_id
  relation admin_owner: admin via admin_owner_id
  relation grantee:     customer | admin via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view   = @app_scope(exclude admin_owner) + owner + admin_owner + mode access_mode = "public" + grantee:read   @rls maps select
  permission edit   = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:write                               @rls maps update
  permission create = @app_scope(exclude admin_owner) + owner + admin_owner                                               @rls maps insert
  permission delete = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:delete                              @rls maps delete
}
`

func TestPureRecord_EmitsExpectedRLS(t *testing.T) {
	s, err := Parse(pureRecTargetSpec)
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
	for _, want := range []string{

		"customer_id = (current_setting('request.jwt.claims', true)::json ->> 'customer_id')",

		"admin_owner_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')",

		"(current_setting('request.jwt.claims', true)::json ->> 'customer_id') IS NULL AND admin_owner_id IS NULL",

		"access_mode = 'public'",

		"auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id'), records.id, 'read')",
		"auth.resource_acl_grants_record_admin((current_setting('request.jwt.claims', true)::json ->> 'sub'), records.id, 'read')",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("records_select missing %q:\n%s", want, sel)
		}
	}

	ins := policyByCmd(res, "records", "INSERT").Check
	if strings.Contains(ins, "access_mode = 'public'") || strings.Contains(ins, "resource_acl_grants") {
		t.Errorf("records_insert should not carry read mode / grant terms:\n%s", ins)
	}
}

func TestPureRecord_EmitsGrantDefinersAndAccessor(t *testing.T) {
	s, err := Parse(pureRecTargetSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dfns, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	defs := DefinersSQL(dfns)
	for _, want := range []string{
		"FUNCTION auth.resource_acl_grants_record(p_customer_id text, p_record_id text, p_access text)",
		"FUNCTION auth.resource_acl_grants_record_admin(p_admin_id text, p_record_id text, p_access text)",
	} {
		if !strings.Contains(defs, want) {
			t.Errorf("definers missing %q:\n%s", want, defs)
		}
	}

	acc := grantFnByName(t, s, "records_accessors")
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION auth.records_accessors(p_id text)",
		"RETURNS TABLE(source text, principal_kind text, principal_id text, access text)",
		"SECURITY DEFINER",

		"SELECT 'owner'::text AS source, 'customer'::text AS principal_kind, customer_id AS principal_id, 'write'::text AS access\n    FROM records WHERE id = p_id AND customer_id IS NOT NULL",

		"SELECT 'owner'::text, 'admin'::text, admin_owner_id, 'write'::text\n    FROM records WHERE id = p_id AND admin_owner_id IS NOT NULL",

		"SELECT 'grant'::text, principal_kind, principal_id, access\n    FROM resource_acl WHERE resource_id = p_id AND resource_type = 'record'",

		"SELECT 'role'::text, 'admin'::text, ra.principal_id, 'read'::text",
		"WHERE r.id = p_id AND r.admin_owner_id IS NULL",
	} {
		if !strings.Contains(acc, want) {
			t.Errorf("records_accessors missing %q:\n%s", want, acc)
		}
	}
}

func TestPureAccessor_CustomerOnly(t *testing.T) {
	pure, err := Parse(storeManagePureSpec)
	if err != nil {
		t.Fatalf("parse pure: %v", err)
	}
	if err := Validate(pure); err != nil {
		t.Fatalf("validate pure: %v", err)
	}
	for _, tc := range []struct{ table, discrim string }{
		{"records", "record"},
		{"files", "file"},
	} {
		acc := grantFnByName(t, pure, tc.table+"_accessors")
		if strings.Contains(acc, "admin_owner_id") {
			t.Errorf("%s_accessors (customer-only) should not reference admin_owner_id:\n%s", tc.table, acc)
		}

		if !strings.Contains(acc, "'owner'::text AS source, 'customer'::text AS principal_kind, customer_id AS principal_id, 'write'::text AS access\n    FROM "+tc.table+" WHERE id = p_id AND customer_id IS NOT NULL") {
			t.Errorf("%s_accessors missing customer-owner branch:\n%s", tc.table, acc)
		}

		if !strings.Contains(acc, "FROM resource_acl WHERE resource_id = p_id AND resource_type = '"+tc.discrim+"'") {
			t.Errorf("%s_accessors missing discriminated grant branch:\n%s", tc.table, acc)
		}
	}
}
