package demesne

import "testing"

// The capstone compile spike for the descriptor→pure-relation epic: a `record`
// object expressed with NO descriptor{} block — only generic relations (owner,
// admin_owner, grantee) + composable terms (@app_scope(exclude …), mode, the grant
// access selector) — must emit BYTE-IDENTICAL RLS policies to the prescriptive
// descriptor form. That equality is the refactor gate: dropping the descriptor is
// provably behaviour-preserving. (Primitives 1–3 cover the RLS side; the grant
// write-moat and the accessor enumerator — definer-side — are separate primitives.)

// Control: the descriptor record (owner + admin-owner + binary visibility + a
// customer/admin grant list over the discriminated resource_acl).
const pureRecControlSpec = `
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
  descriptor {
    owner       customer | service via customer_id
    admin owner admin via admin_owner_id
    mode        via access_mode
    modes       private + read "public" + list "customer" + list "admin"
    grants      via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view   = @app_scope + @descriptor   @rls maps select
  permission edit   = @app_scope + @descriptor   @rls maps update
  permission create = @app_scope + @descriptor   @rls maps insert
  permission delete = @app_scope + @descriptor   @rls maps delete
}
`

// Target: the SAME record as pure relations — no descriptor. owner / admin_owner /
// grantee are ordinary relations; visibility and operator reach are composable terms.
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

func TestPureRecord_ByteIdenticalToDescriptor(t *testing.T) {
	ctrl, err := Parse(pureRecControlSpec)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	if err := Validate(ctrl); err != nil {
		t.Fatalf("validate control: %v", err)
	}
	target, err := Parse(pureRecTargetSpec)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	if err := Validate(target); err != nil {
		t.Fatalf("validate target: %v", err)
	}

	cRLS, err := ctrl.EmitRLS()
	if err != nil {
		t.Fatalf("emit control rls: %v", err)
	}
	tRLS, err := target.EmitRLS()
	if err != nil {
		t.Fatalf("emit target rls: %v", err)
	}
	if c, tg := cRLS.PolicySQL("authenticated"), tRLS.PolicySQL("authenticated"); c != tg {
		t.Errorf("record RLS differs between descriptor and pure-relation forms:\n--- descriptor ---\n%s\n--- pure relations ---\n%s", c, tg)
	}

	// And the grant definers are byte-identical (the accessor enumerator is a
	// separate primitive, so total definer sets are not compared here).
	for _, name := range []string{"resource_acl_grants_record", "resource_acl_grants_record_admin"} {
		if c, tg := grantFnByName(t, ctrl, name), grantFnByName(t, target, name); c != tg {
			t.Errorf("grant definer %q differs:\n--- descriptor ---\n%s\n--- pure ---\n%s", name, c, tg)
		}
	}
}
