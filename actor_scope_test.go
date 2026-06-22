package demesne

import (
	"strings"
	"testing"
)

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
  relation owner:       customer | service via customer_id
  relation admin_owner: admin via admin_owner_id
  relation grantee:     customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view = @app_scope(exclude admin_owner) + owner + admin_owner + mode access_mode = "public_project" + grantee:read @rls maps select
}
`

const adminPlaneNoteSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
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
subject service  { anchor project reach self identifies sub roles none }
object note {
  table  notes
  scoped tenant > project
  relation owner:   admin via created_by
  relation grantee: admin via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note"
  permission view   = owner + mode access_mode = "public" for admin + grantee:read   @rls maps select
  permission edit   = @app_scope + owner + grantee:write                             @rls maps update
  permission create = @app_scope + owner                                             @rls maps insert
  permission delete = @app_scope + owner + grantee:delete                            @rls maps delete
}
`

func TestAdminPlaneActorScoped(t *testing.T) {
	s, err := Parse(adminPlaneNoteSpec)
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

	if !strings.Contains(sql, "created_by = (current_setting('request.jwt.claims', true)::json ->> 'sub')") {
		t.Errorf("missing admin-plane owner term (created_by = sub):\n%s", sql)
	}

	if !strings.Contains(sql, "access_mode = 'public' AND (current_setting('request.jwt.claims', true)::json ->> 'customer_id') IS NULL") {
		t.Errorf("public read mode not scoped to the operator plane:\n%s", sql)
	}

	if !strings.Contains(sql, "(current_setting('request.jwt.claims', true)::json ->> 'sub'), notes.id, 'read')") {
		t.Errorf("admin grant disjunct not bound to the admin claim:\n%s", sql)
	}

	accessors := findAccessor(t, adminPlaneNoteSpec, "notes")
	if !strings.Contains(accessors, "created_by") || strings.Contains(accessors, "customer_id") {
		t.Errorf("accessor enumerator should read created_by, never customer_id:\n%s", accessors)
	}
	if !strings.Contains(accessors, "'admin'") {
		t.Errorf("accessor owner rows should be tagged with the admin kind:\n%s", accessors)
	}

	if strings.Contains(accessors, "'role'") || strings.Contains(accessors, "role_assignments") {
		t.Errorf("admin-plane @app_scope-free accessor leaked a role branch:\n%s", accessors)
	}

	withAppScope := findAccessor(t, adminOwnerSpec, "records")
	if !strings.Contains(withAppScope, "'role'") {
		t.Errorf("an @app_scope object should still enumerate the role plane:\n%s", withAppScope)
	}
}

func TestUnscopedReadUnchanged(t *testing.T) {
	s, err := Parse(reachGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sql := res.PolicySQL("authenticated")

	if strings.Contains(sql, "access_mode = 'public_project' AND") {
		t.Errorf("unscoped read mode leaked a plane predicate:\n%s", sql)
	}
	if !strings.Contains(sql, "access_mode = 'public_project'") {
		t.Errorf("expected the bare public_project sentinel:\n%s", sql)
	}
}
