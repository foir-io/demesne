package demesne

import (
	"reflect"
	"testing"
)

const fullRoleStoreSpec = `
topology { level tenant  level project parent tenant }
vocabulary admin { permission a:read  preset v @ project = a:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at by revoked_by
  granted     granted_at by granted_by
  permissions permissions
  pk          id
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant > project; relation m: admin via role; permission view = m @rls maps select }
`

const minimalRoleStoreSpec = `
topology { level tenant  level project parent tenant }
vocabulary admin { permission a:read  preset v @ project = a:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant > project; relation m: admin via role; permission view = m @rls maps select }
`

const rpScopedRoleStoreSpec = `
topology { level tenant  level project parent tenant }
vocabulary admin { permission a:read  preset v @ project = a:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at by revoked_by
  granted     granted_at by granted_by
  pk          id
  column      client_id
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant > project; relation m: admin via role; permission view = m @rls maps select }
`

func TestRoleAssignment_TouchAndExtra(t *testing.T) {
	s := mustSpec(t, rpScopedRoleStoreSpec)
	r, err := s.RoleAssignmentSurface("")
	if err != nil {
		t.Fatalf("surface: %v", err)
	}

	sql, args := r.AssignInsert("a1", "u1", "role1", []string{"t1", "p1"}, "g1", map[string]any{"client_id": "rp1"})
	wantCreate := "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by, client_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " +
		"RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by, client_id"
	if sql != wantCreate {
		t.Errorf("AssignInsert (extra) SQL:\n got: %s\nwant: %s", sql, wantCreate)
	}
	if !reflect.DeepEqual(args, []any{"a1", "admin", "u1", "role1", "t1", "p1", "g1", "rp1"}) {
		t.Errorf("AssignInsert (extra) args = %v", args)
	}

	tsql, targs := r.AssignTouchInsert("a1", "u1", "role1", []string{"t1", "p1"}, "g1", map[string]any{"client_id": "rp1"})
	wantTouch := "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by, client_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " +
		"ON CONFLICT (principal_kind, principal_id, role_id, COALESCE(tenant_id, ''), COALESCE(project_id, ''), COALESCE(client_id, '')) DO UPDATE SET " +
		"revoked_at = NULL, revoked_by = NULL, granted_at = now(), granted_by = EXCLUDED.granted_by " +
		"RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by, client_id"
	if tsql != wantTouch {
		t.Errorf("AssignTouchInsert SQL:\n got: %s\nwant: %s", tsql, wantTouch)
	}

	if !reflect.DeepEqual(targs, args) {
		t.Errorf("TOUCH args drift from CREATE: %v vs %v", targs, args)
	}
}

func TestTouchOnConflict_GeneralAcrossEdges(t *testing.T) {
	roleAssign := touchOnConflict(
		[]string{"principal_kind", "principal_id", "role_id"},
		[]string{"tenant_id", "project_id", "client_id"},
		[]string{"revoked_at = NULL", "granted_at = now()"})
	if roleAssign != "ON CONFLICT (principal_kind, principal_id, role_id, COALESCE(tenant_id, ''), COALESCE(project_id, ''), COALESCE(client_id, '')) DO UPDATE SET revoked_at = NULL, granted_at = now()" {
		t.Errorf("role-assignment touch clause = %q", roleAssign)
	}
	levelGrant := touchOnConflict(
		[]string{"grantee_id"},
		[]string{"tenant_id"},
		[]string{"revoked_at = NULL"})
	if levelGrant != "ON CONFLICT (grantee_id, COALESCE(tenant_id, '')) DO UPDATE SET revoked_at = NULL" {
		t.Errorf("level-grant touch clause = %q", levelGrant)
	}
}

func TestRoleAssignment_FullSurface(t *testing.T) {
	s := mustSpec(t, fullRoleStoreSpec)
	r, err := s.RoleAssignmentSurface("")
	if err != nil {
		t.Fatalf("RoleAssignmentSurface: %v", err)
	}

	sql, args := r.AssignInsert("a1", "u1", "role1", []string{"t1", "p1"}, "granter1", nil)
	wantSQL := "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_by) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7) " +
		"RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by"
	if sql != wantSQL {
		t.Errorf("AssignInsert SQL:\n got: %s\nwant: %s", sql, wantSQL)
	}
	wantArgs := []any{"a1", "admin", "u1", "role1", "t1", "p1", "granter1"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("AssignInsert args = %v, want %v", args, wantArgs)
	}

	if got := r.RevokeSQL(); got != "UPDATE role_assignments SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL" {
		t.Errorf("RevokeSQL = %q", got)
	}

	wantByRole := "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by " +
		"FROM role_assignments WHERE role_id = $1 ORDER BY granted_at DESC"
	if got := r.ListForRoleSQL(); got != wantByRole {
		t.Errorf("ListForRoleSQL:\n got: %s\nwant: %s", got, wantByRole)
	}

	wantByPrincipal := "SELECT a.id, a.principal_id, a.role_id, a.granted_at, a.granted_by, r.key, r.permissions " +
		"FROM role_assignments a JOIN roles r ON r.id = a.role_id " +
		"WHERE a.principal_kind = 'admin' AND a.principal_id = $1 AND a.revoked_at IS NULL"
	if got := r.ListForPrincipalSQL(); got != wantByPrincipal {
		t.Errorf("ListForPrincipalSQL:\n got: %s\nwant: %s", got, wantByPrincipal)
	}
}

func TestRoleAssignment_MinimalSurface(t *testing.T) {
	s := mustSpec(t, minimalRoleStoreSpec)
	r, err := s.RoleAssignmentSurface("")
	if err != nil {
		t.Fatalf("RoleAssignmentSurface: %v", err)
	}
	if r.PK != "id" {
		t.Errorf("PK should default to id, got %q", r.PK)
	}

	sql, args := r.AssignInsert("a1", "u1", "role1", []string{"t1", "p1"}, "ignored", nil)
	wantSQL := "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6) " +
		"RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at"
	if sql != wantSQL {
		t.Errorf("AssignInsert SQL:\n got: %s\nwant: %s", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{"a1", "admin", "u1", "role1", "t1", "p1"}) {
		t.Errorf("AssignInsert args = %v", args)
	}

	if got := r.RevokeSQL(); got != "UPDATE role_assignments SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL" {
		t.Errorf("RevokeSQL = %q", got)
	}

	if got := r.ListForRoleSQL(); got != "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at FROM role_assignments WHERE role_id = $1" {
		t.Errorf("ListForRoleSQL = %q", got)
	}

	wantByPrincipal := "SELECT a.id, a.principal_id, a.role_id, r.key " +
		"FROM role_assignments a JOIN roles r ON r.id = a.role_id " +
		"WHERE a.principal_kind = 'admin' AND a.principal_id = $1 AND a.revoked_at IS NULL"
	if got := r.ListForPrincipalSQL(); got != wantByPrincipal {
		t.Errorf("ListForPrincipalSQL (minimal):\n got: %s\nwant: %s", got, wantByPrincipal)
	}
}

func TestRoleAssignment_ShortScope(t *testing.T) {
	s := mustSpec(t, fullRoleStoreSpec)
	r, _ := s.RoleAssignmentSurface("")
	_, args := r.AssignInsert("a1", "u1", "role1", []string{"t1"}, "g1", nil)
	want := []any{"a1", "admin", "u1", "role1", "t1", nil, "g1"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("short-scope args = %v, want %v", args, want)
	}
}

func TestRoleAssignment_PKOverride(t *testing.T) {
	const src = `
topology { level tenant }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
rolestore admin {
  assignments grants
  kind        kind = "op"
  subject     who
  scope       tenant_id
  rolejoin    role_ref role_defs ref slug
  revoked     ended_at
  pk          grant_id
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; relation m: admin via role; permission view = m @rls maps select }
`
	s := mustSpec(t, src)
	r, err := s.RoleAssignmentSurface("")
	if err != nil {
		t.Fatalf("surface: %v", err)
	}
	if r.PK != "grant_id" {
		t.Errorf("PK = %q, want grant_id", r.PK)
	}
	if got := r.RevokeSQL(); got != "UPDATE grants SET ended_at = now() WHERE grant_id = $1 AND ended_at IS NULL" {
		t.Errorf("RevokeSQL = %q", got)
	}
	sql, _ := r.AssignInsert("g1", "u1", "r1", []string{"t1"}, "", nil)
	want := "INSERT INTO grants (grant_id, kind, who, role_ref, tenant_id) VALUES ($1, $2, $3, $4, $5) " +
		"RETURNING grant_id, kind, who, role_ref, tenant_id, ended_at"
	if sql != want {
		t.Errorf("AssignInsert SQL:\n got: %s\nwant: %s", sql, want)
	}
}

func TestRoleAssignment_NoRoleStore(t *testing.T) {
	const src = `
topology { level tenant }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; permission view = @scoped @rls maps select }
`
	s := mustSpec(t, src)
	if _, err := s.RoleAssignmentSurface(""); err == nil {
		t.Error("expected an error when the spec declares no rolestore")
	}
	if _, err := s.RoleAssignmentSurface("nope"); err == nil {
		t.Error("expected an error for an unknown rolestore name")
	}
}
