package demesne

import (
	"reflect"
	"testing"
)

// fullRoleStoreSpec declares every optional write-surface column (pk + the grant /
// revoke audit columns + a materialized permissions column).
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

// minimalRoleStoreSpec declares only the read columns (no pk/granted/revoked-by) —
// the write builders fall back to the "id" PK and omit the undeclared audit columns.
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

func TestRoleAssignment_FullSurface(t *testing.T) {
	s := mustSpec(t, fullRoleStoreSpec)
	r, err := s.RoleAssignmentSurface("")
	if err != nil {
		t.Fatalf("RoleAssignmentSurface: %v", err)
	}

	// Assign — kind inlined, scope + grantor bound, full audit projection returned.
	sql, args := r.AssignInsert("a1", "u1", "role1", []string{"t1", "p1"}, "granter1")
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

	// Revoke — soft-revoke by PK + revoker, idempotent.
	if got := r.RevokeSQL(); got != "UPDATE role_assignments SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL" {
		t.Errorf("RevokeSQL = %q", got)
	}

	// List by role — audit view, newest first.
	wantByRole := "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, granted_at, granted_by, revoked_at, revoked_by " +
		"FROM role_assignments WHERE role_id = $1 ORDER BY granted_at DESC"
	if got := r.ListForRoleSQL(); got != wantByRole {
		t.Errorf("ListForRoleSQL:\n got: %s\nwant: %s", got, wantByRole)
	}

	// List by principal — active, joined to the role's key + permissions; kind inlined.
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

	// No grantor column → omitted from the INSERT (grantedBy arg ignored); RETURNING
	// carries only the declared columns (revoked_at, but no granted_at/by, revoked_by).
	sql, args := r.AssignInsert("a1", "u1", "role1", []string{"t1", "p1"}, "ignored")
	wantSQL := "INSERT INTO role_assignments (id, principal_kind, principal_id, role_id, tenant_id, project_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6) " +
		"RETURNING id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at"
	if sql != wantSQL {
		t.Errorf("AssignInsert SQL:\n got: %s\nwant: %s", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{"a1", "admin", "u1", "role1", "t1", "p1"}) {
		t.Errorf("AssignInsert args = %v", args)
	}

	// Revoke with no revoker column.
	if got := r.RevokeSQL(); got != "UPDATE role_assignments SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL" {
		t.Errorf("RevokeSQL = %q", got)
	}

	// No granted-at column → no ORDER BY.
	if got := r.ListForRoleSQL(); got != "SELECT id, principal_kind, principal_id, role_id, tenant_id, project_id, revoked_at FROM role_assignments WHERE role_id = $1" {
		t.Errorf("ListForRoleSQL = %q", got)
	}

	// No granted-at/by + no materialized permissions → ListForPrincipal omits all
	// three optional columns (the guard FALSE branch), keeping only the join + active
	// filter projection.
	wantByPrincipal := "SELECT a.id, a.principal_id, a.role_id, r.key " +
		"FROM role_assignments a JOIN roles r ON r.id = a.role_id " +
		"WHERE a.principal_kind = 'admin' AND a.principal_id = $1 AND a.revoked_at IS NULL"
	if got := r.ListForPrincipalSQL(); got != wantByPrincipal {
		t.Errorf("ListForPrincipalSQL (minimal):\n got: %s\nwant: %s", got, wantByPrincipal)
	}
}

// A scope shorter than ScopeCols leaves the unsupplied levels NULL (an unpinned
// tail), not a panic.
func TestRoleAssignment_ShortScope(t *testing.T) {
	s := mustSpec(t, fullRoleStoreSpec)
	r, _ := s.RoleAssignmentSurface("")
	_, args := r.AssignInsert("a1", "u1", "role1", []string{"t1"}, "g1")
	want := []any{"a1", "admin", "u1", "role1", "t1", nil, "g1"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("short-scope args = %v, want %v", args, want)
	}
}

// The pk override is honoured by both the INSERT id column and the revoke key.
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
	sql, _ := r.AssignInsert("g1", "u1", "r1", []string{"t1"}, "")
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
