package demesne

import (
	"strings"
	"testing"
)

// The platform plane (v3 WS6): a table ABOVE tenancy, governed by a role anchored
// at the virtual root. This is the general retirement of the is_platform_admin
// god-flag — the global tables' staff-access definer is GENERATED as a revocable
// role check (has_platform_role, the same role-resolution EXISTS as every
// tenant/project role, with NULL scope), not a hand-written standing-boolean.
//
// The spec mirrors Foir's shape: a virtual platform root, the scoped impersonation
// GRANT operator (reaches DOWN into tenants), AND a platform-anchored `staff` role
// subject governing the global objects. The two must not bleed into each other:
// the grant never touches a global table (no scope column to cascade on); the
// platform role never touches a tenant/project table (it is the schema-root plane).
const platformPlaneSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read  permission content:write
  preset project_admin @ project = content:read + content:write
  preset tenant_owner  @ tenant  = *
  rank tenant_owner > project_admin
}
vocabulary platform {
  permission platform:manage
  preset platform_admin @ platform = platform:manage
}
vocabulary customer { permission self:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at

subject operator { anchor platform; reach via grant impersonation; identifies sub; roles none }
subject staff    { anchor platform; reach descendants; identifies sub; roles configurable platform }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
subject customer { anchor project;  reach self; identifies customer_id; roles configurable customer; binds owner }

object record {
  table  records
  scoped tenant > project
  relation owner: customer via customer_id
  permission view = owner @rls maps select
}

// The app-defined containment/global template (the generic replacement for the
// removed settings/platform sugar): four @scoped CRUD permissions. On a
// global (virtual-leaf) object it composes to the platform-role branch.
template contained {
  permission view   = @scoped @rls maps select
  permission create = @scoped @rls maps insert
  permission edit   = @scoped @rls maps update
  permission delete = @scoped @rls maps delete
}

object admin_users {
  table  admin_users
  scoped platform
  use    contained
}
object tenants {
  table  tenants
  scoped platform
  use    contained
}
`

func TestPlatformPlane_GlobalObjectGovernedByPlatformRole(t *testing.T) {
	s, err := Parse(platformPlaneSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	byName := map[string]GenFn{}
	for _, d := range defs {
		byName[d.Name] = d
	}

	// (1) The platform-role definer is GENERATED, named has_<anchor>_role =
	//     has_platform_role (DELIBERATELY not the legacy is_platform_admin — the
	//     policy must read as a revocable role), takes only (user_id) (a root-plane
	//     role pins NO scope column), and resolves over the SAME role store as every
	//     other role, with every scope column NULL.
	plat, ok := byName["has_platform_role"]
	if !ok {
		t.Fatalf("no has_platform_role definer generated; got %v", keysOf(byName))
	}
	if plat.Sig != "user_id text" {
		t.Errorf("has_platform_role sig = %q, want a root-plane role (user_id text)", plat.Sig)
	}
	for _, want := range []string{
		"FROM role_assignments ra",
		"JOIN roles r",
		"ra.principal_kind = 'admin'",
		"ra.principal_id = user_id",
		"ra.tenant_id IS NULL",
		"ra.project_id IS NULL",
		"ra.revoked_at IS NULL",
		"r.key IN ('platform_admin')",
	} {
		if !strings.Contains(plat.Body, want) {
			t.Errorf("has_platform_role body missing %q:\n%s", want, plat.Body)
		}
	}
	// It is a REVOCABLE role, never a standing god-flag column read.
	if strings.Contains(plat.Body, "has_platform_role = ") || strings.Contains(plat.Body, "FROM admin_users") {
		t.Errorf("has_platform_role still reads a standing flag column, not the role store:\n%s", plat.Body)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	pol := map[string]Policy{}
	for _, p := range rls.Policies {
		pol[p.Name] = p
	}

	// (2) A global object's policy IS the platform-role branch — nothing else. No
	//     containment columns (there are none above tenancy), no `OR ()` empty
	//     block, no impersonation grant (the grant cascades DOWN, not up to a
	//     global table).
	au, ok := pol["admin_users_select"]
	if !ok {
		t.Fatalf("no admin_users_select policy; got %v", policyNames(rls))
	}
	wantBranch := "auth.has_platform_role((current_setting('request.jwt.claims', true)::json ->> 'sub'))"
	if au.Using != wantBranch {
		t.Errorf("admin_users_select USING = %q\nwant exactly the platform-role branch %q", au.Using, wantBranch)
	}
	if strings.Contains(au.Using, "tenant_id") || strings.Contains(au.Using, "impersonation_grants_reach") || strings.Contains(au.Using, "()") {
		t.Errorf("global object leaked containment / grant / empty-block:\n%s", au.Using)
	}
	// All four ops on a global object are the platform-role branch.
	for _, name := range []string{"admin_users_insert", "admin_users_update", "admin_users_delete", "tenants_select"} {
		p, ok := pol[name]
		if !ok {
			t.Fatalf("no %s policy; got %v", name, policyNames(rls))
		}
		pred := p.Using
		if pred == "" {
			pred = p.Check
		}
		if !strings.Contains(pred, "auth.has_platform_role(") {
			t.Errorf("%s should be governed by the platform role, got:\n%s", name, pred)
		}
	}

	// (3) FORWARD ISOLATION. A tenant-scoped object never gets the platform-role
	//     branch (the role is the schema-root plane, not a god-flag on every table);
	//     it still gets the scoped impersonation grant. The two planes don't bleed.
	rec, ok := pol["records_select"]
	if !ok {
		t.Fatalf("no records_select policy; got %v", policyNames(rls))
	}
	if strings.Contains(rec.Using, "has_platform_role") {
		t.Errorf("tenant-scoped record leaked the platform-role branch (has_platform_role is not a god-flag):\n%s", rec.Using)
	}
	if !strings.Contains(rec.Using, "auth.impersonation_grants_reach(") {
		t.Errorf("tenant-scoped record lost the scoped grant operator:\n%s", rec.Using)
	}
}

// A global object with NO platform-role subject must fail closed: there is no
// grant term, the containment block is empty, so nothing reaches the rows. The
// emitter must refuse (an unreachable policy is never silently a no-op), and
// Validate must surface it (V11 definer closure / uncompilable @rls).
func TestPlatformPlane_GlobalObjectWithoutRoleFailsClosed(t *testing.T) {
	const noStaff = `
topology {
  level platform virtual
  level tenant   parent platform
}
vocabulary admin { permission content:read  preset tenant_owner @ tenant = content:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
template contained {
  permission view   = @scoped @rls maps select
  permission create = @scoped @rls maps insert
  permission edit   = @scoped @rls maps update
  permission delete = @scoped @rls maps delete
}
object admin_users {
  table  admin_users
  scoped platform
  use    contained
}
`
	s, err := Parse(noStaff)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil {
		t.Fatal("a global object with no platform-role subject must not validate — it would emit an unreachable (or empty) policy")
	}
}

// The control-plane shapes (v3 WS6): mixed objects that compose the platform-staff
// plane with self/role/session — the realistic model of Foir's global tables, not
// the pure-staff shorthand. Proves: (P1) a `staff` term emits an UNGUARDED
// has_platform_role; (P2) an owner axis resolves on a GLOBAL object from the
// relation's type (admin_user_id = sub); (P3) one memberin definer serves both the
// tenant picker (caller, row.id) and admin_users co-tenant (row.id, session claim).
const controlPlaneSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read
  preset project_admin @ project = content:read
  preset tenant_owner  @ tenant  = content:read
  rank tenant_owner > project_admin
}
vocabulary platform {
  permission platform:manage
  preset platform_admin @ platform = platform:manage
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject staff { anchor platform; reach descendants; identifies sub; roles configurable platform }
subject admin { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }

object tenant {
  table  tenants
  level  tenant
  scoped tenant
  relation staff:         staff via role
  relation tenant_access: admin via memberin tenant(@sub, id)
  permission view = staff + tenant_access + @session  @rls maps select guard status <> "CHURNED"
  permission edit = staff                             @rls maps update
}
object admin_user {
  table  admin_users
  scoped platform
  relation staff:    staff via role
  relation self:     admin via id
  relation cotenant: admin via memberin tenant(id, @tenant_id)
  permission view = staff + self + cotenant @rls maps select
  permission edit = staff + self            @rls maps update
}
object admin_credential {
  table  admin_credentials
  scoped platform
  relation staff: staff via role
  relation owner: admin via admin_user_id
  permission view = staff + owner @rls maps select
}
`

func TestPlatformPlane_ControlPlaneShapes(t *testing.T) {
	s, err := Parse(controlPlaneSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	byName := map[string]GenFn{}
	for _, d := range defs {
		byName[d.Name] = d
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	pol := map[string]Policy{}
	for _, p := range rls.Policies {
		pol[p.Name] = p
	}

	// The one memberin definer, shared by both call directions.
	mi, ok := byName["admin_memberin_tenant"]
	if !ok {
		t.Fatalf("no admin_memberin_tenant definer; got %v", keysOf(byName))
	}
	if mi.Sig != "p_principal text, p_tenant text" {
		t.Errorf("memberin sig = %q", mi.Sig)
	}
	for _, want := range []string{"FROM role_assignments", "principal_id = p_principal", "tenant_id = p_tenant", "principal_kind = 'admin'", "revoked_at IS NULL"} {
		if !strings.Contains(mi.Body, want) {
			t.Errorf("memberin body missing %q:\n%s", want, mi.Body)
		}
	}

	subClaim := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"
	tenantClaim := "(current_setting('request.jwt.claims', true)::json ->> 'tenant_id')"

	// (P1) tenants: staff UNGUARDED; tenant_access + session GUARDED by CHURNED.
	tv := pol["tenants_select"].Using
	if !strings.Contains(tv, "auth.has_platform_role("+subClaim+")") {
		t.Errorf("tenants_select missing unguarded staff branch:\n%s", tv)
	}
	if strings.Contains(tv, "has_platform_role("+subClaim+") AND") {
		t.Errorf("staff branch must be UNGUARDED (staff sees CHURNED tenants):\n%s", tv)
	}
	if !strings.Contains(tv, "auth.admin_memberin_tenant("+subClaim+", id)") {
		t.Errorf("tenants_select missing tenant-access (caller, row.id):\n%s", tv)
	}
	// the membership + session branches must carry the CHURNED guard
	if !strings.Contains(tv, "CHURNED") {
		t.Errorf("tenants_select lost the CHURNED guard:\n%s", tv)
	}

	// (P3) admin_users: co-tenant is the SAME definer, args reversed (row.id, session).
	av := pol["admin_users_select"].Using
	if !strings.Contains(av, "auth.admin_memberin_tenant(id, "+tenantClaim+")") {
		t.Errorf("admin_users_select missing co-tenant (row.id, session claim):\n%s", av)
	}
	if !strings.Contains(av, "id = "+subClaim) {
		t.Errorf("admin_users_select missing self axis (id = sub):\n%s", av)
	}
	if !strings.Contains(av, "auth.has_platform_role("+subClaim+")") {
		t.Errorf("admin_users_select missing staff:\n%s", av)
	}

	// (P2) admin_credentials: owner axis on a GLOBAL object resolves the admin's
	//      claim from the relation type → admin_user_id = sub.
	cv := pol["admin_credentials_select"].Using
	if !strings.Contains(cv, "admin_user_id = "+subClaim) {
		t.Errorf("admin_credentials_select missing owner axis (admin_user_id = sub):\n%s", cv)
	}
	if !strings.Contains(cv, "auth.has_platform_role("+subClaim+")") {
		t.Errorf("admin_credentials_select missing staff:\n%s", cv)
	}
}

func policyNames(r *RLSResult) []string {
	out := make([]string, 0, len(r.Policies))
	for _, p := range r.Policies {
		out = append(out, p.Name)
	}
	return out
}
