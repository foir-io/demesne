package demesne

import (
	"strings"
	"testing"
)

// A faithful subset of Foir's control plane: the platform/admin role planes, the
// impersonation grant, and the project + tenant level entities.
const structAccessorSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission c:r
  preset project_admin @ project = c:r
  preset tenant_owner  @ tenant  = *
  rank tenant_owner > project_admin
}
vocabulary platform { permission p:m  preset platform_admin @ platform = p:m }
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
subject operator { anchor platform reach via grant impersonation identifies sub roles none }
subject staff    { anchor platform reach descendants identifies sub roles configurable platform }
subject admin    { anchor tenant   reach descendants identifies sub roles configurable admin binds admin }
object project {
  table  projects
  level  project
  scoped tenant > project
  relation staff:  staff  via role
  relation tenant: tenant via tenant_id
  relation member: admin  via role
  permission view = staff + tenant->owner + member + @session @rls maps select
}
object tenant {
  table  tenants
  level  tenant
  scoped tenant
  relation staff:         staff via role
  relation tenant_access: admin via memberin tenant(@sub, id)
  permission view = staff + tenant_access + @session @rls maps select
}
`

// The structural Expand enumerator over the control plane: project/tenant get a
// <table>_accessors enumerating role-holders (ROLE), platform staff (STAFF), and
// active impersonation operators (IMPERSONATION) — the read-side dual of their
// SELECT predicates, with no owner/grant/visibility axes and no "everyone".
func TestStructuralAccessorEnumerator(t *testing.T) {
	proj := findAccessor(t, structAccessorSpec, "projects")

	if !strings.Contains(proj, "RETURNS TABLE(source text, principal_kind text, principal_id text, access text)") {
		t.Errorf("projects accessor not set-returning:\n%s", proj)
	}
	// STAFF — platform-role holders (NULL scope).
	if !strings.Contains(proj, "'staff'::text AS source") ||
		!strings.Contains(proj, "rr.key IN ('platform_admin')") {
		t.Errorf("missing staff branch:\n%s", proj)
	}
	// ROLE (tenant owner) — tenant-level role for the project's tenant.
	if !strings.Contains(proj, "ra.tenant_id = e.tenant_id AND ra.project_id IS NULL JOIN roles rr ON rr.id = ra.role_id AND rr.key IN ('tenant_owner')") {
		t.Errorf("missing tenant-owner role branch:\n%s", proj)
	}
	// ROLE (project member) — any project role for (tenant, this project id).
	if !strings.Contains(proj, "ra.tenant_id = e.tenant_id AND ra.project_id = e.id JOIN roles rr ON rr.id = ra.role_id AND rr.key IN ('project_admin')") {
		t.Errorf("missing project-member role branch:\n%s", proj)
	}
	// IMPERSONATION — active grants for the project's tenant.
	if !strings.Contains(proj, "'impersonation'::text") ||
		!strings.Contains(proj, "ig.tenant_id = e.tenant_id AND ig.revoked_at IS NULL AND ig.expires_at > now()") {
		t.Errorf("missing impersonation branch:\n%s", proj)
	}
	// No owner/grant/public concepts on the control plane.
	if strings.Contains(proj, "'owner'::text") || strings.Contains(proj, "'grant'::text") {
		t.Errorf("structural accessor must not have owner/grant branches:\n%s", proj)
	}
	// UNION (dedup), not UNION ALL.
	if strings.Contains(proj, "UNION ALL") {
		t.Errorf("structural accessor should UNION (dedup), not UNION ALL:\n%s", proj)
	}

	ten := findAccessor(t, structAccessorSpec, "tenants")
	// STAFF + impersonation for the tenant's own id + any-role-in-tenant (memberin,
	// no preset filter, project not NULL-pinned).
	if !strings.Contains(ten, "'staff'::text AS source") {
		t.Errorf("tenant missing staff branch:\n%s", ten)
	}
	if !strings.Contains(ten, "ig.tenant_id = e.id AND ig.revoked_at IS NULL") {
		t.Errorf("tenant missing impersonation branch:\n%s", ten)
	}
	if !strings.Contains(ten, "ra.tenant_id = e.id\n    WHERE e.id = p_id") {
		t.Errorf("tenant missing any-role memberin branch (project not NULL-pinned):\n%s", ten)
	}
}
