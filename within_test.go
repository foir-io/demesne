package demesne

import (
	"strings"
	"testing"
)

const withinSpec = `
topology { level platform virtual level tenant parent platform level project parent tenant }
vocabulary v { permission a:b preset padmin @ project = a:b preset tadmin @ tenant = a:b rank tadmin > padmin }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin { anchor tenant reach descendants identifies sub roles configurable v binds admin }
object settings {
  table  settings
  scoped tenant
  relation tenant:  tenant  via tenant_id
  relation project: project via project_id
  permission view = tenant->owner
                  + (project->owner and @within(project))
                  + (@kind("service") and @within(project))
                  + (mode is_public = "true" and @within(project nullable))
                  @rls maps select
  permission remove = (project->owner and @within(project)) @rls maps delete
}
`

func TestWithin_SettingsShape(t *testing.T) {
	s := mustSpec(t, withinSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sel := findPolicy(rls, "settings_select")
	if sel == nil {
		t.Fatalf("no settings_select (unsupported: %v)", rls.Unsupported)
	}
	u := sel.Using
	sub := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"
	proj := "(current_setting('request.jwt.claims', true)::json ->> 'project_id')"

	if !strings.Contains(u, "auth.is_tenant_admin("+sub+", tenant_id)") {
		t.Errorf("missing 2-arg is_tenant_admin:\n%s", u)
	}
	if !strings.Contains(u, "auth.is_project_admin("+sub+", tenant_id, project_id)") {
		t.Errorf("missing 3-arg is_project_admin (walk arity fix):\n%s", u)
	}
	if !strings.Contains(u, "project_id = "+proj) {
		t.Errorf("missing @within(project) scope:\n%s", u)
	}
	if !strings.Contains(u, "(current_setting('request.jwt.claims', true)::json ->> 'kind') = 'service'") {
		t.Errorf("missing @kind service:\n%s", u)
	}
	if !strings.Contains(u, "is_public = 'true'") {
		t.Errorf("missing mode is_public:\n%s", u)
	}
	if !strings.Contains(u, "(project_id IS NULL OR project_id = "+proj+")") {
		t.Errorf("missing @within(project nullable) fallback:\n%s", u)
	}
	tclaim := "(current_setting('request.jwt.claims', true)::json ->> 'tenant_id')"
	if !strings.HasPrefix(u, "(tenant_id = "+tclaim+" AND (auth.is_tenant_admin") {
		t.Errorf("containment must be tenant-only, wrapping the per-branch block (project scope is per-branch via @within):\n%s", u)
	}
	if strings.Contains(u, tclaim+" AND project_id = ") {
		t.Errorf("project_id must NOT be in the uniform containment (it is per-branch):\n%s", u)
	}

	del := findPolicy(rls, "settings_delete")
	if del == nil || !strings.Contains(del.Using, "auth.is_project_admin("+sub+", tenant_id, project_id)") {
		t.Errorf("settings_delete should be tenant+project scoped project-admin: %v", del)
	}
}
