package demesne

import (
	"strings"
	"testing"
)

const memberinReachedBySpec = `
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
object admin_user {
  table  admin_users
  scoped platform
  relation staff:       staff via role
  relation self:        admin via id
  relation dir_tenant:  admin via memberin tenant(id, @tenant_id) reachedby
  relation dir_project: admin via memberin project(id, @project_id) reachedby
  permission view = staff + self + dir_tenant + dir_project @rls maps select
}
`

func TestMemberinReachedBy(t *testing.T) {
	s, err := Parse(memberinReachedBySpec)
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
	haveDef := map[string]bool{}
	for _, d := range defs {
		haveDef[d.Name] = true
	}
	for _, want := range []string{
		"admin_memberin_tenant", "admin_memberin_project",
		"is_tenant_admin", "is_project_admin",
	} {
		if !haveDef[want] {
			t.Errorf("reachedby needs definer %q but it was not emitted (have: %v)", want, reachDefKeys(haveDef))
		}
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	var sel string
	for _, p := range rls.Policies {
		if p.Name == "admin_users_select" {
			sel = p.Using
		}
	}
	if sel == "" {
		t.Fatalf("no admin_user_select policy (policies: %v)", policyNames(rls))
	}

	// The tenant directory term must AND the target-membership with the caller's
	// tenant reach; the project term likewise at project scope.
	for _, want := range []string{
		"admin_memberin_tenant",
		"is_tenant_admin",
		"admin_memberin_project",
		"is_project_admin",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("admin_user_select missing %q\n  using: %s", want, sel)
		}
	}
	if !strings.Contains(sel, "admin_memberin_tenant") || !strings.Contains(sel, " AND ") {
		t.Errorf("reachedby did not AND the reach gate onto memberin:\n  %s", sel)
	}
}

func reachDefKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
