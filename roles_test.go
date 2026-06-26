package demesne

import (
	"strings"
	"testing"
)

func rolesOf(e EffectiveRoles) []string { return e.Roles() }

func TestResolveRoles_ScopedAndPlane(t *testing.T) {
	asg := []RoleAssignment{
		{Scope: []string{"t1", ""}, RoleKey: "tenant_owner"},
		{Scope: []string{"t1", "p1"}, RoleKey: "project_admin"},
		{Scope: []string{"", ""}, RoleKey: "platform_admin"},
	}
	cases := []struct {
		name  string
		scope []string
		want  []string
	}{
		{"own project", []string{"t1", "p1"}, []string{"platform_admin", "project_admin", "tenant_owner"}},
		{"sibling project keeps tenant + plane", []string{"t1", "p2"}, []string{"platform_admin", "tenant_owner"}},
		{"foreign tenant keeps only plane", []string{"t2", "p9"}, []string{"platform_admin"}},
		{"no current scope keeps only plane", []string{"", ""}, []string{"platform_admin"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rolesOf(ResolveRoles(asg, c.scope))
			if !equalSet(got, c.want) {
				t.Errorf("ResolveRoles(%v) = %v, want %v", c.scope, got, c.want)
			}
		})
	}
}

func TestResolveRoles_FailClosed(t *testing.T) {
	if got := rolesOf(ResolveRoles(nil, []string{"t1", "p1"})); len(got) != 0 {
		t.Errorf("nil assignments: want no membership, got %v", got)
	}
	empties := []RoleAssignment{
		{Scope: []string{"t1", "p1"}, RoleKey: ""},
		{Scope: []string{"t9", ""}, RoleKey: "tenant_owner"},
	}
	got := rolesOf(ResolveRoles(empties, []string{"t1", "p1"}))
	if len(got) != 0 {
		t.Errorf("empty key skipped + out-of-scope role: want no membership, got %v", got)
	}
	if ResolveRoles(empties, []string{"t1", "p1"}).Holds("tenant_owner") {
		t.Error("out-of-scope tenant_owner must not be held")
	}
}

func TestNewEffectiveRoles(t *testing.T) {
	e := NewEffectiveRoles("platform_admin", "", "tenant_owner")
	if !e.Holds("platform_admin") || !e.Holds("tenant_owner") {
		t.Errorf("constructed set missing a key: %v", e.Roles())
	}
	if e.Holds("") || e.Holds("ws_editor") {
		t.Errorf("set should not hold empty or absent keys: %v", e.Roles())
	}
	if got := e.Roles(); !equalSet(got, []string{"platform_admin", "tenant_owner"}) {
		t.Errorf("Roles() = %v", got)
	}
	if (EffectiveRoles{}).Holds("anything") {
		t.Error("zero-value EffectiveRoles must fail closed")
	}
}

const roleTierSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read
  permission content:write
  preset project_admin @ project = content:read + content:write
  preset tenant_owner  @ tenant  = *
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
object record {
  table  records
  scoped tenant > project
  relation owner: admin via owner_id
  permission view = owner @rls maps select
}
`

func TestEmitFramework_RoleTier(t *testing.T) {
	s := mustValidSpec(t, roleTierSpec)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"func RoleTiers(held demesne.EffectiveRoles) RoleSet",
		"PlatformAdmin bool",
		"ProjectAdmin  bool",
		"TenantOwner   bool",
		`PlatformAdmin: held.Holds("platform_admin"),`,
		`ProjectAdmin:  held.Holds("project_admin"),`,
		`TenantOwner:   held.Holds("tenant_owner"),`,
		"func HoldsRoles(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectiveRoles, error)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("Go role tier missing %q", want)
		}
	}

	tsSrc, err := s.EmitFrameworkTS()
	if err != nil {
		t.Fatalf("EmitFrameworkTS: %v", err)
	}
	for _, want := range []string{
		"export function roleTiers(held: EffectiveRoles) {",
		`platformAdmin: held.holds("platform_admin"),`,
		`projectAdmin: held.holds("project_admin"),`,
		`tenantOwner: held.holds("tenant_owner"),`,
		"export async function holdsRoles(q: Querier, principalId: string, scope: string[]): Promise<EffectiveRoles> {",
	} {
		if !strings.Contains(tsSrc, want) {
			t.Errorf("TS role tier missing %q", want)
		}
	}

	plat := strings.Index(src, `PlatformAdmin: held.Holds("platform_admin")`)
	scoped := strings.Index(src, `ProjectAdmin:  held.Holds("project_admin")`)
	if plat < 0 || scoped < 0 || plat > scoped {
		t.Errorf("platform-plane role must precede scoped roles (plat=%d scoped=%d)", plat, scoped)
	}
}

const governedRolesSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read
  permission content:write
  preset project_admin @ project = content:read + content:write
  preset tenant_owner  @ tenant  = *
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
object roles {
  table  roles
  scoped tenant > project
  relation owner: admin via owner_id
  permission view = owner @rls maps select
  permission edit = owner @rls maps update
}
`

func TestEmitFramework_GovernedRolesObjectCompiles(t *testing.T) {
	s := mustValidSpec(t, governedRolesSpec)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"var Roles = rolesAccess{}",
		"func RoleTiers(held demesne.EffectiveRoles) RoleSet",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("a governed `roles` object and the role-tier accessor must coexist; missing %q", want)
		}
	}
	tsSrc, err := s.EmitFrameworkTS()
	if err != nil {
		t.Fatalf("EmitFrameworkTS: %v", err)
	}
	for _, want := range []string{
		"export const roles = {",
		"export function roleTiers(held: EffectiveRoles) {",
	} {
		if !strings.Contains(tsSrc, want) {
			t.Errorf("TS: a governed `roles` object and roleTiers must coexist; missing %q", want)
		}
	}
	if testing.Short() {
		t.Skip("-short: skipping the go-build compile proof")
	}
	if out, ok := buildFrameworkModule(t, src); !ok {
		t.Fatalf("framework governing a `roles` object does not compile:\n%s\n--- generated ---\n%s", out, src)
	}
}

const governedCheckSpec = `
topology { level tenant }
vocabulary v {
  permission a:read
  preset viewer @ tenant = a:read
}
rolestore v {
  assignments role_assignments
  kind        principal_kind = "x"
  subject     principal_id
  scope       tenant_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject u { anchor tenant; reach descendants; identifies sub; roles configurable v; binds admin }
object check {
  table  checks
  scoped tenant
  relation owner: u via owner_id
  permission view = owner @rls maps select
}
`

func TestEmitFramework_ReservedNameCollisionFires(t *testing.T) {
	s := mustValidSpec(t, governedCheckSpec)
	_, err := s.EmitFramework("authz")
	if err == nil {
		t.Fatal("Go emit must fail closed: object `check` collides with the generated Check helper")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("error should name the collision, got: %v", err)
	}
	if _, tsErr := s.EmitFrameworkTS(); tsErr == nil {
		t.Fatal("TS emit must fail closed for the `check` collision too")
	}
}

func TestEmitFramework_NoRoleTierWhenNoPresets(t *testing.T) {
	const spec = `
topology { level tenant }
vocabulary v { permission a:read }
subject u { anchor tenant reach self identifies sub roles none }
object note { table notes scoped tenant relation o: u via owner_id permission view = o @rls maps select }
`
	s := mustValidSpec(t, spec)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	if strings.Contains(src, "type RoleSet struct") || strings.Contains(src, "func RoleTiers(") {
		t.Errorf("a spec with no rolestore/presets must emit no role tier:\n%s", src)
	}
}
