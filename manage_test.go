package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func manageSpecSrc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "manage.demesne"))
	if err != nil {
		t.Fatalf("read examples/manage.demesne: %v", err)
	}
	return string(src)
}

func manageSpec(t *testing.T) *Spec {
	t.Helper()
	s, err := Parse(manageSpecSrc(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

func manageVocab(t *testing.T) *Vocabulary {
	t.Helper()
	v := manageSpec(t).vocabByName("admin")
	if v == nil {
		t.Fatal("vocabulary admin not found")
	}
	return v
}

func TestImplies_Parse(t *testing.T) {
	v := manageVocab(t)
	if len(v.Implications) != 3 {
		t.Fatalf("got %d implications, want 3: %+v", len(v.Implications), v.Implications)
	}
	star := v.Implications[0]
	if star.Perm != "platform:manage" || !star.Star || len(star.Set) != 0 {
		t.Errorf("platform:manage = %+v, want star", star)
	}
	tenant := v.Implications[1]
	if tenant.Perm != "tenant:manage" || tenant.Star {
		t.Errorf("tenant:manage = %+v, want an explicit list", tenant)
	}
	if !equalSet(tenant.Set, []string{"project:manage", "billing:*", "invitations:*"}) {
		t.Errorf("tenant:manage set = %v", tenant.Set)
	}
	if !equalSet(v.Implications[2].Set, []string{"records:*", "content:*"}) {
		t.Errorf("project:manage set = %v", v.Implications[2].Set)
	}
}

func TestImplies_ParseRejectsBadItem(t *testing.T) {
	bad := strings.Replace(manageSpecSrc(t), "implies project:manage, billing:*", "implies manage", 1)
	_, err := Parse(bad)
	if err == nil || !strings.Contains(err.Error(), "comma-separated list of permission keys") {
		t.Errorf("expected a parse error naming the implies list form, got %v", err)
	}
}

func TestImplies_Closure(t *testing.T) {
	v := manageVocab(t)
	cases := []struct {
		perm string
		want []string
	}{
		{"platform:manage", []string{
			"platform:manage", "tenant:manage", "project:manage",
			"billing:read", "billing:write", "invitations:read", "invitations:write",
			"records:read", "records:write", "content:read", "content:publish",
		}},
		{"tenant:manage", []string{
			"tenant:manage", "project:manage",
			"billing:read", "billing:write", "invitations:read", "invitations:write",
			"records:read", "records:write", "content:read", "content:publish",
		}},
		{"project:manage", []string{
			"project:manage", "records:read", "records:write", "content:read", "content:publish",
		}},
		{"records:read", []string{"records:read"}},
		{"billing:write", []string{"billing:write"}},
	}
	for _, c := range cases {
		got, err := v.ImpliedPermissions(c.perm)
		if err != nil {
			t.Fatalf("%s: %v", c.perm, err)
		}
		if !equalSet(got, c.want) {
			t.Errorf("%s closure:\n got %v\nwant %v", c.perm, got, c.want)
		}
	}
}

func TestImplies_KeyIsTheCeiling(t *testing.T) {
	v := manageVocab(t)
	project, err := v.ImpliedPermissions("project:manage")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"billing:read", "billing:write", "invitations:read", "invitations:write", "tenant:manage", "platform:manage"} {
		if contains(project, forbidden) {
			t.Errorf("project:manage must not confer %q — the key is the ceiling, not the assignment scope", forbidden)
		}
	}
	tenant, err := v.ImpliedPermissions("tenant:manage")
	if err != nil {
		t.Fatal(err)
	}
	if contains(tenant, "platform:manage") {
		t.Error("tenant:manage must not confer platform:manage — implication runs downward only")
	}
}

func TestImplies_Cyclic(t *testing.T) {
	v := &Vocabulary{
		Name:        "v",
		Permissions: []string{"a:manage", "b:manage"},
		Implications: []*Implication{
			{Perm: "a:manage", Set: []string{"b:manage"}},
			{Perm: "b:manage", Set: []string{"a:manage"}},
		},
	}
	_, err := v.ImpliedPermissions("a:manage")
	if err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("expected a cyclic error, got %v", err)
	}
	self := &Vocabulary{
		Name:         "v",
		Permissions:  []string{"a:manage"},
		Implications: []*Implication{{Perm: "a:manage", Set: []string{"a:manage"}}},
	}
	if _, err := self.ImpliedPermissions("a:manage"); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("expected a self-cyclic error, got %v", err)
	}
}

func TestImplies_UnknownTarget(t *testing.T) {
	v := &Vocabulary{
		Name:         "v",
		Permissions:  []string{"a:manage"},
		Implications: []*Implication{{Perm: "a:manage", Set: []string{"ghost:read"}}},
	}
	_, err := v.ImpliedPermissions("a:manage")
	if err == nil || !strings.Contains(err.Error(), "neither a permission") {
		t.Errorf("expected an unknown-target error, got %v", err)
	}
	wild := &Vocabulary{
		Name:         "v",
		Permissions:  []string{"a:manage"},
		Implications: []*Implication{{Perm: "a:manage", Set: []string{"ghost:*"}}},
	}
	if _, err := wild.ImpliedPermissions("a:manage"); err == nil {
		t.Error("a wildcard matching no permission must fail, not silently confer nothing")
	}
}

func TestImplies_ValidateReportsCycle(t *testing.T) {
	src := strings.Replace(manageSpecSrc(t),
		"permission records:read", "permission records:read implies tenant:manage", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("Validate must reject an implication cycle, got %v", err)
	}
}

func TestManage_ResolveMatrix(t *testing.T) {
	r, err := manageSpec(t).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	platform := []RoleAssignment{{Scope: []string{"", ""}, Permissions: []string{"platform:manage"}}}
	tenantT1 := []RoleAssignment{{Scope: []string{"T1", ""}, Permissions: []string{"tenant:manage"}}}
	projectT1P1 := []RoleAssignment{{Scope: []string{"T1", "P1"}, Permissions: []string{"project:manage"}}}
	projectAtTenant := []RoleAssignment{{Scope: []string{"T1", ""}, Permissions: []string{"project:manage"}}}

	cases := []struct {
		name  string
		asg   []RoleAssignment
		scope []string
		want  []string
	}{
		{"platform manage reaches an arbitrary tenant/project", platform, []string{"T9", "P9"},
			[]string{"platform:manage", "tenant:manage", "project:manage", "billing:read", "billing:write",
				"invitations:read", "invitations:write", "records:read", "records:write", "content:read", "content:publish"}},
		{"tenant manage reaches its own projects", tenantT1, []string{"T1", "P1"},
			[]string{"tenant:manage", "project:manage", "billing:read", "billing:write",
				"invitations:read", "invitations:write", "records:read", "records:write", "content:read", "content:publish"}},
		{"tenant manage does not reach another tenant", tenantT1, []string{"T2", "P1"}, nil},
		{"project manage is bounded to its project", projectT1P1, []string{"T1", "P1"},
			[]string{"project:manage", "records:read", "records:write", "content:read", "content:publish"}},
		{"project manage does not reach a sibling project", projectT1P1, []string{"T1", "P2"}, nil},
		{"project manage at tenant scope spans the tenant's projects but keeps its ceiling", projectAtTenant, []string{"T1", "P7"},
			[]string{"project:manage", "records:read", "records:write", "content:read", "content:publish"}},
		{"project manage at tenant scope still does not cross tenants", projectAtTenant, []string{"T2", "P7"}, nil},
	}
	for _, c := range cases {
		eff, err := r.Resolve(c.asg, c.scope)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := eff.Permissions()
		if len(c.want) == 0 {
			if len(got) != 0 {
				t.Errorf("%s: got %v want none", c.name, got)
			}
			continue
		}
		if !equalSet(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.name, got, c.want)
		}
	}
}

func TestManage_RootScopeIsGlobalNotExact(t *testing.T) {
	r, err := manageSpec(t).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	global := []RoleAssignment{{Scope: []string{"", ""}, Permissions: []string{"records:read"}}}
	for _, q := range [][]string{{"T1", "P1"}, {"T2", "P9"}, {"", ""}} {
		eff, err := r.Resolve(global, q)
		if err != nil {
			t.Fatal(err)
		}
		if !eff.Holds("records:read") {
			t.Errorf("a NULL-root assignment must reach %v", q)
		}
	}
	pinned := []RoleAssignment{{Scope: []string{"T1", ""}, Permissions: []string{"records:read"}}}
	for _, q := range [][]string{{"T2", "P1"}, {"", ""}} {
		eff, err := r.Resolve(pinned, q)
		if err != nil {
			t.Fatal(err)
		}
		if eff.Holds("records:read") {
			t.Errorf("a tenant-pinned assignment must NOT reach %v", q)
		}
	}
}

func manageDefiner(t *testing.T, name string) GenFn {
	t.Helper()
	defs, err := manageSpec(t).EmitDefiners()
	if err != nil {
		t.Fatalf("EmitDefiners: %v", err)
	}
	for _, d := range defs {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("definer %q not emitted; got %d definers", name, len(defs))
	return GenFn{}
}

func TestManage_SQLSurface(t *testing.T) {
	hasPerm := manageDefiner(t, "member_has_perm")
	wantSig := "user_id text, check_tenant_id text, check_project_id text, p_perm text"
	if hasPerm.Sig != wantSig {
		t.Errorf("signature:\n got %s\nwant %s", hasPerm.Sig, wantSig)
	}
	for _, col := range []string{"tenant_id", "project_id"} {
		want := "(ra." + col + " IS NULL OR ra." + col + " = check_"
		if !strings.Contains(hasPerm.Body, want) {
			t.Errorf("scope level %q is not wildcard-on-NULL — platform scope cannot exist:\n%s", col, hasPerm.Body)
		}
		if strings.Contains(hasPerm.Body, "AND ra."+col+" = check_") {
			t.Errorf("scope level %q is pinned exact:\n%s", col, hasPerm.Body)
		}
	}
	if !strings.Contains(hasPerm.Body, "r.permissions::text[] && auth.member_perm_implied_by(p_perm)") {
		t.Errorf("the permission test does not consult the implication closure:\n%s", hasPerm.Body)
	}

	impliedBy := manageDefiner(t, "member_perm_implied_by")
	if impliedBy.Returns != "text[]" || impliedBy.Sig != "p_perm text" {
		t.Errorf("perm_implied_by signature: %s -> %s", impliedBy.Sig, impliedBy.Returns)
	}
	if !strings.HasSuffix(impliedBy.Body, "ARRAY[p_perm]::text[])") {
		t.Errorf("a permission outside the vocabulary must fall back to itself:\n%s", impliedBy.Body)
	}
	wantRows := []string{
		"('platform:manage', ARRAY['platform:manage']::text[])",
		"('tenant:manage', ARRAY['platform:manage', 'tenant:manage']::text[])",
		"('project:manage', ARRAY['platform:manage', 'project:manage', 'tenant:manage']::text[])",
		"('records:read', ARRAY['platform:manage', 'project:manage', 'records:read', 'tenant:manage']::text[])",
		"('billing:read', ARRAY['billing:read', 'platform:manage', 'tenant:manage']::text[])",
		"('content:publish', ARRAY['content:publish', 'platform:manage', 'project:manage', 'tenant:manage']::text[])",
	}
	for _, row := range wantRows {
		if !strings.Contains(impliedBy.Body, row) {
			t.Errorf("reverse closure row missing:\n want %s\n body %s", row, impliedBy.Body)
		}
	}
	if strings.Contains(impliedBy.Body, "('billing:read', ARRAY['billing:read', 'platform:manage', 'project:manage'") {
		t.Error("project:manage must not appear in billing:read's reverse closure")
	}
}

func TestManage_NoImplicationsEmitsTheUnchangedCondition(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("EmitDefiners: %v", err)
	}
	for _, d := range defs {
		if strings.HasSuffix(d.Name, "_perm_implied_by") {
			t.Errorf("a vocabulary without implications must not emit %s", d.Name)
		}
		if d.Name != "member_has_perm" {
			continue
		}
		if !strings.Contains(d.Body, "p_perm = ANY(r.perms)") {
			t.Errorf("a vocabulary without implications must keep the direct membership test:\n%s", d.Body)
		}
	}
}

func TestManage_GlobalAssignmentsAudit(t *testing.T) {
	r, err := manageSpec(t).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	want := "SELECT ra.user_id, r.key, ra.tenant_id, ra.project_id FROM role_assignments ra " +
		"JOIN roles r ON r.id = ra.role_id WHERE ra.principal_kind = 'user' AND ra.revoked_at IS NULL " +
		"AND ra.tenant_id IS NULL ORDER BY 1, 2"
	if got := r.GlobalAssignmentsSQL(); got != want {
		t.Errorf("GlobalAssignmentsSQL:\n got: %s\nwant: %s", got, want)
	}
}
