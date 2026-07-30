package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planesSpecSrc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "planes.demesne"))
	if err != nil {
		t.Fatalf("read examples/planes.demesne: %v", err)
	}
	return string(src)
}

func planesSpec(t *testing.T) *Spec {
	t.Helper()
	s, err := Parse(planesSpecSrc(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

func definersByName(t *testing.T, s *Spec) map[string]GenFn {
	t.Helper()
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	out := map[string]GenFn{}
	for _, d := range defs {
		out[d.Name] = d
	}
	return out
}

func TestPlane_HoldsResolvesToTheVocabularysRolestore(t *testing.T) {
	s := planesSpec(t)

	rs, err := s.holdsRoleStore("platform:manage")
	if err != nil {
		t.Fatalf("holdsRoleStore(platform:manage): %v", err)
	}
	if rs.Name != "platform" {
		t.Errorf("platform:manage resolved to rolestore %q, want platform", rs.Name)
	}
	rs, err = s.holdsRoleStore("content:read")
	if err != nil {
		t.Fatalf("holdsRoleStore(content:read): %v", err)
	}
	if rs.Name != "admin" {
		t.Errorf("content:read resolved to rolestore %q, want admin", rs.Name)
	}

	byName := definersByName(t, s)
	if _, ok := byName["platform_has_perm"]; !ok {
		t.Fatalf("no platform_has_perm definer; got %v", keysOf(byName))
	}
	if _, ok := byName["operator_has_perm"]; !ok {
		t.Fatalf("no operator_has_perm definer; got %v", keysOf(byName))
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	pol := map[string]Policy{}
	for _, p := range rls.Policies {
		pol[p.Name] = p
	}
	if got := pol["tenants_select"].Using; !strings.Contains(got, "auth.platform_has_perm(") || strings.Contains(got, "operator_has_perm") {
		t.Errorf("tenants_select must route through the platform rolestore:\n%s", got)
	}
	if got := pol["documents_select"].Using; !strings.Contains(got, "auth.operator_has_perm(") || strings.Contains(got, "platform_has_perm") {
		t.Errorf("documents_select must route through the admin rolestore:\n%s", got)
	}
}

func TestPlane_FloorPinsOffPlaneScopeColumnsNull(t *testing.T) {
	byName := definersByName(t, planesSpec(t))

	plat := byName["platform_has_perm"]
	if plat.Sig != "user_id text, p_perm text" {
		t.Errorf("platform_has_perm takes scope arguments (%q) — a global plane answers no scope question", plat.Sig)
	}
	for _, want := range []string{
		"ra.tenant_id IS NULL",
		"ra.project_id IS NULL",
		"ra.principal_kind = 'admin'",
		"ra.principal_id = user_id",
		"ra.revoked_at IS NULL",
		"p_perm = ANY(r.permissions)",
	} {
		if !strings.Contains(plat.Body, want) {
			t.Errorf("platform_has_perm body missing %q — an assignment scoped below the plane would satisfy it:\n%s", want, plat.Body)
		}
	}
	if strings.Contains(plat.Body, "ra.tenant_id IS NULL OR") || strings.Contains(plat.Body, "ra.project_id IS NULL OR") {
		t.Errorf("platform_has_perm pins its off-plane columns with a wildcard, not a NULL test:\n%s", plat.Body)
	}
	if strings.Contains(plat.Body, "r.key IN (") {
		t.Errorf("platform_has_perm still matches role keys instead of held permissions:\n%s", plat.Body)
	}

	admin := byName["operator_has_perm"]
	if admin.Sig != "user_id text, check_tenant_id text, check_project_id text, p_perm text" {
		t.Errorf("the scoped rolestore's definer changed shape: %q", admin.Sig)
	}
	for _, want := range []string{
		"(ra.tenant_id IS NULL OR ra.tenant_id = check_tenant_id)",
		"(ra.project_id IS NULL OR ra.project_id = check_project_id)",
	} {
		if !strings.Contains(admin.Body, want) {
			t.Errorf("operator_has_perm lost its scope-relative matching (%q):\n%s", want, admin.Body)
		}
	}
}

func TestPlane_ScopedAssignmentCannotHoldPlatformAuthority(t *testing.T) {
	s := planesSpec(t)
	r, err := s.HoldsResolver("platform")
	if err != nil {
		t.Fatalf("HoldsResolver(platform): %v", err)
	}
	if r.PlaneDepth != 0 || r.Plane != "platform" {
		t.Fatalf("platform resolver plane = %q depth = %d, want platform/0", r.Plane, r.PlaneDepth)
	}

	global := []RoleAssignment{{Scope: []string{"", ""}, RoleKey: "platform_admin", Permissions: []string{"platform:manage"}}}
	scoped := map[string][]RoleAssignment{
		"tenant-scoped":  {{Scope: []string{"T1", ""}, RoleKey: "platform_admin", Permissions: []string{"platform:manage"}}},
		"project-scoped": {{Scope: []string{"T1", "P1"}, RoleKey: "platform_admin", Permissions: []string{"platform:manage"}}},
	}
	queries := [][]string{nil, {"", ""}, {"T1", ""}, {"T1", "P1"}, {"T2", "P2"}}

	for _, q := range queries {
		eff, err := r.Resolve(global, q)
		if err != nil {
			t.Fatalf("resolve global at %v: %v", q, err)
		}
		if !eff.Holds("platform:manage") {
			t.Errorf("a globally scoped assignment must confer platform:manage at query scope %v", q)
		}
	}
	for name, asg := range scoped {
		for _, q := range queries {
			eff, err := r.Resolve(asg, q)
			if err != nil {
				t.Fatalf("resolve %s at %v: %v", name, q, err)
			}
			if eff.Holds("platform:manage") {
				t.Errorf("a %s assignment held platform:manage at query scope %v — platform authority must be unreachable from a scoped row", name, q)
			}
		}
	}

	sql := r.AssignmentsSQL()
	for _, want := range []string{"ra.tenant_id IS NULL", "ra.project_id IS NULL"} {
		if !strings.Contains(sql, want) {
			t.Errorf("AssignmentsSQL does not restrict the fetch to the plane (%q):\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "SELECT ra.tenant_id") {
		t.Errorf("AssignmentsSQL selects a pinned scope column, which is always NULL:\n%s", sql)
	}
}

func TestPlane_ScopedRolestoreKeepsScopeRelativeReach(t *testing.T) {
	s := planesSpec(t)
	r, err := s.HoldsResolver("admin")
	if err != nil {
		t.Fatalf("HoldsResolver(admin): %v", err)
	}
	if r.Plane != "" || r.PlaneDepth != 2 {
		t.Fatalf("admin resolver plane = %q depth = %d, want no plane at full depth", r.Plane, r.PlaneDepth)
	}
	asg := []RoleAssignment{{Scope: []string{"T1", ""}, RoleKey: "tenant_owner", Permissions: []string{"content:read"}}}
	if eff, _ := r.Resolve(asg, []string{"T1", "P9"}); !eff.Holds("content:read") {
		t.Error("a tenant-wide admin assignment must still reach every project under it")
	}
	if eff, _ := r.Resolve(asg, []string{"T2", "P1"}); eff.Holds("content:read") {
		t.Error("a tenant-pinned admin assignment must not cross tenants")
	}
}

func TestPlane_StarPresetCannotCrossVocabularies(t *testing.T) {
	s := planesSpec(t)
	admin := s.vocabByName("admin")
	if admin == nil {
		t.Fatal("no admin vocabulary")
	}
	perms, err := admin.PresetPermissions("tenant_owner")
	if err != nil {
		t.Fatalf("PresetPermissions(tenant_owner): %v", err)
	}
	if contains(perms, "platform:manage") {
		t.Fatalf("`preset tenant_owner @ tenant = *` reached outside its vocabulary: %v", perms)
	}
	r, err := s.HoldsResolver("platform")
	if err != nil {
		t.Fatal(err)
	}
	asg := []RoleAssignment{{Scope: []string{"", ""}, RoleKey: "tenant_owner", Permissions: perms}}
	if eff, _ := r.Resolve(asg, nil); eff.Holds("platform:manage") {
		t.Errorf("a star-expanded tenant_owner held platform:manage: %v", eff.Permissions())
	}
}

func planeParse(t *testing.T, src string) error {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		return err
	}
	return Validate(s)
}

func TestPlane_UnknownPlaneRejected(t *testing.T) {
	src := strings.Replace(planesSpecSrc(t), "  plane       platform\n", "  plane       nowhere\n", 1)
	err := planeParse(t, src)
	if err == nil || !strings.Contains(err.Error(), "not a topology level") {
		t.Fatalf("expected an unknown-plane rejection, got %v", err)
	}
}

func TestPlane_PlaneWithUnnamedLevelsBelowRejected(t *testing.T) {
	src := strings.Replace(planesSpecSrc(t),
		"  scope       tenant_id project_id\n  plane       platform\n",
		"  scope       tenant_id\n  plane       platform\n", 1)
	err := planeParse(t, src)
	if err == nil || !strings.Contains(err.Error(), "must be named so the floor can pin it NULL") {
		t.Fatalf("a plane that cannot pin every level below it must be rejected, got %v", err)
	}
}

func TestPlane_HoldsOnAGlobalObjectStillNeedsAGlobalPlane(t *testing.T) {
	src := strings.Replace(planesSpecSrc(t), "  plane       platform\n", "", 1)
	err := planeParse(t, src)
	if err == nil || !strings.Contains(err.Error(), "uses @holds on a global object") {
		t.Fatalf("without a plane the global object must fail closed, got %v", err)
	}
}

const ambiguousPermSpec = `
topology { level tenant  level project parent tenant }
vocabulary a {
  permission shared:verb
  preset ap @ tenant = shared:verb
}
vocabulary b {
  permission shared:verb
  preset bp @ tenant = shared:verb
}
rolestore a { assignments ra kind k = "a" subject pid scope tenant_id project_id rolejoin role_id roles id key revoked rv permissions perms }
rolestore b { assignments rb kind k = "b" subject pid scope tenant_id project_id rolejoin role_id roles id key revoked rv permissions perms }
subject sa { anchor tenant reach descendants identifies sub  roles configurable a binds admin }
subject sb { anchor tenant reach descendants identifies bsub roles configurable b binds owner }
object doc {
  table docs
  scoped tenant > project
  permission view = @holds(shared:verb) @rls maps select
}
`

func TestPlane_AmbiguousPermissionRejected(t *testing.T) {
	err := planeParse(t, ambiguousPermSpec)
	if err == nil || !strings.Contains(err.Error(), "declared by more than one vocabulary") {
		t.Fatalf("a permission in two vocabularies must not silently pick a rolestore, got %v", err)
	}
}

func TestPlane_PermissionInNoVocabularyRejected(t *testing.T) {
	src := strings.Replace(ambiguousPermSpec, "vocabulary b {\n  permission shared:verb", "vocabulary b {\n  permission other:verb", 1)
	src = strings.Replace(src, "preset bp @ tenant = shared:verb", "preset bp @ tenant = other:verb", 1)
	src = strings.Replace(src, "@holds(shared:verb)", "@holds(ghost:verb)", 1)
	err := planeParse(t, src)
	if err == nil || !strings.Contains(err.Error(), "declared by no vocabulary") {
		t.Fatalf("an undeclared permission must not resolve to a rolestore, got %v", err)
	}
}

func TestPlane_SingleRolestoreKeepsTheDefault(t *testing.T) {
	s, err := Parse(hardeningSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rs, err := s.holdsRoleStore("totally:unknown")
	if err != nil {
		t.Fatalf("with one rolestore @holds must resolve to it regardless of the vocabulary: %v", err)
	}
	if rs != s.RoleStores[0] {
		t.Errorf("single-rolestore resolution picked %q, not the declared rolestore", rs.Name)
	}
}

func TestPlane_CollidingHoldsDefinersRejected(t *testing.T) {
	src := strings.Replace(planesSpecSrc(t), "rolestore platform {", "rolestore operator {", 1)
	src = strings.Replace(src, "vocabulary platform {", "vocabulary operator {", 1)
	src = strings.Replace(src, "  roles      configurable admin\n", "  roles      configurable admin\n", 1)
	err := planeParse(t, src)
	if err == nil || !strings.Contains(err.Error(), "both compile their @holds check to") {
		t.Fatalf("two rolestores sharing a definer name must be rejected, got %v", err)
	}
}

const unbackedVocabSpec = `
topology { level tenant  level project parent tenant }
vocabulary a {
  permission shared:verb
  preset ap @ tenant = shared:verb
}
vocabulary b {
  permission other:verb
  preset bp @ tenant = other:verb
}
vocabulary c {
  permission shared:verb
  preset cp @ tenant = shared:verb
}
rolestore a { assignments ra kind k = "a" subject pid scope tenant_id project_id rolejoin role_id roles id key revoked rv permissions perms }
rolestore b { assignments rb kind k = "b" subject pid scope tenant_id project_id rolejoin role_id roles id key revoked rv permissions perms }
subject sa { anchor tenant reach descendants identifies sub  roles configurable a binds admin }
subject sb { anchor tenant reach descendants identifies bsub roles configurable b binds owner }
object doc {
  table docs
  scoped tenant > project
  permission view = @holds(shared:verb) @rls maps select
}
`

func TestPlane_VocabularyBackingNoRolestoreCannotMakeAPermissionAmbiguous(t *testing.T) {
	s, err := Parse(unbackedVocabSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("a vocabulary that backs no rolestore names no candidate and must not make @holds ambiguous: %v", err)
	}
	rs, err := s.holdsRoleStore("shared:verb")
	if err != nil {
		t.Fatalf("resolve shared:verb: %v", err)
	}
	if rs.Name != "a" {
		t.Errorf("shared:verb resolved to rolestore %q, want the only rolestore-backed vocabulary that declares it (a)", rs.Name)
	}
}

func TestPlane_TwoBackedVocabulariesAreStillAmbiguous(t *testing.T) {
	src := strings.Replace(unbackedVocabSpec, "  permission other:verb\n  preset bp @ tenant = other:verb", "  permission shared:verb\n  preset bp @ tenant = shared:verb", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "declared by more than one vocabulary") {
		t.Fatalf("two ROLESTORE-BACKED vocabularies declaring one permission must still be rejected, got %v", err)
	}
}
