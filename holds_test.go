package demesne

import (
	"sort"
	"strings"
	"testing"
)

// A generic, deliberately non-Foir spec: a 2-level tenancy (tenant > team) under a
// virtual root, a role vocabulary with a nested preset, a star preset and a rank
// ladder, and a rolestore that declares a materialized permissions column. Proves
// the holds-resolver derives everything from the spec — no baked names.
const holdsSpec = `
topology {
  level org    virtual
  level tenant parent org
  level team   parent tenant
}

vocabulary roles {
  permission docs:read  permission docs:write  permission docs:publish
  permission admin:read permission admin:write
  preset viewer @ team   = docs:read + admin:read
  preset editor @ team   = viewer + docs:write + docs:publish
  preset owner  @ tenant = *
  rank owner > editor > viewer
}

rolestore roles {
  assignments role_assignments
  kind        principal_kind = "member"
  subject     principal_id
  scope       tenant_id team_id
  rolejoin    role_id roles_tbl id key
  revoked     revoked_at
  permissions perms
}

subject member { anchor team; reach descendants; identifies sub; roles configurable roles; binds admin }
`

func mustParseHolds(t *testing.T, spec string) *Spec {
	t.Helper()
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func vocabRoles(t *testing.T) *Vocabulary {
	t.Helper()
	v := mustParseHolds(t, holdsSpec).vocabByName("roles")
	if v == nil {
		t.Fatal("vocabulary roles not found")
	}
	return v
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func TestPresetPermissions(t *testing.T) {
	v := vocabRoles(t)
	cases := []struct {
		preset string
		want   []string
	}{
		{"viewer", []string{"docs:read", "admin:read"}},
		{"editor", []string{"docs:read", "admin:read", "docs:write", "docs:publish"}},
		// owner = * → the whole vocabulary.
		{"owner", []string{"docs:read", "docs:write", "docs:publish", "admin:read", "admin:write"}},
	}
	for _, c := range cases {
		got, err := v.PresetPermissions(c.preset)
		if err != nil {
			t.Fatalf("%s: %v", c.preset, err)
		}
		if !equalSet(got, c.want) {
			t.Errorf("%s: got %v want %v", c.preset, got, c.want)
		}
		// Deterministic + sorted.
		if !sort.StringsAreSorted(got) {
			t.Errorf("%s: result not sorted: %v", c.preset, got)
		}
	}
}

func TestPresetPermissionsErrors(t *testing.T) {
	v := vocabRoles(t)
	if _, err := v.PresetPermissions("nope"); err == nil {
		t.Error("expected error for unknown preset")
	}

	// A preset referencing a name that is neither a permission nor a preset.
	bad := &Vocabulary{
		Name:        "v",
		Permissions: []string{"a:read"},
		Presets:     []*Preset{{Name: "p", Set: []string{"a:read", "ghost"}}},
	}
	if _, err := bad.PresetPermissions("p"); err == nil {
		t.Error("expected error for a reference to neither a permission nor a preset")
	}

	// A direct self-cycle and a transitive cycle both fail closed.
	selfCycle := &Vocabulary{
		Name:    "v",
		Presets: []*Preset{{Name: "p", Set: []string{"p"}}},
	}
	if _, err := selfCycle.PresetPermissions("p"); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("expected a cyclic error, got %v", err)
	}
	transitive := &Vocabulary{
		Name: "v",
		Presets: []*Preset{
			{Name: "a", Set: []string{"b"}},
			{Name: "b", Set: []string{"a"}},
		},
	}
	if _, err := transitive.PresetPermissions("a"); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("expected a transitive cyclic error, got %v", err)
	}
}

func TestRankHelpers(t *testing.T) {
	v := vocabRoles(t)
	if i, ok := v.RankOf("owner"); !ok || i != 0 {
		t.Errorf("RankOf(owner) = %d,%v want 0,true", i, ok)
	}
	if i, ok := v.RankOf("viewer"); !ok || i != 2 {
		t.Errorf("RankOf(viewer) = %d,%v want 2,true", i, ok)
	}
	if _, ok := v.RankOf("ghost"); ok {
		t.Error("RankOf(ghost) should be false")
	}
	if got := v.PresetsAtOrAbove("editor"); !equalSet(got, []string{"owner", "editor"}) {
		t.Errorf("PresetsAtOrAbove(editor) = %v want [owner editor]", got)
	}
	if got := v.PresetsAtOrAbove("owner"); !equalSet(got, []string{"owner"}) {
		t.Errorf("PresetsAtOrAbove(owner) = %v want [owner]", got)
	}
	if got := v.PresetsAtOrAbove("ghost"); got != nil {
		t.Errorf("PresetsAtOrAbove(ghost) = %v want nil", got)
	}
}

func TestAssignmentsSQL(t *testing.T) {
	s := mustParseHolds(t, holdsSpec)
	r, err := s.HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	want := "SELECT ra.tenant_id, ra.team_id, r.key, r.perms FROM role_assignments ra " +
		"JOIN roles_tbl r ON r.id = ra.role_id WHERE ra.principal_kind = 'member' " +
		"AND ra.principal_id = $1 AND ra.revoked_at IS NULL"
	if got := r.AssignmentsSQL(); got != want {
		t.Errorf("AssignmentsSQL (materialized):\n got: %s\nwant: %s", got, want)
	}

	// Without a materialized column the perms column is dropped from the projection.
	noPerms := strings.Replace(holdsSpec, "  permissions perms\n", "", 1)
	r2, err := mustParseHolds(t, noPerms).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver (no perms col): %v", err)
	}
	want2 := "SELECT ra.tenant_id, ra.team_id, r.key FROM role_assignments ra " +
		"JOIN roles_tbl r ON r.id = ra.role_id WHERE ra.principal_kind = 'member' " +
		"AND ra.principal_id = $1 AND ra.revoked_at IS NULL"
	if got := r2.AssignmentsSQL(); got != want2 {
		t.Errorf("AssignmentsSQL (expand-key):\n got: %s\nwant: %s", got, want2)
	}
	if r2.PermsCol != "" {
		t.Errorf("PermsCol should be empty without a permissions declaration, got %q", r2.PermsCol)
	}
}

// Resolve with MATERIALIZED permissions — the Foir shape (custom roles carry an
// arbitrary set). Proves the scope-containment match + dedup union.
func TestResolveMaterialized(t *testing.T) {
	s := mustParseHolds(t, holdsSpec)
	r, err := s.HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	assignments := []RoleAssignment{
		// tenant-wide viewer (team unpinned)
		{Scope: []string{"T1", ""}, RoleKey: "viewer", Permissions: []string{"docs:read", "admin:read"}},
		// project-scoped CUSTOM role (key is not a preset; perms are arbitrary)
		{Scope: []string{"T1", "TM1"}, RoleKey: "custom", Permissions: []string{"docs:write"}},
		// a different tenant
		{Scope: []string{"T2", "TM9"}, RoleKey: "owner", Permissions: []string{"admin:write"}},
	}
	cases := []struct {
		tenant, team string
		want         []string
	}{
		{"T1", "TM1", []string{"docs:read", "admin:read", "docs:write"}}, // tenant-wide + custom
		{"T1", "TM2", []string{"docs:read", "admin:read"}},               // tenant-wide only
		{"T1", "", []string{"docs:read", "admin:read"}},                  // tenant-wide query: project grant excluded
		{"T2", "TM9", []string{"admin:write"}},                           // other tenant
		{"T3", "TM1", []string{}},                                        // no match
	}
	for _, c := range cases {
		h, err := r.Resolve(assignments, []string{c.tenant, c.team})
		if err != nil {
			t.Fatalf("(%s,%s): %v", c.tenant, c.team, err)
		}
		if !equalSet(h.Permissions(), c.want) {
			t.Errorf("(%s,%s): got %v want %v", c.tenant, c.team, h.Permissions(), c.want)
		}
		// Holds(perm) agrees with Permissions().
		for _, p := range c.want {
			if !h.Holds(p) {
				t.Errorf("(%s,%s): Holds(%q) = false, expected true", c.tenant, c.team, p)
			}
		}
		if h.Holds("docs:read") != contains(c.want, "docs:read") {
			t.Errorf("(%s,%s): Holds(docs:read) disagrees with want", c.tenant, c.team)
		}
	}
}

// (uses the package-level contains helper from emit_rls.go)

// Resolve with NO materialized column — role keys expand through the vocabulary.
func TestResolveExpandKey(t *testing.T) {
	noPerms := strings.Replace(holdsSpec, "  permissions perms\n", "", 1)
	r, err := mustParseHolds(t, noPerms).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	assignments := []RoleAssignment{
		{Scope: []string{"T1", "TM1"}, RoleKey: "editor"}, // Permissions nil → expand
		{Scope: []string{"T1", ""}, RoleKey: "owner"},     // tenant-wide owner = *
	}
	h, err := r.Resolve(assignments, []string{"T1", "TM1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// owner (*) subsumes everything, so the effective set is the whole vocabulary.
	want := []string{"docs:read", "docs:write", "docs:publish", "admin:read", "admin:write"}
	if !equalSet(h.Permissions(), want) {
		t.Errorf("expand-key resolve: got %v want %v", h.Permissions(), want)
	}

	// An unknown role key with no materialized perms fails closed.
	if _, err := r.Resolve([]RoleAssignment{{Scope: []string{"T1", "TM1"}, RoleKey: "ghost"}}, []string{"T1", "TM1"}); err == nil {
		t.Error("expected error expanding an unknown role key")
	}
}

// The vocabulary-name fallback: a rolestore whose name differs from the vocabulary
// resolves the vocab via the `binds admin` subject's `roles`.
func TestHoldsResolverVocabFallback(t *testing.T) {
	spec := strings.Replace(holdsSpec, "rolestore roles {", "rolestore store {", 1)
	r, err := mustParseHolds(t, spec).HoldsResolver("store")
	if err != nil {
		t.Fatalf("HoldsResolver(store): %v", err)
	}
	if r.Vocabulary() == nil || r.Vocabulary().Name != "roles" {
		t.Errorf("expected the fallback to resolve vocabulary 'roles', got %+v", r.Vocabulary())
	}
}

// The ROOT scope column is a strict tenancy boundary: an empty-root (NULL-tenant)
// assignment must NEVER match a real-tenant query — it matches only an empty-root
// query, mirroring effPermsFromRecords' strict tenant equality. Regression guard for
// the platform-root cross-tenant drift (a NULL-tenant admin role must not leak into
// every tenant).
func TestResolveRootStrict(t *testing.T) {
	r, err := mustParseHolds(t, holdsSpec).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	asg := []RoleAssignment{
		{Scope: []string{"", ""}, RoleKey: "x", Permissions: []string{"docs:read"}},
	}
	if h, _ := r.Resolve(asg, []string{"T1", "TM1"}); len(h.Permissions()) != 0 {
		t.Errorf("empty-root assignment leaked into a real tenant: %v", h.Permissions())
	}
	if h, _ := r.Resolve(asg, []string{"", ""}); !equalSet(h.Permissions(), []string{"docs:read"}) {
		t.Errorf("empty-root assignment should match an empty-root query, got %v", h.Permissions())
	}
}

// scopeContains generalises over N scope levels: root strict, every deeper level an
// empty-wildcard. Exercised directly with a 3-column chain (the specs under test use
// only 2), covering root-strict, tenant-wide/org-wide subtree coverage, the
// shallower-query rejection, and a mid-level gap.
func TestScopeContainsMultiLevel(t *testing.T) {
	cases := []struct {
		name              string
		assignment, query []string
		want              bool
	}{
		{"exact", []string{"O1", "T1", "P1"}, []string{"O1", "T1", "P1"}, true},
		{"tenant-wide covers project", []string{"O1", "T1", ""}, []string{"O1", "T1", "P1"}, true},
		{"tenant-wide at tenant query", []string{"O1", "T1", ""}, []string{"O1", "T1", ""}, true},
		{"org-wide covers deep", []string{"O1", "", ""}, []string{"O1", "T9", "P9"}, true},
		{"root differs", []string{"O1", "", ""}, []string{"O2", "T1", "P1"}, false},
		{"deeper grant rejects shallower query", []string{"O1", "T1", "P1"}, []string{"O1", "T1", ""}, false},
		{"mid-level differs", []string{"O1", "T1", "P1"}, []string{"O1", "T2", "P1"}, false},
		{"empty root never matches real", []string{"", "T1", "P1"}, []string{"O1", "T1", "P1"}, false},
		{"mid-level gap wildcards", []string{"O1", "", "P1"}, []string{"O1", "T1", "P1"}, true},
		{"shorter query, unpinned tail ok", []string{"O1", "", ""}, []string{"O1"}, true},
	}
	for _, c := range cases {
		if got := scopeContains(c.assignment, c.query); got != c.want {
			t.Errorf("%s: scopeContains(%v,%v) = %v want %v", c.name, c.assignment, c.query, got, c.want)
		}
	}
}

// Materialized permissions are opaque pass-through at read time — a custom role may
// carry a value OUTSIDE the vocabulary (validation is a write-time concern), exactly
// as effPermsFromRecords surfaces whatever the column holds.
func TestResolveMaterializedPassThrough(t *testing.T) {
	r, err := mustParseHolds(t, holdsSpec).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	asg := []RoleAssignment{
		{Scope: []string{"T1", "TM1"}, RoleKey: "weird", Permissions: []string{"totally:madeup"}},
	}
	h, err := r.Resolve(asg, []string{"T1", "TM1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !equalSet(h.Permissions(), []string{"totally:madeup"}) {
		t.Errorf("materialized perms must pass through opaque (incl. out-of-vocab): %v", h.Permissions())
	}
}

// Empty input and the materialized/empty edge both yield an empty set (no error, no
// spurious key expansion).
func TestResolveEmptyAndNil(t *testing.T) {
	r, err := mustParseHolds(t, holdsSpec).HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	if h, err := r.Resolve(nil, []string{"T1", "TM1"}); err != nil || len(h.Permissions()) != 0 {
		t.Errorf("nil input should yield empty perms, got %v err=%v", h.Permissions(), err)
	}
	// A materialized assignment that grants nothing -> empty, NOT a key expansion.
	asg := []RoleAssignment{{Scope: []string{"T1", "TM1"}, RoleKey: "empty-role", Permissions: []string{}}}
	if h, err := r.Resolve(asg, []string{"T1", "TM1"}); err != nil || len(h.Permissions()) != 0 {
		t.Errorf("empty materialized role should grant nothing, got %v err=%v", h.Permissions(), err)
	}
}

// A rolestore with no resolvable vocabulary (no same-named vocab, no `binds admin`
// subject) fails closed at build time.
func TestHoldsResolverNoVocab(t *testing.T) {
	spec := `
topology { level root virtual  level tenant parent root }
rolestore store {
  assignments asg
  kind        k = "m"
  subject     pid
  scope       tenant_id
  rolejoin    role_id roles id key
  revoked     rev
}
subject u { anchor tenant; reach descendants; identifies sub; roles none }
`
	s := mustParseHolds(t, spec)
	if _, err := s.HoldsResolver("store"); err == nil {
		t.Error("expected an error when no vocabulary resolves for the rolestore")
	}
}
