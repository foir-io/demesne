package demesne

import (
	"database/sql"
	"reflect"
	"testing"
)

func vocab() *Vocabulary {
	return &Vocabulary{
		Name:        "staff",
		Permissions: []string{"docs:read", "docs:write", "docs:publish", "admin:read"},
		Implications: []*Implication{
			{Perm: "docs:publish", Set: []string{"docs:write"}},
			{Perm: "docs:write", Set: []string{"docs:read"}},
			{Perm: "admin:read", Star: true},
		},
		Presets: []*Preset{
			{Name: "viewer", Level: "workspace", Set: []string{"docs:read"}},
			{Name: "editor", Level: "workspace", Set: []string{"viewer", "docs:write"}},
			{Name: "owner", Level: "tenant", Star: true},
			{Name: "broken", Set: []string{"nope"}},
		},
		Rank: []string{"owner", "editor", "viewer"},
	}
}

func TestComposeCan_EveryCombination(t *testing.T) {
	for _, c := range []struct {
		governed, allow bool
		pdp             Decision
		want            Decision
	}{
		{false, false, NotGoverned, NotGoverned},
		{false, false, Allow, Allow},
		{false, false, Deny, Deny},
		{true, false, NotGoverned, Deny},
		{true, false, Allow, Deny},
		{true, true, NotGoverned, Allow},
		{true, true, Allow, Allow},
		{true, true, Deny, Deny},
	} {
		if got := ComposeCan(c.governed, c.allow, c.pdp); got != c.want {
			t.Errorf("ComposeCan(%v, %v, %v) = %v, want %v", c.governed, c.allow, c.pdp, got, c.want)
		}
	}
	if got := []string{Allow.String(), Deny.String(), NotGoverned.String()}; !reflect.DeepEqual(got, []string{"allow", "deny", "ungoverned"}) {
		t.Errorf("Decision strings = %v", got)
	}
}

func TestCapabilityGateErr_NamesTheVerbToCall(t *testing.T) {
	want := "doc.publish_draft is a capability (@pdp) verb with no row-level check — resolve held permissions and call CanPublishDraft(held) on the Doc object"
	if got := CapabilityGateErr("doc", "publish_draft").Error(); got != want {
		t.Errorf("got %q", got)
	}
	if got := CapabilityGateErr("api_key", "read").Error(); got != "api_key.read is a capability (@pdp) verb with no row-level check — resolve held permissions and call CanRead(held) on the APIKey object" {
		t.Errorf("got %q", got)
	}
}

func TestMintClaims_RefusesKeysOutsideTheContract(t *testing.T) {
	got, err := MintClaimsValues([]string{"sub", "tenant_id"}, map[string]string{"tenant_id": "t1", "sub": "u1"})
	if err != nil || got != `{"sub":"u1","tenant_id":"t1"}` {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := MintClaimsValues([]string{"sub"}, map[string]string{"zeta": "1", "alpha": "2"}); err == nil || err.Error() != "MintClaims: key(s) not in the claims contract: [alpha zeta]" {
		t.Errorf("got %v", err)
	}
}

func TestVocabulary_PresetsAndRank(t *testing.T) {
	v := vocab()
	for name, want := range map[string][]string{
		"viewer": {"docs:read"},
		"editor": {"docs:read", "docs:write"},
		"owner":  {"admin:read", "docs:publish", "docs:read", "docs:write"},
	} {
		got, err := v.PresetPermissions(name)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("PresetPermissions(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if _, err := v.PresetPermissions("broken"); err == nil || err.Error() != `vocabulary "staff": preset "broken" references "nope", which is neither a permission nor a preset in this vocabulary` {
		t.Errorf("broken preset: %v", err)
	}
	if _, err := v.PresetPermissions("absent"); err == nil || err.Error() != `vocabulary "staff": no preset "absent"` {
		t.Errorf("absent preset: %v", err)
	}
	if r, ok := v.RankOf("editor"); r != 1 || !ok {
		t.Errorf("RankOf(editor) = %d, %v", r, ok)
	}
	if _, ok := v.RankOf("broken"); ok {
		t.Error("an unranked preset has a rank")
	}
	if got := v.PresetsAtOrAbove("editor"); !reflect.DeepEqual(got, []string{"owner", "editor"}) {
		t.Errorf("PresetsAtOrAbove(editor) = %v", got)
	}
	if got := v.PresetsAtOrAbove("broken"); got != nil {
		t.Errorf("PresetsAtOrAbove(broken) = %v", got)
	}
}

func TestVocabulary_Implications(t *testing.T) {
	v := vocab()
	if got, err := v.ImpliedPermissions("docs:publish"); err != nil || !reflect.DeepEqual(got, []string{"docs:publish", "docs:read", "docs:write"}) {
		t.Errorf("ImpliedPermissions(docs:publish) = %v, %v", got, err)
	}
	if got, err := v.ImpliedPermissions("admin:read"); err != nil || len(got) != 4 {
		t.Errorf("a starred implication grants every permission: %v, %v", got, err)
	}
	if got, err := v.ExpandImplications([]string{"docs:write", "x:y"}); err != nil || !reflect.DeepEqual(got, []string{"docs:write", "x:y", "docs:read", "docs:write"}) {
		t.Errorf("ExpandImplications = %v, %v", got, err)
	}
	cyclic := &Vocabulary{Name: "c", Permissions: []string{"a:x", "a:y"}, Implications: []*Implication{{Perm: "a:x", Set: []string{"a:y"}}, {Perm: "a:y", Set: []string{"a:*"}}}}
	if _, err := cyclic.ImpliedPermissions("a:x"); err == nil || err.Error() != `vocabulary "c": permission "a:x" is cyclic (a permission cannot imply itself, directly or transitively)` {
		t.Errorf("cycle: %v", err)
	}
	var none *Vocabulary
	if got, err := none.ExpandImplications([]string{"p"}); err != nil || !reflect.DeepEqual(got, []string{"p"}) {
		t.Errorf("a nil vocabulary passes permissions through: %v, %v", got, err)
	}
}

func TestResolveRoles_KeepsTheRolesInScope(t *testing.T) {
	assignments := []RoleAssignment{
		{Scope: []string{"t1", ""}, RoleKey: "owner"},
		{Scope: []string{"t1", "w1"}, RoleKey: "editor"},
		{Scope: []string{"t2", "w9"}, RoleKey: "viewer"},
	}
	if got := ResolveRoles(assignments, []string{"t1", "w1"}).Roles(); !reflect.DeepEqual(got, []string{"editor", "owner"}) {
		t.Errorf("in t1/w1: %v", got)
	}
	if got := ResolveRoles(assignments, []string{"t1", "w2"}).Roles(); !reflect.DeepEqual(got, []string{"owner"}) {
		t.Errorf("in t1/w2: %v", got)
	}
	if got := ResolveRoles(assignments, []string{"", ""}).Roles(); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("only a global assignment reaches the root scope: %v", got)
	}
	if got := ResolveRoles(append(assignments, RoleAssignment{Scope: []string{"", ""}, RoleKey: "auditor"}), []string{"t9", "w9"}).Roles(); !reflect.DeepEqual(got, []string{"auditor"}) {
		t.Errorf("a global assignment reaches every scope: %v", got)
	}
	if !NewEffectiveRoles("a", "b").Holds("b") || NewEffectiveRoles("a").Holds("b") {
		t.Error("NewEffectiveRoles holds exactly its keys")
	}
}

func TestHoldsResolver_SQL(t *testing.T) {
	r := &HoldsResolver{
		Assignments: "role_grants", KindCol: "grantee_kind", KindVal: "staff", SubjectCol: "grantee_id",
		ScopeCols: []string{"tenant_id", "workspace_id"}, RevokedCol: "revoked_at",
		RoleCol: "role_id", RolesTable: "roles", RolesID: "id", KeyCol: "key", Vocab: vocab(),
	}
	if got := r.GlobalAssignmentsSQL(); got != "SELECT ra.grantee_id, r.key, ra.tenant_id, ra.workspace_id FROM role_grants ra JOIN roles r ON r.id = ra.role_id WHERE ra.grantee_kind = 'staff' AND ra.revoked_at IS NULL AND ra.tenant_id IS NULL ORDER BY 1, 2" {
		t.Errorf("GlobalAssignmentsSQL = %q", got)
	}
	if got := r.SelectedScopeCols(); !reflect.DeepEqual(got, []string{"tenant_id", "workspace_id"}) {
		t.Errorf("SelectedScopeCols = %v", got)
	}
	if r.Vocabulary() != r.Vocab {
		t.Error("Vocabulary returns the resolver's vocabulary")
	}
	held, err := r.Resolve([]RoleAssignment{{Scope: []string{"t1", "w1"}, RoleKey: "editor"}}, []string{"t1", "w1"})
	if err != nil || !held.Holds("docs:write") || held.Holds("docs:publish") {
		t.Errorf("Resolve: %v, %v", held.Permissions(), err)
	}
}

var _ Querier = FromSQL((*sql.DB)(nil))
