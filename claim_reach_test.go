package demesne

import (
	"strings"
	"testing"
)

func TestClaimReach_LiftsContainmentOnConferredOpsOnly(t *testing.T) {
	e := emitReach(t, reachFixture)
	lift := claimSQL("view_mode") + " = 'all'"

	sel := e.policy(t, "assets_select").Using
	want := "((folder_id IS NULL OR folder_id = " + claimSQL("folder_id") + ") OR folder_id IN (SELECT auth.paths_reach_set(" + claimSQL("folder_id") + ")) OR " + lift + ")"
	hasFragments(t, "assets_select", sel, want)
	hasFragments(t, "assets_select", sel, "space_id = "+claimSQL("space_id")+" AND ")

	lacksFragments(t, "assets_update USING", e.policy(t, "assets_update").Using, lift)
	lacksFragments(t, "assets_update CHECK", e.policy(t, "assets_update").Check, lift)
	lacksFragments(t, "assets_insert", e.policy(t, "assets_insert").Check, lift)
	lacksFragments(t, "ledgers_select", e.policy(t, "ledgers_select").Using, lift)
	lacksFragments(t, "folders_select", e.policy(t, "folders_select").Using, lift)

	hasFragments(t, "catalog_can_bound_for_select", e.definer(t, "catalog_can_bound_for_select").Body, lift)
	lacksFragments(t, "catalog_can_bound", e.definer(t, "catalog_can_bound").Body, lift)
}

func TestClaimReach_SkipsTheLevelEntity(t *testing.T) {
	src := reachFixture + `
object folder_node {
  table folder_nodes
  level folder
  scoped estate > space > folder
  permission view = @scoped @rls maps select
}
`
	e := emitReach(t, src)
	lacksFragments(t, "folder_nodes_select", e.policy(t, "folder_nodes_select").Using, "view_mode")
}

func TestClaimReach_HasNoEdgeSurface(t *testing.T) {
	e := emitReach(t, reachFixture)
	for _, g := range e.spec.ReachGrants() {
		if eg, ok := g.(*Grant); ok && eg.Name == "overview" {
			t.Fatalf("a claim grant has no edge to manage, but ReachGrants lists it")
		}
	}
	if _, err := e.spec.GrantSurface("overview"); err == nil {
		t.Fatal("GrantSurface must refuse a claim grant")
	}
	keys, err := e.spec.ClaimsContract()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(keys, ","), "view_mode") {
		t.Fatalf("a claim grant key is minted by the adopter like @kind, not by BuildClaims: %v", keys)
	}
	for name := range e.definers {
		if strings.HasPrefix(name, "overview") {
			t.Fatalf("a claim grant emits no definer, got %s", name)
		}
	}
}

func TestClaimReach_EscapesTheValue(t *testing.T) {
	src := strings.Replace(reachFixture, `view_mode = "all"`, `view_mode = "o'all"`, 1)
	e := emitReach(t, src)
	hasFragments(t, "assets_select", e.policy(t, "assets_select").Using, claimSQL("view_mode")+" = 'o''all'")
}

func TestClaimReach_Refusals(t *testing.T) {
	cases := []struct {
		name, old, new string
		want           []string
	}{
		{"virtual level", `grant overview at folder via claim`, `grant overview at control via claim`, []string{"claim grant \"overview\"", "virtual"}},
		{"no operations", `via claim view_mode = "all" confers select`, `via claim view_mode = "all"`, []string{"must name the operations"}},
		{"edge options", `via claim view_mode = "all" confers select`, `via claim view_mode = "all" expires ends_at confers select`, []string{"takes no edge options"}},
		{"scope ladder", `via claim view_mode = "all" confers select`, `via claim view_mode = "all" scope folder on folder_id missing deny confers select`, []string{"takes no edge options"}},
		{"reaching subject", `subject robot  { anchor space; reach self;`, `subject robot  { anchor space; reach via grant overview;`, []string{"does not take a reaching subject"}},
		{"selection", `reach descendants via ancestors for select
  permission view = @scoped @rls maps select
  permission edit`, `reach overview unscoped
  permission view = @scoped @rls maps select
  permission edit`, []string{"not an edge grant"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(reachFixture, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			mustRefuse(t, strings.Replace(reachFixture, tc.old, tc.new, 1), tc.want...)
		})
	}
	t.Run("authority term", func(t *testing.T) {
		mustRefuse(t, reachFixture+`
object pad { table pads scoped estate > space > folder permission view = via grant overview @rls maps select }
`, "cannot be an authority term")
	})
}
