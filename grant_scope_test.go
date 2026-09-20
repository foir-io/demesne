package demesne

import (
	"strings"
	"testing"
)

func TestGrantScope_LadderDefiners(t *testing.T) {
	e := emitReach(t, reachFixture)
	space, folder := sessionClaimSQL("space_id"), sessionClaimSQL("folder_id")
	live := "holder_id = user_id AND estate_id = check_estate_id AND ended_at IS NULL AND expires_at > now()"

	cases := map[string]string{
		"approvals_reach": "EXISTS (SELECT 1 FROM approvals WHERE " + live +
			" AND (space_id IS NULL OR space_id = " + space + ")" +
			" AND (folder_id IS NULL OR " + folder + " IS NULL OR folder_id = " + folder + "))",
		"approvals_reach_set": "estate_id FROM approvals WHERE holder_id = user_id AND ended_at IS NULL AND expires_at > now()" +
			" AND (space_id IS NULL OR space_id = " + space + ")" +
			" AND (folder_id IS NULL OR " + folder + " IS NULL OR folder_id = " + folder + ")",
		"approvals_reach_unscoped": "EXISTS (SELECT 1 FROM approvals WHERE " + live + " AND space_id IS NULL AND folder_id IS NULL)",
		"approvals_reach_unscoped_set": "estate_id FROM approvals WHERE holder_id = user_id AND ended_at IS NULL AND expires_at > now()" +
			" AND space_id IS NULL AND folder_id IS NULL",
		"approvals_reach_in_space": "EXISTS (SELECT 1 FROM approvals WHERE " + live +
			" AND (space_id IS NULL OR check_space_id = '' OR space_id = check_space_id))",
		"approvals_reach_in_folder": "EXISTS (SELECT 1 FROM approvals WHERE " + live +
			" AND (space_id IS NULL OR check_space_id = '' OR space_id = check_space_id)" +
			" AND (folder_id IS NULL OR check_folder_id = '' OR folder_id = check_folder_id))",
	}
	for name, body := range cases {
		if got := e.definer(t, name).Body; got != body {
			t.Errorf("%s\n got: %s\nwant: %s", name, got, body)
		}
	}
	sigs := map[string]string{
		"approvals_reach":           "user_id text, check_estate_id text",
		"approvals_reach_set":       "user_id text",
		"approvals_reach_unscoped":  "user_id text, check_estate_id text",
		"approvals_reach_in_space":  "user_id text, check_estate_id text, check_space_id text",
		"approvals_reach_in_folder": "user_id text, check_estate_id text, check_space_id text, check_folder_id text",
	}
	for name, sig := range sigs {
		if got := e.definer(t, name).Sig; got != sig {
			t.Errorf("%s sig = %q, want %q", name, got, sig)
		}
	}
	for name := range e.definers {
		if strings.HasPrefix(name, "paths_reach_") && name != "paths_reach_set" {
			t.Errorf("a grant without scope levels emits only its reach and set, got %s", name)
		}
	}
}

func TestGrantScope_ExplicitProbeUsesNullForNonTextIdentifiers(t *testing.T) {
	e := emitReach(t, "identifiers uuid\n"+reachFixture)
	body := e.definer(t, "approvals_reach_in_space").Body
	hasFragments(t, "approvals_reach_in_space", body, "(space_id IS NULL OR check_space_id IS NULL OR space_id = check_space_id)")
	hasFragments(t, "approvals_reach", e.definer(t, "approvals_reach").Body, "space_id = "+sessionClaimSQL("space_id")+"::uuid")
}

func TestGrantScope_Selections(t *testing.T) {
	e := emitReach(t, reachFixture)
	sub := claimSQL("sub")
	scoped := "estate_id IN (SELECT auth.approvals_reach_set(" + sub + "))"
	unscoped := "estate_id IN (SELECT auth.approvals_reach_unscoped_set(" + sub + "))"

	if got, want := e.policy(t, "ledgers_select").Using, unscoped+" OR (estate_id = "+claimSQL("estate_id")+")"; got != want {
		t.Errorf("ledgers_select\n got: %s\nwant: %s", got, want)
	}
	bound := "(" + unscoped + " OR (" + scoped + " AND id = " + claimSQL("space_id") + "))"
	if got, want := e.policy(t, "spaces_select").Using, bound+" OR (estate_id = "+claimSQL("estate_id")+")"; got != want {
		t.Errorf("spaces_select\n got: %s\nwant: %s", got, want)
	}
	upd := e.policy(t, "spaces_update")
	for _, half := range []string{upd.Using, upd.Check} {
		hasFragments(t, "spaces_update", half, unscoped)
		lacksFragments(t, "spaces_update", half, scoped)
	}
	hasFragments(t, "assets_select", e.policy(t, "assets_select").Using, scoped)
	lacksFragments(t, "assets_select", e.policy(t, "assets_select").Using, "unscoped")
}

func TestGrantScope_ViaSelectsTheEdgeDirectionPerObjectAndOp(t *testing.T) {
	e := emitReach(t, reachFixture)
	down := "folder_id IN (SELECT auth.paths_reach_set(" + claimSQL("folder_id") + "))"
	up := "folder_id IN (SELECT auth.paths_up_reach_set(" + claimSQL("folder_id") + "))"

	hasFragments(t, "blueprints_select", e.policy(t, "blueprints_select").Using, up)
	lacksFragments(t, "blueprints_select", e.policy(t, "blueprints_select").Using, down)
	hasFragments(t, "assets_select", e.policy(t, "assets_select").Using, down)
	lacksFragments(t, "assets_select", e.policy(t, "assets_select").Using, up)
	lacksFragments(t, "blueprints_update", e.policy(t, "blueprints_update").Using, up, down)

	if got, want := e.definer(t, "paths_up_reach_set").Body, "ancestor_id FROM paths WHERE descendant_id = user_id"; got != want {
		t.Errorf("paths_up_reach_set = %q, want %q", got, want)
	}
	if got, want := e.definer(t, "paths_reach_set").Body, "descendant_id FROM paths WHERE ancestor_id = user_id"; got != want {
		t.Errorf("paths_reach_set = %q, want %q", got, want)
	}
}

func TestGrantScope_SharedEdgeTableNeedsItsOwnDefinerName(t *testing.T) {
	src := strings.Replace(reachFixture, " named paths_up confers select", " confers select", 1)
	mustRefuse(t, src, `grants "descendants" and "ancestors" both emit paths_reach`, "named")

	same := reachFixture + "\ngrant mirror at folder via edge paths(ancestor_id, descendant_id) confers select\n"
	e := emitReach(t, same)
	n := 0
	for name := range e.definers {
		if name == "paths_reach_set" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("two grants with one emission share a definer, got %d", n)
	}
}

func TestGrantScope_Refusals(t *testing.T) {
	cases := []struct {
		name, old, new string
		want           []string
	}{
		{"rung not below the grant", "scope space on space_id missing deny", "scope estate on space_id missing deny", []string{`scope "estate" must be a non-virtual level below "estate"`}},
		{"rungs out of order", "scope space on space_id missing deny\n  scope folder on folder_id missing allow", "scope folder on folder_id missing allow\n  scope space on space_id missing deny", []string{`scope "space" must be a non-virtual level below "folder"`}},
		{"missing rule", "scope folder on folder_id missing allow", "scope folder on folder_id missing maybe", []string{`missing must be allow or deny, got "maybe"`}},
		{"reused column", "scope folder on folder_id missing allow", "scope folder on space_id missing allow", []string{`reuses column "space_id"`}},
		{"unscoped without a ladder", "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach descendants unscoped for select\n  permission view = @scoped @rls maps select\n  permission edit", []string{"need a grant with scope levels"}},
		{"bound level not a rung", "reach support bound space for select", "reach support bound estate for select", []string{"bound estate"}},
		{"via across levels", "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach descendants via support for select\n  permission view = @scoped @rls maps select\n  permission edit", []string{"the replacement must be another edge grant"}},
		{"via without the op", "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach descendants via ancestors for select, update\n  permission view = @scoped @rls maps select\n  permission edit", []string{`selects update, which grant "descendants" does not confer`}},
		{"overlapping ops", "reach support unscoped for update", "reach support unscoped for update, select", []string{`selects the reach of "support" for select twice`}},
		{"op the grant does not confer", "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach descendants via ancestors for update\n  permission view = @scoped @rls maps select\n  permission edit", []string{`which grant "descendants" does not confer`}},
		{"unknown op", "reach support unscoped for update", "reach support unscoped for upsert", []string{`unknown operation "upsert"`}},
		{"unreached grant", "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach ancestors via descendants for select\n  permission view = @scoped @rls maps select\n  permission edit", []string{"which no subject reaches through"}},
		{"duplicate grant", "grant overview at folder", "grant support at folder", []string{`grant "support" is declared twice`}},
		{"no selection mode", "reach support unscoped for update", "reach support for update", []string{"needs `unscoped`, `bound <level>` or `via <grant>`"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(reachFixture, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			mustRefuse(t, strings.Replace(reachFixture, tc.old, tc.new, 1), tc.want...)
		})
	}
	t.Run("replacement that does not confer an op the grant does", func(t *testing.T) {
		src := strings.Replace(reachFixture, "via edge paths(ancestor_id, descendant_id) confers select", "via edge paths(ancestor_id, descendant_id) confers select, update", 1)
		src = strings.Replace(src, "reach descendants via ancestors for select\n  permission view = @scoped @rls maps select\n  permission edit", "reach descendants via ancestors\n  permission view = @scoped @rls maps select\n  permission edit", 1)
		mustRefuse(t, src, `reach descendants via ancestors: "ancestors" does not confer update`)
	})
}

func TestGrantScope_StructuralEnumerationFollowsTheSelectedEdge(t *testing.T) {
	src := reachFixture + `
rolestore crew {
  assignments crew_assignments kind member_kind = "crew" subject member_id
  scope estate_ref space_ref folder_ref rolejoin role_id crew_roles id key revoked ended_at
}
subject crew { anchor estate; reach descendants; identifies crew_sub; roles configurable crew; binds admin }
vocabulary crew { permission node:read preset reader @ folder = node:read }
object folder_node {
  table folder_nodes
  level folder
  scoped estate > space > folder
  reach descendants via ancestors for select
  relation member: crew via role
  permission view = member @rls maps select
}
object other_node {
  table other_nodes
  level folder
  scoped estate > space > folder
  relation member: crew via role
  permission view = member @rls maps select
}
`
	e := emitReach(t, src)
	selected := e.definer(t, "folder_nodes_accessors").Body
	hasFragments(t, "folder_nodes_accessors", selected, "JOIN paths ig ON ig.ancestor_id = e.id", "ig.descendant_id")
	lacksFragments(t, "folder_nodes_accessors", selected, "ig.descendant_id = e.id")
	plain := e.definer(t, "other_nodes_accessors").Body
	hasFragments(t, "other_nodes_accessors", plain, "JOIN paths ig ON ig.descendant_id = e.id", "ig.ancestor_id")
	if strings.Count(plain, "JOIN paths ig") != 1 {
		t.Errorf("a grant reached only through a selection is not enumerated where nothing selects it:\n%s", plain)
	}
}

func TestGrantScope_BoundOnALevelTheObjectCarriesOnlyAsAColumn(t *testing.T) {
	e := emitReach(t, reachFixture)
	sub := claimSQL("sub")
	scoped := "estate_id IN (SELECT auth.approvals_reach_set(" + sub + "))"
	unscoped := "estate_id IN (SELECT auth.approvals_reach_unscoped_set(" + sub + "))"
	own := "estate_id = " + claimSQL("estate_id")

	want := "(" + unscoped + " OR (" + scoped + " AND space_id = " + claimSQL("space_id") + ")) OR (" + own + ")"
	if got := e.policy(t, "allowances_select").Using; got != want {
		t.Errorf("allowances_select\n got: %s\nwant: %s", got, want)
	}
	for _, name := range []string{"allowances_insert", "allowances_update", "allowances_delete"} {
		p := e.policy(t, name)
		for _, half := range []string{p.Using, p.Check} {
			if half == "" {
				continue
			}
			if half != unscoped+" OR ("+own+")" {
				t.Errorf("%s must take the unscoped reach only:\n%s", name, half)
			}
		}
	}
}

func TestGrantScope_BoundColumnIsBoundToTheSchema(t *testing.T) {
	src := `
topology { level control virtual level estate parent control level space parent estate }
grant support at estate via edge approvals(holder_id, estate_id) scope space on space_id missing deny
subject helper { anchor control; reach via grant support; identifies sub; roles none }
object allowance {
  table allowances
  scoped estate
  reach support bound space for select
  permission view = @scoped @rls maps select
}
`
	s, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	sc := NewSchema()
	for _, c := range []string{"holder_id", "estate_id", "space_id"} {
		sc.AddColumn("approvals", c, "text", true)
	}
	sc.AddColumn("allowances", "id", "text", false)
	sc.AddColumn("allowances", "estate_id", "text", false)
	if err := s.ValidateAgainst(sc); err == nil || !strings.Contains(err.Error(), `"space_id"`) || !strings.Contains(err.Error(), "reach bound") {
		t.Fatalf("a bound level's column must exist on the object's table, got %v", err)
	}
	sc.AddColumn("allowances", "space_id", "text", true)
	if err := s.ValidateAgainst(sc); err != nil {
		t.Fatalf("with the column present the spec binds: %v", err)
	}
}
