package demesne

import (
	"strings"
	"testing"
)

func TestAdmit_JoinsThePolicyOfEachNamedOp(t *testing.T) {
	e := emitReach(t, reachFixture)
	containment := "(estate_id = " + claimSQL("estate_id") + " OR estate_id IN (SELECT auth.approvals_reach_set(" + claimSQL("sub") + "))) AND space_id = " + claimSQL("space_id")
	permission := "(" + containment + " AND ((" + claimSQL("kind") + " = 'staff')))"
	arm := func(col string) string {
		return "(" + containment + " AND ((" + claimSQL("kind") + " = 'robot') AND (estate_id = " + claimSQL("estate_id") + ") AND (space_id = " + claimSQL("space_id") + ") AND ((" + claimSQL("folder_id") + " IS NULL OR auth.paths_reachable(" + claimSQL("folder_id") + ", " + col + ")))))"
	}
	want := map[string]string{
		"folders_select": "(" + permission + ") OR " + arm("id"),
		"folders_delete": "(" + permission + ") OR " + arm("id"),
		"folders_update": "(" + permission + ") OR " + arm("id"),
		"folders_insert": "(" + permission + ") OR " + arm("parent_id"),
	}
	for name, pred := range want {
		p := e.policy(t, name)
		got := p.Using
		if p.Cmd == "INSERT" {
			got = p.Check
		}
		if got != pred {
			t.Errorf("%s\n got: %s\nwant: %s", name, got, pred)
		}
		if p.Cmd == "UPDATE" && p.Check != pred {
			t.Errorf("%s WITH CHECK must carry the same arm:\n%s", name, p.Check)
		}
	}
	lacksFragments(t, "assets_select", e.policy(t, "assets_select").Using, "paths_reachable")
}

func TestAdmit_IsNotLentOrEnumerated(t *testing.T) {
	src := reachFixture + `
object tag {
  table tags
  scoped estate > space
  relation holder: robot via object folder->view on folder_id
  permission view = @scoped and holder @rls maps select
}
object shelf {
  table shelves
  scoped estate > space
  relation reader: robot via grant shelf_acl(shelf_id, principal_kind, principal_id, access)
  relation confined: robot via closure paths(ancestor_id, descendant_id) on folder_id from claim folder_id missing deny
  permission view = @scoped and reader:read @rls maps select
  admit select = @kind("robot") and confined
}
`
	e := emitReach(t, src)
	lent := e.definer(t, "folder_can_view").Body
	hasFragments(t, "folder_can_view", lent, claimSQL("kind")+" = 'staff'")
	lacksFragments(t, "folder_can_view", lent, "'robot'", "paths_reachable")

	acc := e.definer(t, "shelves_accessors").Body
	hasFragments(t, "shelves_accessors", acc, "FROM shelf_acl")
	lacksFragments(t, "shelves_accessors", acc, "paths")

	hasFragments(t, "shelves_select", e.policy(t, "shelves_select").Using,
		") OR ((estate_id = "+claimSQL("estate_id"), "auth.paths_reachable("+claimSQL("folder_id")+", folder_id)")
	lacksFragments(t, "shelves_select", e.policy(t, "shelves_select").Using, claimSQL("folder_id")+" IS NULL OR auth.paths_reachable")
}

func TestAdmit_PointCheckAgreesWithThePolicy(t *testing.T) {
	e := emitReach(t, reachFixture)
	var folder *Object
	for _, o := range e.spec.Objects {
		if o.Name == "folder" {
			folder = o
		}
	}
	sql, err := e.spec.editPointCheckSQL(folder)
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT EXISTS (SELECT 1 FROM folders WHERE id = $1 AND (" + e.policy(t, "folders_update").Using + "))"
	if sql != want {
		t.Errorf("CanEdit must run the policy's predicate, arms included\n got: %s\nwant: %s", sql, want)
	}
}

func TestClaimClosure_Emission(t *testing.T) {
	e := emitReach(t, reachFixture)
	if got, want := e.definer(t, "paths_reachable").Body, "EXISTS (SELECT 1 FROM paths WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant)"; got != want {
		t.Errorf("paths_reachable = %q, want %q", got, want)
	}
	for _, tr := range e.spec.EmitTriggers() {
		if strings.Contains(tr.FunctionSQL(), "paths") {
			t.Errorf("a closure with no base is maintained by the adopter, but a trigger was emitted:\n%s", tr.FunctionSQL())
		}
	}
}

func TestAdmit_Refusals(t *testing.T) {
	cases := []struct {
		name, old, new string
		want           []string
	}{
		{"unknown op", "admit insert =", "admit upsert =", []string{`admits unknown operation "upsert"`}},
		{"op no permission maps", "  permission delete = @scoped and @kind(\"staff\") @rls maps delete\n", "", []string{"admits delete, but no @rls permission maps delete"}},
		{"unknown relation", "and confined_parent", "and confined_elsewhere", []string{`references unknown relation "confined_elsewhere"`}},
		{"closure missing rule", "on parent_id from claim folder_id missing allow", "on parent_id from claim folder_id missing sometimes", []string{`missing must be allow or deny, got "sometimes"`}},
		{"owner closure without base", "on parent_id from claim folder_id missing allow", "on parent_id", []string{"needs `base <table>(id, parent)`"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(reachFixture, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			mustRefuse(t, strings.Replace(reachFixture, tc.old, tc.new, 1), tc.want...)
		})
	}
	for name, view := range map[string]string{
		"claim closure inside a conjunction": `@scoped and (reader:read + confined)`,
		"claim closure as a disjunct":        `reader:read + confined`,
	} {
		t.Run(name, func(t *testing.T) {
			src := reachFixture + `
object shelf {
  table shelves
  scoped estate > space
  relation reader: robot via grant shelf_acl(shelf_id, principal_kind, principal_id, access)
  relation confined: robot via closure paths(ancestor_id, descendant_id) on folder_id from claim folder_id missing deny
  permission view = ` + view + ` @rls maps select
}
`
			s, err := Parse(src)
			if err != nil {
				t.Fatal(err)
			}
			err = Validate(s)
			if err == nil {
				_, err = s.EmitDefiners()
			}
			if err == nil || !strings.Contains(err.Error(), "cannot soundly enumerate") {
				t.Fatalf("a claim-confined closure in an enumerated read must fail closed, got %v", err)
			}
		})
	}
}
