package demesne

import (
	"strings"
	"testing"
)

func selectPerm(expr []*Term, tree *PermNode) *Perm {
	return &Perm{Verb: "read", Maps: "select", Expr: expr, Tree: tree}
}

// Owner + grant in a flat OR is exactly what the enumerator covers → no refusal
// (and the Foir-shaped case, so the gate must not trip it).
func TestAccessorCoverage_OwnerGrantUnion_Covered(t *testing.T) {
	obj := &Object{
		Name: "record", Table: "records",
		Relations: []*Relation{
			{Name: "owner", Types: []string{"customer"}, Repr: ViaColumn{Column: "owner_id"}},
			{Name: "grantee", Types: []string{"customer"}, Repr: ViaGrant{Table: "resource_acl"}},
		},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "owner"}, {Ident: "grantee"}},
			&PermNode{Op: "or", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "owner"}},
				{Op: "leaf", Term: &Term{Ident: "grantee"}},
			}},
		)},
	}
	if ok, reason := accessorCoverage(obj); !ok {
		t.Errorf("owner+grant flat-OR must be covered, got refusal: %s", reason)
	}
}

// A SELECT term over a relation with no reverse branch yet (here ViaObject) must fail
// closed — emitting would silently under-report who can access the row.
func TestAccessorCoverage_UncoveredRepr_FailsClosed(t *testing.T) {
	obj := &Object{
		Name: "comment", Table: "comments",
		Relations: []*Relation{{Name: "parent", Repr: ViaObject{Object: "doc", Verb: "view", Col: "doc_id"}}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "parent"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "parent"}})},
	}
	ok, reason := accessorCoverage(obj)
	if ok {
		t.Fatal("a SELECT via ViaObject must fail closed (no accessor branch yet)")
	}
	if !strings.Contains(reason, "parent") {
		t.Errorf("reason should name the offending relation, got %q", reason)
	}
}

// ViaGroup now has a reverse builder → covered, and the group branch reverse-reads the
// closure (transitive members of the row's group) — the same rows the forward term
// tests.
func TestAccessorCoverage_ViaGroup_CoveredWithBranch(t *testing.T) {
	g := ViaGroup{Closure: "team_members", GroupCol: "group_id", MemberCol: "member_id", Col: "team_id"}
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "team", Types: []string{"customer"}, Repr: g}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "team"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "team"}})},
	}
	if ok, reason := accessorCoverage(obj); !ok {
		t.Fatalf("ViaGroup should now be covered, got refusal: %s", reason)
	}
	br := defGroupAccessorBranches(obj, obj.Perms[0], map[string]*Relation{"team": obj.Relations[0]})
	if len(br) != 1 {
		t.Fatalf("want 1 group branch, got %d", len(br))
	}
	for _, want := range []string{
		"'group'::text", "'customer'::text", "c.member_id",
		"JOIN team_members c ON c.group_id = t.team_id", "WHERE t.id = p_id",
	} {
		if !strings.Contains(br[0], want) {
			t.Errorf("group branch missing %q:\n%s", want, br[0])
		}
	}
}

// Intersection / exclusion in the SELECT tree must fail closed — the union-only
// enumerator cannot represent INTERSECT / EXCEPT.
func TestAccessorCoverage_IntersectionExclusion_FailsClosed(t *testing.T) {
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "owner", Repr: ViaColumn{Column: "owner_id"}}},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "owner"}},
			&PermNode{Op: "and", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "owner"}},
				{Op: "not", Kids: []*PermNode{{Op: "leaf", Term: &Term{Ident: "owner"}}}},
			}},
		)},
	}
	if ok, reason := accessorCoverage(obj); ok {
		t.Errorf("an `and`/`and not` SELECT tree must fail closed, got covered (reason=%q)", reason)
	}
}

func TestAccessorCoverage_NoSelectPerm_Covered(t *testing.T) {
	if ok, _ := accessorCoverage(&Object{Name: "x", Table: "xs"}); !ok {
		t.Error("no SELECT perm → nothing to enumerate → covered")
	}
}

// Non-relation leaves (a builtin) must not trip the gate.
func TestAccessorCoverage_BuiltinLeaf_Covered(t *testing.T) {
	obj := &Object{
		Name: "record", Table: "records",
		Relations: []*Relation{{Name: "owner", Repr: ViaColumn{Column: "owner_id"}}},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "owner"}, {Builtin: "app_scope", ExcludeRel: "owner"}},
			&PermNode{Op: "or", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "owner"}},
				{Op: "leaf", Term: &Term{Builtin: "app_scope", ExcludeRel: "owner"}},
			}},
		)},
	}
	if ok, reason := accessorCoverage(obj); !ok {
		t.Errorf("a builtin leaf alongside owner must not trip the gate, got refusal: %s", reason)
	}
}
