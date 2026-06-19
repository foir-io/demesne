package demesne

import (
	"strings"
	"testing"
)

func selectPerm(expr []*Term, tree *PermNode) *Perm {
	return &Perm{Verb: "read", Maps: "select", Expr: expr, Tree: tree}
}

// cover runs the coverage gate for the FIRST object, with all given objects in scope
// (so a ViaObject borrow can resolve the borrowed object).
func cover(objs ...*Object) (bool, string) {
	return (&Spec{Objects: objs}).accessorCoverage(objs[0])
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
	if ok, reason := cover(obj); !ok {
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
	ok, reason := cover(obj)
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
	if ok, reason := cover(obj); !ok {
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
// ViaClosure now has a reverse builder → covered; the branch reverse-reads the
// closure (ancestors of the row's node) — the same rows the forward _reachable tests.
func TestAccessorCoverage_ViaClosure_CoveredWithBranch(t *testing.T) {
	c := ViaClosure{Closure: "node_closure", AncestorCol: "ancestor", DescendantCol: "descendant", Col: "node_id"}
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "tree", Types: []string{"customer"}, Repr: c}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "tree"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "tree"}})},
	}
	if ok, reason := cover(obj); !ok {
		t.Fatalf("ViaClosure should now be covered, got refusal: %s", reason)
	}
	br := defClosureAccessorBranches(obj, obj.Perms[0], map[string]*Relation{"tree": obj.Relations[0]})
	if len(br) != 1 {
		t.Fatalf("want 1 closure branch, got %d", len(br))
	}
	for _, want := range []string{
		"'closure'::text", "'customer'::text", "x.ancestor",
		"JOIN node_closure x ON x.descendant = t.node_id", "WHERE t.id = p_id",
	} {
		if !strings.Contains(br[0], want) {
			t.Errorf("closure branch missing %q:\n%s", want, br[0])
		}
	}
}

// A read borrow (ViaObject) from a covered content object is now covered, and the
// branch LATERAL-calls the borrowed object's accessor enumerator on the related row.
func TestAccessorCoverage_ViaObject_ReadBorrow_CoveredWithBranch(t *testing.T) {
	doc := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{
			{Name: "owner", Types: []string{"customer"}, Repr: ViaColumn{Column: "owner_id"}},
			{Name: "grantee", Types: []string{"customer"}, Repr: ViaGrant{Table: "resource_acl", RecordCol: "resource_id", KindCol: "principal_kind", PrincipalCol: "principal_id", AccessCol: "access"}},
		},
		// selectPerm's verb is "read", so the borrow below must be doc->read.
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "owner"}, {Ident: "grantee"}},
			&PermNode{Op: "or", Kids: []*PermNode{{Op: "leaf", Term: &Term{Ident: "owner"}}, {Op: "leaf", Term: &Term{Ident: "grantee"}}}},
		)},
	}
	comment := &Object{
		Name: "comment", Table: "comments",
		Relations: []*Relation{{Name: "parent", Repr: ViaObject{Object: "doc", Verb: "read", Col: "doc_id"}}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "parent"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "parent"}})},
	}
	if ok, reason := cover(comment, doc); !ok {
		t.Fatalf("comment borrowing doc->read (doc covered + has grant store) should be covered, got: %s", reason)
	}
	br := (&Spec{Objects: []*Object{comment, doc}}).defObjectAccessorBranches(
		comment, comment.Perms[0], map[string]*Relation{"parent": comment.Relations[0]})
	if len(br) != 1 {
		t.Fatalf("want 1 object branch, got %d", len(br))
	}
	for _, want := range []string{"JOIN LATERAL auth.docs_accessors(t.doc_id) a ON true", "WHERE t.id = p_id"} {
		if !strings.Contains(br[0], want) {
			t.Errorf("object branch missing %q:\n%s", want, br[0])
		}
	}
}

// A NON-read borrow (the borrowed verb is not the other object's select verb) must
// fail closed — the read accessor enumerator can't answer a different verb.
func TestAccessorCoverage_ViaObject_NonReadBorrow_FailsClosed(t *testing.T) {
	doc := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "grantee", Types: []string{"customer"}, Repr: ViaGrant{Table: "resource_acl", RecordCol: "resource_id", KindCol: "principal_kind", PrincipalCol: "principal_id", AccessCol: "access"}}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "grantee"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "grantee"}})},
	}
	comment := &Object{
		Name: "comment", Table: "comments",
		Relations: []*Relation{{Name: "parent", Repr: ViaObject{Object: "doc", Verb: "edit", Col: "doc_id"}}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "parent"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "parent"}})},
	}
	if ok, _ := cover(comment, doc); ok {
		t.Error("a non-read (doc->edit) borrow must fail closed")
	}
}

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
	if ok, reason := cover(obj); ok {
		t.Errorf("an `and`/`and not` SELECT tree must fail closed, got covered (reason=%q)", reason)
	}
}

func TestAccessorCoverage_NoSelectPerm_Covered(t *testing.T) {
	if ok, _ := cover(&Object{Name: "x", Table: "xs"}); !ok {
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
	if ok, reason := cover(obj); !ok {
		t.Errorf("a builtin leaf alongside owner must not trip the gate, got refusal: %s", reason)
	}
}
