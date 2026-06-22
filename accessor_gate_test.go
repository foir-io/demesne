package demesne

import (
	"strings"
	"testing"
)

func selectPerm(expr []*Term, tree *PermNode) *Perm {
	return &Perm{Verb: "read", Maps: "select", Expr: expr, Tree: tree}
}

func cover(objs ...*Object) (bool, string) {
	return (&Spec{Objects: objs}).accessorCoverage(objs[0])
}

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
	br := (&Spec{}).defGroupAccessorBranches(obj, obj.Perms[0], map[string]*Relation{"team": obj.Relations[0]})
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

func TestAccessorBranch_MaterializedGroup_ReadsFlat(t *testing.T) {
	g := ViaGroup{Closure: "tc", GroupCol: "grp", MemberCol: "mem", Edge: "te", EdgeMember: "mem", EdgeGroup: "grp", Col: "team_id", Materialized: true}
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "team", Types: []string{"customer"}, Repr: g}},
		Perms:     []*Perm{selectPerm([]*Term{{Ident: "team"}}, &PermNode{Op: "leaf", Term: &Term{Ident: "team"}})},
	}
	s := &Spec{Objects: []*Object{obj}}
	br := s.defGroupAccessorBranches(obj, obj.Perms[0], map[string]*Relation{"team": obj.Relations[0]})
	if len(br) != 1 {
		t.Fatalf("want 1 group branch, got %d", len(br))
	}

	for _, want := range []string{
		"'group'::text", "'customer'::text", "f.principal_id",
		"FROM auth.docs_team_flat f", "WHERE f.resource_id = p_id",
	} {
		if !strings.Contains(br[0], want) {
			t.Errorf("materialized group branch missing %q:\n%s", want, br[0])
		}
	}
	if strings.Contains(br[0], "JOIN tc") {
		t.Errorf("materialized branch must not walk the closure:\n%s", br[0])
	}

	flats := s.EmitMaterializedFlats()
	if len(flats) != 1 {
		t.Fatalf("want 1 materialized flat, got %d", len(flats))
	}
	if got, want := s.groupFlatName(obj, obj.Relations[0], g), flats[0].qFlat(); got != want {
		t.Errorf("accessor reads %q but EmitMaterializedFlats emits %q", got, want)
	}
}

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

func TestAccessorCoverage_ViaObject_ReadBorrow_CoveredWithBranch(t *testing.T) {
	doc := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{
			{Name: "owner", Types: []string{"customer"}, Repr: ViaColumn{Column: "owner_id"}},
			{Name: "grantee", Types: []string{"customer"}, Repr: ViaGrant{Table: "resource_acl", RecordCol: "resource_id", KindCol: "principal_kind", PrincipalCol: "principal_id", AccessCol: "access"}},
		},

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

func TestAccessorCoverage_AndNot_NonComposableLeaf_FailsClosed(t *testing.T) {
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{{Name: "grantee", Types: []string{"customer"}, Repr: ViaGrant{Table: "resource_acl", RecordCol: "resource_id", KindCol: "principal_kind", PrincipalCol: "principal_id", AccessCol: "access"}}},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "grantee"}, {Builtin: "app_scope"}},
			&PermNode{Op: "and", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "grantee"}},
				{Op: "not", Kids: []*PermNode{{Op: "leaf", Term: &Term{Builtin: "app_scope"}}}},
			}},
		)},
	}
	if ok, _ := cover(obj); ok {
		t.Error("and/not over a non-composable (@app_scope role-plane) leaf must fail closed")
	}
}

func TestAccessorTree_AndNot_Composes(t *testing.T) {
	g := ViaGrant{Table: "resource_acl", RecordCol: "resource_id", KindCol: "principal_kind", PrincipalCol: "principal_id", AccessCol: "access"}
	grp := ViaGroup{Closure: "blocked_members", GroupCol: "group_id", MemberCol: "member_id", Col: "blocklist_id"}
	obj := &Object{
		Name: "doc", Table: "docs",
		Relations: []*Relation{
			{Name: "grantee", Types: []string{"customer"}, Repr: g},
			{Name: "blocked", Types: []string{"customer"}, Repr: grp},
		},

		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "grantee:read"}, {Ident: "blocked"}},
			&PermNode{Op: "and", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "grantee:read"}},
				{Op: "not", Kids: []*PermNode{{Op: "leaf", Term: &Term{Ident: "blocked"}}}},
			}},
		)},
	}
	if ok, reason := cover(obj); !ok {
		t.Fatalf("grantee:read AND NOT blocked should compose (covered), got: %s", reason)
	}
	sql, ok := (&Spec{Objects: []*Object{obj}}).accessorTreeSQL(obj, obj.Perms[0].Tree,
		map[string]*Relation{"grantee": obj.Relations[0], "blocked": obj.Relations[1]})
	if !ok {
		t.Fatal("composer should succeed for composable content leaves")
	}
	for _, want := range []string{
		"SELECT a.* FROM (",
		"(a.principal_kind, a.principal_id) NOT IN (SELECT b.principal_kind, b.principal_id FROM (",
		"blocked_members",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("composed and/not SQL missing %q:\n%s", want, sql)
		}
	}
}

func TestStructuralCoverage_RoleMemberinBuiltin_Covered(t *testing.T) {
	obj := &Object{
		Name: "tenant", Table: "tenants", Level: "tenant",
		Relations: []*Relation{
			{Name: "staff", Types: []string{"staff"}, Repr: ViaRole{}},
			{Name: "access", Types: []string{"admin"}, Repr: ViaMemberIn{Level: "tenant"}},
		},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "staff"}, {Ident: "access"}, {Builtin: "session"}},
			&PermNode{Op: "or", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "staff"}},
				{Op: "leaf", Term: &Term{Ident: "access"}},
				{Op: "leaf", Term: &Term{Builtin: "session"}},
			}},
		)},
	}
	if ok, reason := structuralAccessorCoverage(obj); !ok {
		t.Errorf("role+memberin+builtin level entity should be covered, got: %s", reason)
	}
}

func TestStructuralCoverage_UncoveredOwner_FailsClosed(t *testing.T) {
	obj := &Object{
		Name: "tenant", Table: "tenants", Level: "tenant",
		Relations: []*Relation{
			{Name: "staff", Types: []string{"staff"}, Repr: ViaRole{}},
			{Name: "owner", Types: []string{"admin"}, Repr: ViaColumn{Column: "owner_id"}},
		},
		Perms: []*Perm{selectPerm(
			[]*Term{{Ident: "staff"}, {Ident: "owner"}},
			&PermNode{Op: "or", Kids: []*PermNode{
				{Op: "leaf", Term: &Term{Ident: "staff"}},
				{Op: "leaf", Term: &Term{Ident: "owner"}},
			}},
		)},
	}
	if ok, _ := structuralAccessorCoverage(obj); ok {
		t.Error("an owner (ViaColumn) term on a level entity must fail closed")
	}
}

func TestAccessorCoverage_NoSelectPerm_Covered(t *testing.T) {
	if ok, _ := cover(&Object{Name: "x", Table: "xs"}); !ok {
		t.Error("no SELECT perm → nothing to enumerate → covered")
	}
}

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
