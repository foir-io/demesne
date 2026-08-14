package demesne

import (
	"strings"
	"testing"
)

// The grant membership hop: a polymorphic grant table whose rows may name a
// GROUP as principal, admitting the group's members through a closure. This is
// the resource_acl + user-groups shape — "share this note with Directors" as
// ONE grant row, membership resolved live at read time.
const grantGroupSpec = `
topology {
  level org    virtual
  level tenant parent org
  level project parent tenant
}

subject operator { anchor project; reach self; identifies sub; roles none; binds owner }

object note {
  table  notes
  scoped tenant > project
  relation admin_owner: operator via owner_id
  relation grantee: operator via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note" group "group" closure group_closure(grp, mem) edge group_members(admin_user_id, group_id)
  permission view = admin_owner + grantee:read @rls maps select
}
`

func mustGrantGroupSpec(t *testing.T) *Spec {
	t.Helper()
	s, err := Parse(grantGroupSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

func TestGrantGroupHop_ParsesOntoTheGrant(t *testing.T) {
	s := mustGrantGroupSpec(t)
	obj := s.objectByName("note")
	if obj == nil {
		t.Fatal("no note object")
	}
	var vg *ViaGrant
	for _, r := range obj.Relations {
		if g, ok := r.Repr.(ViaGrant); ok {
			vg = &g
		}
	}
	if vg == nil {
		t.Fatal("no grant relation parsed")
	}
	if vg.GroupKindVal != "group" || vg.GroupClosure != "group_closure" ||
		vg.GroupGroupCol != "grp" || vg.GroupMemberCol != "mem" ||
		vg.GroupEdge != "group_members" || vg.GroupEdgeMember != "admin_user_id" || vg.GroupEdgeGroup != "group_id" {
		t.Fatalf("hop parsed wrong: %+v", vg)
	}
}

// TestGrantGroupHop_DefinerJoinsTheClosure pins the emitted definer body: the
// direct principal match stays, and the membership branch joins the grant
// table to the closure so a group row admits its members — with the discrim,
// kind and access conjuncts all present, since dropping any one of them turns
// a scoped grant into a wider one.
func TestGrantGroupHop_DefinerJoinsTheClosure(t *testing.T) {
	s := mustGrantGroupSpec(t)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var grantFn *GenFn
	for i := range defs {
		if strings.Contains(defs[i].Name, "resource_acl_grants_note") {
			grantFn = &defs[i]
		}
	}
	if grantFn == nil {
		t.Fatal("no grant definer emitted")
	}
	for _, want := range []string{
		// The direct branch is untouched.
		"principal_kind = 'operator'",
		"principal_id = p_operator_id",
		// The membership branch.
		"FROM resource_acl g JOIN group_closure gc ON gc.grp = g.principal_id",
		"g.resource_type = 'note'",
		"g.principal_kind = 'group'",
		"gc.mem = p_operator_id",
		"g.access = p_access",
	} {
		if !strings.Contains(grantFn.Body, want) {
			t.Errorf("definer body missing %q in:\n%s", want, grantFn.Body)
		}
	}
}

// TestGrantGroupHop_TriggersMaintainTheClosure pins that a grant-side hop is
// enough to get the closure rebuild triggers — no `via group` audience column
// needs to exist for the membership machinery to be maintained.
func TestGrantGroupHop_TriggersMaintainTheClosure(t *testing.T) {
	s := mustGrantGroupSpec(t)
	trig := s.TriggersSQL()
	for _, want := range []string{
		"WITH RECURSIVE",
		"FROM group_members",
		"INSERT INTO group_closure (grp, mem)",
	} {
		if !strings.Contains(trig, want) {
			t.Errorf("trigger SQL missing %q in:\n%s", want, trig)
		}
	}
}

// TestGrantGroupHop_RLSPolicyShapeUnchanged pins that the hop lives INSIDE the
// definer: the emitted policy still calls the same definer function, so the
// policy surface (and every existing spec without a hop) is untouched.
func TestGrantGroupHop_RLSPolicyShapeUnchanged(t *testing.T) {
	s := mustGrantGroupSpec(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	pol := findPolicy(res, "notes_select")
	if pol == nil {
		t.Fatalf("no notes_select policy (unsupported: %v)", res.Unsupported)
	}
	if !strings.Contains(pol.Using, "resource_acl_grants_note(") {
		t.Errorf("policy no longer routes through the grant definer:\n%s", pol.Using)
	}
	if strings.Contains(pol.Using, "group_closure") {
		t.Errorf("the membership join leaked into the policy body (it belongs in the definer):\n%s", pol.Using)
	}
}
