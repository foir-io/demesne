package demesne

import (
	"strings"
	"testing"
)

const armProbeSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object group {
  table  teams
  scoped tenant > project
  relation member:  customer via member_id
  relation grantee: customer via grant team_acl(team_id, principal_kind, principal_id, access)
  permission view = member + grantee:read @rls maps select
}
object record {
  table  records
  scoped tenant > project
  relation owner:       customer via customer_id
  relation grantee:     customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  relation comp_parent: record via composition record_relationships(from_record_id, to_record_id) where kind = "composition"
  relation slice_root:  record via composition records(id, root_id)
  relation in_team:     group via object group->view on team_id
  permission view = owner + grantee:read + comp_parent + slice_root + in_team @rls maps select
}
object pin {
  table  pins
  scoped tenant > project
  relation of: record via object record->view on record_id
  permission view = of @rls maps select
}
`

func armProbeDefiner(t *testing.T, name string) (*Spec, string) {
	t.Helper()
	s, err := Parse(armProbeSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	for _, d := range defs {
		if d.Name == name {
			return s, d.Body
		}
	}
	t.Fatalf("no %s definer", name)
	return nil, ""
}

func TestDefinerBody_ProbesEachRelationHopBeforeItsDefiner(t *testing.T) {
	_, body := armProbeDefiner(t, "record_can_view")
	for _, want := range []string{
		"(EXISTS (SELECT 1 FROM record_relationships hop WHERE hop.from_record_id = records.id AND hop.kind = 'composition' AND hop.to_record_id IS NOT NULL) AND auth.record_composition_comp_parent(records.id, 'read'))",
		"(records.root_id IS NOT NULL AND auth.record_composition_slice_root(records.id, 'read'))",
		"(EXISTS (SELECT 1 FROM teams hop WHERE hop.id = records.team_id) AND auth.group_can_view(team_id))",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("record_can_view missing %q:\n%s", want, body)
		}
	}
}

func TestDefinerBody_KeepsAGrantTestAsACallToItsDefiner(t *testing.T) {
	_, body := armProbeDefiner(t, "record_can_view")
	want := "auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id'), records.id, 'read')"
	if !strings.Contains(body, want) {
		t.Errorf("record_can_view does not call the grant definer:\n%s", body)
	}
	if strings.Contains(body, "FROM resource_acl") {
		t.Errorf("record_can_view inlines the grant test, which every call would plan whether or not it reaches the arm:\n%s", body)
	}
}

func TestDefinerBody_ACompositionDefinerRendersItsParentPredicatePlain(t *testing.T) {
	_, body := armProbeDefiner(t, "record_composition_comp_parent")
	if strings.Contains(body, "hop.") || strings.Contains(body, " hop ") {
		t.Errorf("the composition definer carries probes in the parent predicate it repeats per access:\n%s", body)
	}
	if !strings.Contains(body, "auth.group_can_view(team_id)") {
		t.Errorf("the composition definer lost the parent's plain object call:\n%s", body)
	}
}

func TestDefinerBody_TheGrantDefinerItselfIsUnchanged(t *testing.T) {
	_, body := armProbeDefiner(t, "resource_acl_grants_record")
	want := "EXISTS (SELECT 1 FROM resource_acl WHERE resource_id = p_record_id AND resource_type = 'record' AND principal_kind = 'customer' AND principal_id = p_customer_id AND access = p_access)"
	if body != want {
		t.Errorf("grant definer body = %s\nwant %s", body, want)
	}
}

func TestPolicy_CallsEachRelationDefinerWithoutProbeOrInline(t *testing.T) {
	s, _ := armProbeDefiner(t, "record_can_view")
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	p := findPolicy(rls, "records_select")
	if p == nil {
		t.Fatalf("no records_select (unsupported: %v)", rls.Unsupported)
	}
	for _, want := range []string{
		"auth.record_composition_comp_parent(records.id, 'read')",
		"auth.record_composition_slice_root(records.id, 'read')",
		"auth.group_can_view(team_id)",
		"auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id'), records.id, 'read')",
	} {
		if !strings.Contains(p.Using, want) {
			t.Errorf("records_select missing plain call %q:\n%s", want, p.Using)
		}
	}
	for _, banned := range []string{" hop ", "hop.", " gr ", "gr."} {
		if strings.Contains(p.Using, banned) {
			t.Errorf("records_select carries a definer-body probe or inline (%q); a policy reads with the caller's privileges:\n%s", banned, p.Using)
		}
	}
}

func TestDefinerBody_ProbeQualifiesTheOuterColumn(t *testing.T) {
	_, body := armProbeDefiner(t, "record_can_view")
	if strings.Contains(body, "hop.id = team_id") {
		t.Errorf("the probe leaves the outer column bare, so a same-named column of the probed table would capture it:\n%s", body)
	}
}

func TestSpec_DefinerBodyModeLeavesTheParsedSpecAlone(t *testing.T) {
	s, _ := armProbeDefiner(t, "record_can_view")
	if s.definerBody {
		t.Fatal("emitting definers switched the parsed spec into definer-body mode")
	}
}
