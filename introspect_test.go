package demesne

import (
	"reflect"
	"testing"
)

const introspectSpec = `
topology { level tenant level project parent tenant }

vocabulary records {
  permission records:read
  permission records:write
  permission records:read:*
  preset viewer @ tenant = records:read
  preset editor @ tenant = viewer + records:write
  preset owner  @ tenant = *
  rank owner > editor > viewer
}
vocabulary audit {
  permission audit:view
}

rolestore records { assignments rec_grants kind grantee_kind = "rec" subject grantee_id scope tenant_id project_id rolejoin role_id roles id key revoked revoked_at }
rolestore audit   { assignments aud_grants kind grantee_kind = "aud" subject grantee_id scope tenant_id project_id rolejoin role_id roles id key revoked revoked_at }

subject recer { anchor tenant reach descendants identifies sub   roles configurable records binds admin }
subject auder { anchor tenant reach descendants identifies audid roles configurable audit  binds owner }

object thing {
  table things
  scoped tenant > project
  relation admin: recer via role
  relation owner: auder via owner_id
  permission view = admin + owner @rls maps select
}
`

func TestVocabularies_PermissionsAndParameterized(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	got := s.Vocabularies()
	want := []VocabularyInfo{
		{Name: "records", Permissions: []PermissionInfo{
			{Name: "records:read", Parameterized: false},
			{Name: "records:write", Parameterized: false},
			{Name: "records:read:*", Parameterized: true},
		}},
		{Name: "audit", Permissions: []PermissionInfo{
			{Name: "audit:view", Parameterized: false},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Vocabularies()\n got: %#v\nwant: %#v", got, want)
	}
}

func TestVocabularies_EmptySpec(t *testing.T) {
	if got := (&Spec{}).Vocabularies(); len(got) != 0 {
		t.Errorf("Vocabularies() on empty spec: want none, got %#v", got)
	}
}

func TestExpandedPresets_RefsAndWildcard(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	got, err := s.ExpandedPresets("records")
	if err != nil {
		t.Fatalf("ExpandedPresets: %v", err)
	}
	want := map[string][]string{
		"viewer": {"records:read"},
		"editor": {"records:read", "records:write"},
		"owner":  {"records:read", "records:read:*", "records:write"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExpandedPresets(records)\n got: %#v\nwant: %#v", got, want)
	}
}

func TestExpandedPresets_DefaultRolestore(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	def, err := s.ExpandedPresets("")
	if err != nil {
		t.Fatalf("ExpandedPresets(default): %v", err)
	}
	named, err := s.ExpandedPresets("records")
	if err != nil {
		t.Fatalf("ExpandedPresets(records): %v", err)
	}
	if !reflect.DeepEqual(def, named) {
		t.Errorf("default rolestore must resolve to the first declared rolestore (records)\n got: %#v\nwant: %#v", def, named)
	}
}

func TestExpandedPresets_NoPresets(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	got, err := s.ExpandedPresets("audit")
	if err != nil {
		t.Fatalf("ExpandedPresets(audit): %v", err)
	}
	if got == nil {
		t.Fatal("a vocabulary with no presets must yield an empty, non-nil map")
	}
	if len(got) != 0 {
		t.Errorf("ExpandedPresets(audit): want empty, got %#v", got)
	}
}

func TestExpandedPresets_MultiRolestoreIsolation(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	rec, err := s.ExpandedPresets("records")
	if err != nil {
		t.Fatalf("ExpandedPresets(records): %v", err)
	}
	aud, err := s.ExpandedPresets("audit")
	if err != nil {
		t.Fatalf("ExpandedPresets(audit): %v", err)
	}
	if _, ok := rec["viewer"]; !ok {
		t.Error("records rolestore should expose its own preset 'viewer'")
	}
	if len(aud) != 0 {
		t.Errorf("audit rolestore must not leak the records vocabulary's presets, got %#v", aud)
	}
}

func TestExpandedPresets_Errors(t *testing.T) {
	s := mustValidSpec(t, introspectSpec)
	if _, err := s.ExpandedPresets("nope"); err == nil {
		t.Error("ExpandedPresets on an unknown rolestore should error")
	}
	if _, err := (&Spec{}).ExpandedPresets(""); err == nil {
		t.Error("ExpandedPresets with no rolestore declared should error")
	}
}
