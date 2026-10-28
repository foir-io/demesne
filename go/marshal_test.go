package demesne

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAZeroProjectionMarshalsWithoutNull(t *testing.T) {
	for _, v := range []any{
		ClaimEntry{}, Claims{}, Principal{}, PDP{}, Preset{}, Implication{}, Vocabulary{},
		HoldsResolver{}, RoleAssignment{}, RoleAssignmentSurface{}, GrantSurface{}, ResourceAccessSurface{},
		Claims{Entries: []ClaimEntry{{}}}, HoldsResolver{Vocab: Vocabulary{Presets: []Preset{{}}}},
	} {
		b, err := json.Marshal(v)
		if err != nil || strings.Contains(string(b), "null") {
			t.Errorf("%T: %s, %v", v, b, err)
		}
	}
}

func TestTheRuntimeReadsAHandBuiltProjectionWithNilFields(t *testing.T) {
	ctx, r := runtime(t)
	refused := func(err error) bool { return err != nil && strings.Contains(err.Error(), "must be") }
	got, err := r.Authorize(ctx, PDP{}, "/x", func(string) bool { return true })
	if err != nil || got != NotGoverned {
		t.Errorf("Authorize: %s, %v", got, err)
	}
	_, err = Claims{}.Mint(ctx, r, nil)
	if refused(err) {
		t.Error(err)
	}
	for name, err := range map[string]error{
		"holds":          func() error { _, err := (HoldsResolver{}).AssignmentsSQL(ctx, r); return err }(),
		"vocabulary":     func() error { _, err := (Vocabulary{}).ExpandImplications(ctx, r, nil); return err }(),
		"grant":          func() error { _, err := (GrantSurface{}).ListSQL(ctx, r); return err }(),
		"roleAssignment": func() error { _, err := (RoleAssignmentSurface{}).RevokeSQL(ctx, r); return err }(),
		"resourceAccess": func() error { _, err := (ResourceAccessSurface{}).ModeSQL(ctx, r); return err }(),
	} {
		if refused(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
