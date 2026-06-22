package demesne

import (
	"reflect"
	"testing"
)

const capVocabSpec = `
topology { level tenant  level project parent tenant }
vocabulary admin {
  permission a:read  permission a:write  permission b:read  permission b:write
  preset viewer @ project = a:read + b:read
  preset editor @ project = viewer + a:write
  preset owner  @ tenant  = *
  rank owner > editor > viewer
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant > project; relation m: admin via role; permission view = m @rls maps select }
`

func capVocabulary(t *testing.T) *Vocabulary {
	t.Helper()
	s := mustSpec(t, capVocabSpec)
	r, err := s.HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	return r.Vocabulary()
}

func TestCapGrant_Allowed(t *testing.T) {
	v := capVocabulary(t)
	held := []string{"a:read", "a:write", "b:read"}

	got := v.CapGrant(held, []string{"a:read", "b:read"})
	if !got.Allowed || len(got.Unknown) != 0 || len(got.Excess) != 0 {
		t.Errorf("subset should be allowed cleanly, got %+v", got)
	}

	if got := v.CapGrant(held, held); !got.Allowed {
		t.Errorf("granting your full held set should be allowed, got %+v", got)
	}

	if got := v.CapGrant(nil, nil); !got.Allowed {
		t.Errorf("empty request should be allowed, got %+v", got)
	}
}

func TestCapGrant_Excess(t *testing.T) {
	v := capVocabulary(t)
	held := []string{"a:read", "b:read"}

	got := v.CapGrant(held, []string{"a:read", "b:write", "a:write"})
	if got.Allowed {
		t.Error("granting unheld valid perms must be denied")
	}
	if !reflect.DeepEqual(got.Excess, []string{"a:write", "b:write"}) {
		t.Errorf("Excess = %v, want [a:write b:write]", got.Excess)
	}
	if len(got.Unknown) != 0 {
		t.Errorf("no unknowns expected, got %v", got.Unknown)
	}
}

func TestCapGrant_Unknown(t *testing.T) {
	v := capVocabulary(t)
	held := []string{"a:read"}

	got := v.CapGrant(held, []string{"a:read", "zzz:bogus", "qqq:nope", "b:read"})
	if got.Allowed {
		t.Error("unknown perms must be denied")
	}
	if !reflect.DeepEqual(got.Unknown, []string{"qqq:nope", "zzz:bogus"}) {
		t.Errorf("Unknown = %v, want [qqq:nope zzz:bogus]", got.Unknown)
	}
	if !reflect.DeepEqual(got.Excess, []string{"b:read"}) {
		t.Errorf("Excess = %v, want [b:read]", got.Excess)
	}
}

func TestCapGrant_Dedup(t *testing.T) {
	v := capVocabulary(t)
	got := v.CapGrant([]string{"a:read"}, []string{"b:write", "b:write", "zzz", "zzz"})
	if !reflect.DeepEqual(got.Excess, []string{"b:write"}) {
		t.Errorf("Excess = %v, want [b:write]", got.Excess)
	}
	if !reflect.DeepEqual(got.Unknown, []string{"zzz"}) {
		t.Errorf("Unknown = %v, want [zzz]", got.Unknown)
	}
}

func TestCapGrant_RankFloorComposition(t *testing.T) {
	v := capVocabulary(t)

	atOrAbove := v.PresetsAtOrAbove("editor")
	if !reflect.DeepEqual(atOrAbove, []string{"owner", "editor"}) {
		t.Fatalf("PresetsAtOrAbove(editor) = %v, want [owner editor]", atOrAbove)
	}
	meetsFloor := func(role string) bool {
		for _, r := range atOrAbove {
			if r == role {
				return true
			}
		}
		return false
	}

	guard := func(role string, held, requested []string) (allowed bool) {
		if !meetsFloor(role) {
			return false
		}
		return v.CapGrant(held, requested).Allowed
	}

	held := []string{"a:read", "b:read"}

	if v.CapGrant(held, []string{"a:read"}).Allowed != true {
		t.Fatal("precondition: the cap alone allows a held subset")
	}
	if guard("viewer", held, []string{"a:read"}) {
		t.Error("a below-floor grantor must be denied even when the cap would allow")
	}

	if !guard("editor", held, []string{"a:read"}) {
		t.Error("an at-floor grantor granting a held subset should pass")
	}
	if guard("editor", held, []string{"a:write"}) {
		t.Error("the cap must deny an unheld perm even above the floor")
	}
}
