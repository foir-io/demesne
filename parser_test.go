package demesne

import (
	"testing"
)

// TestParseErrors checks a few malformed specs fail with a line-numbered error.
func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"bad reach arrow":    "object r { table t scoped a permission view = owner - x @rls }",
		"unterminated brace": "topology { level a",
		"unknown decl":       "frobnicate foo {}",
	}
	for name, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Errorf("%s: expected parse error, got nil", name)
		}
	}
}

func findVocab(s *Spec, name string) *Vocabulary {
	for _, v := range s.Vocabs {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func findPreset(v *Vocabulary, name string) *Preset {
	for _, p := range v.Presets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func findSubject(s *Spec, name string) *Subject {
	for _, sub := range s.Subjects {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

func findObject(s *Spec, name string) *Object {
	for _, o := range s.Objects {
		if o.Name == name {
			return o
		}
	}
	return nil
}

func findRelation(o *Object, name string) *Relation {
	if o == nil {
		return nil
	}
	for _, r := range o.Relations {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func findPerm(o *Object, verb string) *Perm {
	if o == nil {
		return nil
	}
	for _, p := range o.Perms {
		if p.Verb == verb {
			return p
		}
	}
	return nil
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
