package demesne

import (
	"fmt"
	"strings"
)

type PermissionInfo struct {
	Name          string
	Parameterized bool
}

type VocabularyInfo struct {
	Name        string
	Permissions []PermissionInfo
}

func (s *Spec) Vocabularies() []VocabularyInfo {
	out := make([]VocabularyInfo, 0, len(s.Vocabs))
	for _, v := range s.Vocabs {
		perms := make([]PermissionInfo, 0, len(v.Permissions))
		for _, p := range v.Permissions {
			perms = append(perms, PermissionInfo{Name: p, Parameterized: strings.ContainsRune(p, '*')})
		}
		out = append(out, VocabularyInfo{Name: v.Name, Permissions: perms})
	}
	return out
}

func (s *Spec) ExpandedPresets(rolestore string) (map[string][]string, error) {
	var rs *RoleStore
	if rolestore == "" {
		rs = roleStoreByName(s)
	} else {
		for _, r := range s.RoleStores {
			if r.Name == rolestore {
				rs = r
				break
			}
		}
	}
	if rs == nil {
		if rolestore == "" {
			return nil, fmt.Errorf("ExpandedPresets: the spec declares no rolestore")
		}
		return nil, fmt.Errorf("ExpandedPresets: no rolestore %q in the spec", rolestore)
	}
	v, err := s.rolestoreVocab(rs)
	if err != nil {
		return nil, fmt.Errorf("ExpandedPresets: %w", err)
	}
	out := make(map[string][]string, len(v.Presets))
	for _, p := range v.Presets {
		perms, err := v.PresetPermissions(p.Name)
		if err != nil {
			return nil, fmt.Errorf("ExpandedPresets: %w", err)
		}
		out[p.Name] = perms
	}
	return out, nil
}
