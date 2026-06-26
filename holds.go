package demesne

import (
	"fmt"
	"sort"
	"strings"
)

func (s *Spec) vocabByName(name string) *Vocabulary {
	for _, v := range s.Vocabs {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (v *Vocabulary) presetByName(name string) *Preset {
	for _, p := range v.Presets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (v *Vocabulary) PresetPermissions(name string) ([]string, error) {
	into := map[string]bool{}
	if err := v.expandPreset(name, into, map[string]bool{}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(into))
	for p := range into {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Vocabulary) expandPreset(name string, into, onStack map[string]bool) error {
	if onStack[name] {
		return fmt.Errorf("vocabulary %q: preset %q is cyclic (a preset cannot reference itself, directly or transitively)", v.Name, name)
	}
	p := v.presetByName(name)
	if p == nil {
		return fmt.Errorf("vocabulary %q: no preset %q", v.Name, name)
	}
	if p.Star {
		for _, perm := range v.Permissions {
			into[perm] = true
		}
		return nil
	}
	perms := map[string]bool{}
	for _, perm := range v.Permissions {
		perms[perm] = true
	}
	onStack[name] = true
	defer delete(onStack, name)
	for _, item := range p.Set {
		switch {
		case perms[item]:
			into[item] = true
		case v.presetByName(item) != nil:
			if err := v.expandPreset(item, into, onStack); err != nil {
				return err
			}
		default:
			return fmt.Errorf("vocabulary %q: preset %q references %q, which is neither a permission nor a preset in this vocabulary", v.Name, name, item)
		}
	}
	return nil
}

func (v *Vocabulary) RankOf(preset string) (int, bool) {
	for i, r := range v.Rank {
		if r == preset {
			return i, true
		}
	}
	return 0, false
}

func (v *Vocabulary) PresetsAtOrAbove(threshold string) []string {
	ti, ok := v.RankOf(threshold)
	if !ok {
		return nil
	}
	var out []string
	for i, r := range v.Rank {
		if i <= ti {
			out = append(out, r)
		}
	}
	return out
}

type HoldsResolver struct {
	Assignments string
	KindCol     string
	KindVal     string
	SubjectCol  string
	ScopeCols   []string
	RevokedCol  string

	RoleCol    string
	RolesTable string
	RolesID    string
	KeyCol     string

	PermsCol string

	Vocab *Vocabulary
}

func (s *Spec) HoldsResolver(rolestore string) (*HoldsResolver, error) {
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
			return nil, fmt.Errorf("HoldsResolver: the spec declares no rolestore")
		}
		return nil, fmt.Errorf("HoldsResolver: no rolestore %q in the spec", rolestore)
	}
	vocab, err := s.rolestoreVocab(rs)
	if err != nil {
		return nil, err
	}
	return &HoldsResolver{
		Assignments: rs.Assignments,
		KindCol:     rs.KindCol,
		KindVal:     rs.KindVal,
		SubjectCol:  rs.SubjectCol,
		ScopeCols:   append([]string(nil), rs.ScopeCols...),
		RevokedCol:  rs.RevokedCol,
		RoleCol:     rs.RoleCol,
		RolesTable:  rs.RolesTable,
		RolesID:     rs.RolesID,
		KeyCol:      rs.KeyCol,
		PermsCol:    rs.PermsCol,
		Vocab:       vocab,
	}, nil
}

func (s *Spec) rolestoreVocab(rs *RoleStore) (*Vocabulary, error) {
	if v := s.vocabByName(rs.Name); v != nil {
		return v, nil
	}
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" && sub.Roles != "" {
			if v := s.vocabByName(sub.Roles); v != nil {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("HoldsResolver: rolestore %q has no vocabulary (expected a vocabulary named %q, or a `binds admin` subject naming one via `roles`)", rs.Name, rs.Name)
}

func (r *HoldsResolver) Vocabulary() *Vocabulary { return r.Vocab }

func (r *HoldsResolver) AssignmentsSQL() string {
	cols := make([]string, 0, len(r.ScopeCols)+2)
	for _, c := range r.ScopeCols {
		cols = append(cols, "ra."+c)
	}
	cols = append(cols, "r."+r.KeyCol)
	if r.PermsCol != "" {
		cols = append(cols, "r."+r.PermsCol)
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE ra.%s = '%s' AND ra.%s = $1 AND ra.%s IS NULL",
		strings.Join(cols, ", "),
		r.Assignments, r.RolesTable, r.RolesID, r.RoleCol,
		r.KindCol, r.KindVal, r.SubjectCol, r.RevokedCol)
}

type RoleAssignment struct {
	Scope       []string
	RoleKey     string
	Permissions []string
}

type EffectivePerms struct {
	perms map[string]bool
}

func (e EffectivePerms) Holds(perm string) bool { return e.perms[perm] }

func (e EffectivePerms) Permissions() []string {
	out := make([]string, 0, len(e.perms))
	for p := range e.perms {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (r *HoldsResolver) Resolve(assignments []RoleAssignment, scope []string) (EffectivePerms, error) {
	eff := EffectivePerms{perms: map[string]bool{}}
	for _, a := range assignments {
		if !scopeContains(a.Scope, scope) {
			continue
		}
		var perms []string
		if r.PermsCol != "" {

			perms = a.Permissions
		} else {
			expanded, err := r.Vocab.PresetPermissions(a.RoleKey)
			if err != nil {
				return EffectivePerms{}, fmt.Errorf("Resolve: assignment role %q: %w", a.RoleKey, err)
			}
			perms = expanded
		}
		for _, p := range perms {
			eff.perms[p] = true
		}
	}
	return eff, nil
}

func scopeContains(assignment, query []string) bool {
	for i, a := range assignment {
		if i == 0 {

			if i >= len(query) || query[i] != a {
				return false
			}
			continue
		}
		if a == "" {
			continue
		}
		if i >= len(query) || query[i] != a {
			return false
		}
	}
	return true
}

type EffectiveRoles struct {
	roles map[string]bool
}

func NewEffectiveRoles(keys ...string) EffectiveRoles {
	e := EffectiveRoles{roles: make(map[string]bool, len(keys))}
	for _, k := range keys {
		if k != "" {
			e.roles[k] = true
		}
	}
	return e
}

func (e EffectiveRoles) Holds(roleKey string) bool { return e.roles[roleKey] }

func (e EffectiveRoles) Roles() []string {
	out := make([]string, 0, len(e.roles))
	for k := range e.roles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ResolveRoles(assignments []RoleAssignment, scope []string) EffectiveRoles {
	e := EffectiveRoles{roles: map[string]bool{}}
	for _, a := range assignments {
		if a.RoleKey == "" {
			continue
		}
		if scopeAllEmpty(a.Scope) || scopeContains(a.Scope, scope) {
			e.roles[a.RoleKey] = true
		}
	}
	return e
}

func scopeAllEmpty(scope []string) bool {
	for _, s := range scope {
		if s != "" {
			return false
		}
	}
	return true
}
