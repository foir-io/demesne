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

func (v *Vocabulary) HasPermission(perm string) bool {
	for _, p := range v.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func (v *Vocabulary) implicationOf(perm string) *Implication {
	for _, im := range v.Implications {
		if im.Perm == perm {
			return im
		}
	}
	return nil
}

func (v *Vocabulary) matchWildcard(item string) []string {
	prefix, ok := strings.CutSuffix(item, "*")
	if !ok || !strings.HasSuffix(prefix, ":") {
		return nil
	}
	var out []string
	for _, p := range v.Permissions {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	return out
}

func (v *Vocabulary) ImpliedPermissions(perm string) ([]string, error) {
	into := map[string]bool{}
	if err := v.expandImplication(perm, into, map[string]bool{}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(into))
	for p := range into {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Vocabulary) expandImplication(perm string, into, onStack map[string]bool) error {
	if onStack[perm] {
		return fmt.Errorf("vocabulary %q: permission %q is cyclic (a permission cannot imply itself, directly or transitively)", v.Name, perm)
	}
	into[perm] = true
	im := v.implicationOf(perm)
	if im == nil {
		return nil
	}
	if im.Star {
		for _, p := range v.Permissions {
			into[p] = true
		}
		return nil
	}
	onStack[perm] = true
	defer delete(onStack, perm)
	for _, item := range im.Set {
		matched := v.matchWildcard(item)
		if len(matched) == 0 {
			if !v.HasPermission(item) {
				return fmt.Errorf("vocabulary %q: permission %q implies %q, which is neither a permission of this vocabulary nor a `<domain>:*` wildcard matching one", v.Name, perm, item)
			}
			matched = []string{item}
		}
		for _, m := range matched {
			if err := v.expandImplication(m, into, onStack); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *Vocabulary) ExpandImplications(perms []string) ([]string, error) {
	if v == nil || len(v.Implications) == 0 {
		return perms, nil
	}
	out := append([]string(nil), perms...)
	for _, p := range perms {
		if v.implicationOf(p) == nil {
			continue
		}
		implied, err := v.ImpliedPermissions(p)
		if err != nil {
			return nil, err
		}
		out = append(out, implied...)
	}
	return out, nil
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

func (s *Spec) rolestorePlaneDepth(rs *RoleStore) int {
	if rs.Plane == "" {
		return len(rs.ScopeCols)
	}
	chain, err := s.Topology.Chain()
	if err != nil {
		return 0
	}
	depth := 0
	for _, l := range chain {
		if !l.Virtual {
			depth++
		}
		if l.Name == rs.Plane {
			if depth > len(rs.ScopeCols) {
				return len(rs.ScopeCols)
			}
			return depth
		}
	}
	return 0
}

func (s *Spec) vocabsDeclaring(perm string) []*Vocabulary {
	var out []*Vocabulary
	for _, v := range s.Vocabs {
		if v.HasPermission(perm) {
			out = append(out, v)
		}
	}
	return out
}

func vocabNames(vs []*Vocabulary) string {
	names := make([]string, len(vs))
	for i, v := range vs {
		names[i] = v.Name
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func rolestoreNames(rss []*RoleStore) string {
	names := make([]string, len(rss))
	for i, rs := range rss {
		names[i] = rs.Name
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func (s *Spec) holdsRoleStore(perm string) (*RoleStore, error) {
	switch len(s.RoleStores) {
	case 0:
		return nil, fmt.Errorf("the spec declares no rolestore")
	case 1:
		return s.RoleStores[0], nil
	}
	owners := s.vocabsDeclaring(perm)
	switch len(owners) {
	case 0:
		return nil, fmt.Errorf("permission %q is declared by no vocabulary, so it names no rolestore", perm)
	case 1:
	default:
		return nil, fmt.Errorf("permission %q is declared by more than one vocabulary (%s), so it names no single rolestore — a permission belongs to exactly one vocabulary", perm, vocabNames(owners))
	}
	var matched []*RoleStore
	for _, rs := range s.RoleStores {
		if v, err := s.rolestoreVocab(rs); err == nil && v == owners[0] {
			matched = append(matched, rs)
		}
	}
	switch len(matched) {
	case 0:
		return nil, fmt.Errorf("permission %q belongs to vocabulary %q, which backs no rolestore", perm, owners[0].Name)
	case 1:
		return matched[0], nil
	default:
		return nil, fmt.Errorf("permission %q belongs to vocabulary %q, which backs more than one rolestore (%s)", perm, owners[0].Name, rolestoreNames(matched))
	}
}

func (s *Spec) isDefaultRoleStore(rs *RoleStore) bool {
	return len(s.RoleStores) > 0 && s.RoleStores[0] == rs
}

func (s *Spec) holdsPermFn(rs *RoleStore) string {
	if s.isDefaultRoleStore(rs) {
		return s.adminName() + "_has_perm"
	}
	return rs.Name + "_has_perm"
}

func (s *Spec) permImpliedByFn(rs *RoleStore) string {
	if s.isDefaultRoleStore(rs) {
		return s.adminName() + "_perm_implied_by"
	}
	return rs.Name + "_perm_implied_by"
}

type HoldsResolver struct {
	Assignments string
	KindCol     string
	KindVal     string
	SubjectCol  string
	ScopeCols   []string
	RevokedCol  string

	Plane      string
	PlaneDepth int

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
		Plane:       rs.Plane,
		PlaneDepth:  s.rolestorePlaneDepth(rs),
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

func (r *HoldsResolver) SelectedScopeCols() []string { return r.ScopeCols[:r.planeDepth()] }

func (r *HoldsResolver) AssignmentsSQL() string {
	cols := make([]string, 0, len(r.ScopeCols)+2)
	for _, c := range r.SelectedScopeCols() {
		cols = append(cols, "ra."+c)
	}
	cols = append(cols, "r."+r.KeyCol)
	if r.PermsCol != "" {
		cols = append(cols, "r."+r.PermsCol)
	}
	var conds []string
	if r.KindCol != "" {
		conds = append(conds, fmt.Sprintf("ra.%s = '%s'", r.KindCol, r.KindVal))
	}
	conds = append(conds, fmt.Sprintf("ra.%s = $1", r.SubjectCol))
	if r.RevokedCol != "" {
		conds = append(conds, fmt.Sprintf("ra.%s IS NULL", r.RevokedCol))
	}
	for _, c := range r.ScopeCols[r.planeDepth():] {
		conds = append(conds, fmt.Sprintf("ra.%s IS NULL", c))
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE %s",
		strings.Join(cols, ", "),
		r.Assignments, r.RolesTable, r.RolesID, r.RoleCol,
		strings.Join(conds, " AND "))
}

func (r *HoldsResolver) GlobalAssignmentsSQL() string {
	if len(r.ScopeCols) == 0 {
		return ""
	}
	cols := []string{"ra." + r.SubjectCol, "r." + r.KeyCol}
	for _, c := range r.ScopeCols {
		cols = append(cols, "ra."+c)
	}
	var conds []string
	if r.KindCol != "" {
		conds = append(conds, fmt.Sprintf("ra.%s = '%s'", r.KindCol, r.KindVal))
	}
	if r.RevokedCol != "" {
		conds = append(conds, fmt.Sprintf("ra.%s IS NULL", r.RevokedCol))
	}
	conds = append(conds, fmt.Sprintf("ra.%s IS NULL", r.ScopeCols[0]))
	return fmt.Sprintf(
		"SELECT %s FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE %s ORDER BY 1, 2",
		strings.Join(cols, ", "),
		r.Assignments, r.RolesTable, r.RolesID, r.RoleCol,
		strings.Join(conds, " AND "))
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

func (r *HoldsResolver) planeDepth() int {
	if r.Plane == "" {
		return len(r.ScopeCols)
	}
	if r.PlaneDepth < 0 {
		return 0
	}
	if r.PlaneDepth > len(r.ScopeCols) {
		return len(r.ScopeCols)
	}
	return r.PlaneDepth
}

func withinPlane(scope []string, depth int) bool {
	for i := depth; i < len(scope); i++ {
		if scope[i] != "" {
			return false
		}
	}
	return true
}

func clampScope(scope []string, depth int) []string {
	if depth < len(scope) {
		return scope[:depth]
	}
	return scope
}

func (r *HoldsResolver) Resolve(assignments []RoleAssignment, scope []string) (EffectivePerms, error) {
	depth := r.planeDepth()
	eff := EffectivePerms{perms: map[string]bool{}}
	for _, a := range assignments {
		if !withinPlane(a.Scope, depth) {
			continue
		}
		if !scopeContains(clampScope(a.Scope, depth), scope) {
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
		conferred, err := r.Vocab.ExpandImplications(perms)
		if err != nil {
			return EffectivePerms{}, fmt.Errorf("Resolve: %w", err)
		}
		for _, p := range conferred {
			eff.perms[p] = true
		}
	}
	return eff, nil
}

func scopeContains(assignment, query []string) bool {
	for i, a := range assignment {
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
