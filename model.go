package demesne

import "fmt"

type CostClass int

const (
	Inline CostClass = iota
	Definer
	Closure
)

func (c CostClass) String() string {
	switch c {
	case Definer:
		return "definer"
	case Closure:
		return "closure"
	default:
		return "inline"
	}
}

func (r *Relation) CostClass() CostClass {
	switch r.Repr.(type) {
	case ViaColumn:
		return Inline
	case ViaGroup:
		return Closure
	case ViaClosure:
		return Closure
	default:
		return Definer
	}
}

func (s *Spec) subjectByName(name string) *Subject {
	for _, sub := range s.Subjects {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

func (s *Spec) levelIsVirtual(name string) bool {
	if l := s.Topology.LevelByName(name); l != nil {
		return l.Virtual
	}
	return false
}

func (s *Spec) objectByName(name string) *Object {
	for _, o := range s.Objects {
		if o.Name == name {
			return o
		}
	}
	return nil
}

func (s *Spec) grantByName(name string) *Grant {
	for _, g := range s.Grants {
		if g.Name == name {
			return g
		}
	}
	return nil
}

func (t *Topology) LevelByName(name string) *Level {
	for _, l := range t.Levels {
		if l.Name == name {
			return l
		}
	}
	return nil
}

func (t *Topology) Chain() ([]*Level, error) {
	if t == nil || len(t.Levels) == 0 {
		return nil, fmt.Errorf("topology: no levels declared")
	}

	var roots int
	indeg := map[string]int{}
	children := map[string][]*Level{}
	for _, l := range t.Levels {
		if l.isRoot() {
			roots++
			continue
		}
		for _, par := range l.Parents {
			if t.LevelByName(par) == nil {
				return nil, fmt.Errorf("line %d: level %q has unknown parent %q", l.Pos.Line, l.Name, par)
			}
			indeg[l.Name]++
			children[par] = append(children[par], l)
		}
	}
	if roots != 1 {
		return nil, fmt.Errorf("topology: want exactly one root level (no parent), found %d", roots)
	}

	var order []*Level
	var queue []*Level
	for _, l := range t.Levels {
		if indeg[l.Name] == 0 {
			queue = append(queue, l)
		}
	}
	done := map[string]int{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)
		for _, ch := range children[cur.Name] {
			done[ch.Name]++
			if done[ch.Name] == indeg[ch.Name] {
				queue = append(queue, ch)
			}
		}
	}
	if len(order) != len(t.Levels) {
		return nil, fmt.Errorf("topology: %d level(s) not reachable from the root (cycle or disconnected)", len(t.Levels)-len(order))
	}
	return order, nil
}

func (t *Topology) AncestorPaths(name string) ([][]*Level, error) {
	l := t.LevelByName(name)
	if l == nil {
		return nil, fmt.Errorf("unknown level %q", name)
	}
	if l.isRoot() {
		return [][]*Level{{l}}, nil
	}
	var paths [][]*Level
	for _, par := range l.Parents {
		up, err := t.AncestorPaths(par)
		if err != nil {
			return nil, err
		}
		for _, p := range up {
			paths = append(paths, append(append([]*Level{}, p...), l))
		}
	}
	return paths, nil
}

func (t *Topology) AncestorPath(name string) ([]*Level, error) {
	paths, err := t.AncestorPaths(name)
	if err != nil {
		return nil, err
	}
	if len(paths) != 1 {
		return nil, fmt.Errorf("level %q has %d ancestor paths (multi-parent) — only single-path levels can be pinned here", name, len(paths))
	}
	return paths[0], nil
}

func (t *Topology) descendants(name string) ([]*Level, error) {
	order, err := t.Chain()
	if err != nil {
		return nil, err
	}
	var out []*Level
	for _, l := range order {
		if l.Name == name {
			continue
		}
		paths, err := t.AncestorPaths(l.Name)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			if containsLevel(p, name) {
				out = append(out, l)
				break
			}
		}
	}
	return out, nil
}

func containsLevel(path []*Level, name string) bool {
	for _, l := range path {
		if l.Name == name {
			return true
		}
	}
	return false
}

func (s *Spec) nonVirtualChain() ([]*Level, error) {
	chain, err := s.Topology.Chain()
	if err != nil {
		return nil, err
	}
	var out []*Level
	for _, l := range chain {
		if !l.Virtual {
			out = append(out, l)
		}
	}
	return out, nil
}

func (s *Spec) ClaimsContract() ([]string, error) {
	entries, err := s.ClaimsContractEntries()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Key
	}
	return out, nil
}

func (s *Spec) PinnedColumns(sub *Subject) (cols []string, virtualAnchor bool, err error) {

	path, err := s.Topology.AncestorPath(sub.Anchor)
	if err != nil {
		return nil, false, fmt.Errorf("line %d: subject %q anchor %q: %w", sub.Pos.Line, sub.Name, sub.Anchor, err)
	}
	virtualAnchor = path[len(path)-1].Virtual
	for _, l := range path {
		if !l.Virtual {
			cols = append(cols, l.claimKey())
		}
	}
	return cols, virtualAnchor, nil
}

func (s *Spec) FreeColumns(sub *Subject) ([]string, error) {
	if sub.Reach != "descendants" {
		return nil, nil
	}

	desc, err := s.Topology.descendants(sub.Anchor)
	if err != nil {
		return nil, fmt.Errorf("subject %q: %w", sub.Name, err)
	}
	var free []string
	for _, l := range desc {
		if !l.Virtual {
			free = append(free, l.claimKey())
		}
	}
	return free, nil
}
