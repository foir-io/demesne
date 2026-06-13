package demesne

import (
	"fmt"
	"sort"
)

// Computed model over a parsed Spec: the linear topology chain, the derived
// claims contract, scope-column pinning per the §6.2 templates, and relation
// cost classification (§7). These are the inputs both the validators (V1–V10)
// and the emitters consume. Each function is a pure derivation — no I/O.

// CostClass is whether a term compiles to an inline sargable predicate or a
// SECURITY DEFINER function call (§7 / V3).
type CostClass int

const (
	Inline CostClass = iota
	Definer
)

func (c CostClass) String() string {
	if c == Definer {
		return "definer"
	}
	return "inline"
}

// CostClass classifies a relation by how it must be joined: a foreign-key
// column equality is inline+sargable; an edge/role/composition traversal is a
// definer-function join (§7, V3).
func (r *Relation) CostClass() CostClass {
	if _, ok := r.Repr.(ViaColumn); ok {
		return Inline
	}
	return Definer
}

// grantByName returns the named level-scoped reachability grant, or nil.
func (s *Spec) grantByName(name string) *Grant {
	for _, g := range s.Grants {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// LevelByName returns the named level, or nil.
func (t *Topology) LevelByName(name string) *Level {
	for _, l := range t.Levels {
		if l.Name == name {
			return l
		}
	}
	return nil
}

// Chain returns the topology levels in a deterministic topological order (root
// first, parents before children) and verifies the TREE invariant (V1, relaxed
// for EID-265 WS3): exactly one root, every parent resolves, no cycles, all
// levels reachable from the root. Each level has at most one parent (the `parent`
// field is singular), but a parent MAY have multiple children — a branching tree,
// not a strict linear chain. Every object still declares a linear root→leaf
// `scoped` path through the tree (see AncestorPath); per-object emission is
// identical to the chain case along that path.
func (t *Topology) Chain() ([]*Level, error) {
	if t == nil || len(t.Levels) == 0 {
		return nil, fmt.Errorf("topology: no levels declared")
	}

	var roots []*Level
	children := map[string][]*Level{} // parent name → children, in declaration order
	for _, l := range t.Levels {
		if l.Parent == "" {
			roots = append(roots, l)
			continue
		}
		if t.LevelByName(l.Parent) == nil {
			return nil, fmt.Errorf("line %d: level %q has unknown parent %q", l.Pos.Line, l.Name, l.Parent)
		}
		children[l.Parent] = append(children[l.Parent], l)
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("topology: want exactly one root level (no parent), found %d", len(roots))
	}

	// BFS from the root in declaration order → a deterministic topological order
	// that also surfaces cycles / unreachable levels (a cycle never includes the
	// parentless root, so its members are simply unreachable and caught by count).
	var order []*Level
	seen := map[string]bool{}
	queue := []*Level{roots[0]}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		seen[cur.Name] = true
		order = append(order, cur)
		queue = append(queue, children[cur.Name]...)
	}
	if len(order) != len(t.Levels) {
		return nil, fmt.Errorf("topology: %d level(s) not reachable from the root (cycle or disconnected)", len(t.Levels)-len(order))
	}
	return order, nil
}

// AncestorPath returns the levels from the root down to (and including) the named
// level — the unique path through the tree (each level has a single parent). This
// is the per-object/level linear view the chain-era code assumed globally.
func (t *Topology) AncestorPath(name string) ([]*Level, error) {
	l := t.LevelByName(name)
	if l == nil {
		return nil, fmt.Errorf("unknown level %q", name)
	}
	var rev []*Level
	for cur := l; cur != nil; cur = t.LevelByName(cur.Parent) {
		rev = append(rev, cur)
		if cur.Parent == "" {
			break
		}
	}
	path := make([]*Level, len(rev))
	for i, lv := range rev {
		path[len(rev)-1-i] = lv // reverse to root → level
	}
	return path, nil
}

// descendants returns every level strictly below the named level in the tree
// (the subtree, across all branches), in topological order.
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
		path, err := t.AncestorPath(l.Name)
		if err != nil {
			return nil, err
		}
		for _, a := range path {
			if a.Name == name {
				out = append(out, l)
				break
			}
		}
	}
	return out, nil
}

// nonVirtualChain returns the chain with virtual levels removed (the levels
// that actually carry a scope column / claim key).
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

// ClaimsContract is the set of JWT claim keys the spec implies (V5): one
// `<level>_id` per non-virtual level, plus each subject's `identifies` key.
// Sorted + de-duplicated. WithRLS / session minting are generated from this set.
func (s *Spec) ClaimsContract() ([]string, error) {
	chain, err := s.nonVirtualChain()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, l := range chain {
		set[l.Name+"_id"] = true
	}
	for _, sub := range s.Subjects {
		if sub.Identifies != "" {
			set[sub.Identifies] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// PinnedColumns returns the scope columns a subject's reachability predicate
// pins to claim values per the §6.2 templates: every NON-virtual level from the
// root down to (and including) the subject's anchor. A subject whose anchor is
// the virtual root pins nothing — unconditional reach (the operator). The
// boolean reports whether the anchor level is virtual.
//
// reach self vs descendants share the same pinned set; they differ only in
// whether columns BELOW the anchor are free (descendants spans the subtree) —
// see FreeColumns. Sibling isolation (V7) is a consequence of a non-empty
// pinned set.
func (s *Spec) PinnedColumns(sub *Subject) (cols []string, virtualAnchor bool, err error) {
	// The pinned set is the anchor's root→anchor path (its ancestor path in the
	// tree) — the chain-era "root down to the anchor", now path-aware (WS3).
	path, err := s.Topology.AncestorPath(sub.Anchor)
	if err != nil {
		return nil, false, fmt.Errorf("line %d: subject %q anchors at unknown level %q", sub.Pos.Line, sub.Name, sub.Anchor)
	}
	virtualAnchor = path[len(path)-1].Virtual
	for _, l := range path {
		if !l.Virtual {
			cols = append(cols, l.Name+"_id")
		}
	}
	return cols, virtualAnchor, nil
}

// FreeColumns returns the scope columns left free below a subject's anchor.
// For `reach descendants` these span the subtree; for `reach self` the subject
// is locked to one node, so any non-virtual columns below the anchor would be
// pinned by the subject's own identity, not free — returned here only for the
// descendants case.
func (s *Spec) FreeColumns(sub *Subject) ([]string, error) {
	if sub.Reach != "descendants" {
		return nil, nil
	}
	// The free set is the anchor's subtree (every level below it) — the chain-era
	// "columns below the anchor", now the tree's descendants (WS3).
	desc, err := s.Topology.descendants(sub.Anchor)
	if err != nil {
		return nil, fmt.Errorf("subject %q: %w", sub.Name, err)
	}
	var free []string
	for _, l := range desc {
		if !l.Virtual {
			free = append(free, l.Name+"_id")
		}
	}
	return free, nil
}
