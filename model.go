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

// LevelByName returns the named level, or nil.
func (t *Topology) LevelByName(name string) *Level {
	for _, l := range t.Levels {
		if l.Name == name {
			return l
		}
	}
	return nil
}

// Chain returns the topology levels ordered root → leaf, and verifies the
// linear-chain invariant (V1): exactly one root, every parent resolves, every
// level has at most one child (no branching), no cycles, all levels reachable
// from the root in one path.
func (t *Topology) Chain() ([]*Level, error) {
	if t == nil || len(t.Levels) == 0 {
		return nil, fmt.Errorf("topology: no levels declared")
	}

	var roots []*Level
	childOf := map[string]*Level{} // parent name → its (single) child
	for _, l := range t.Levels {
		if l.Parent == "" {
			roots = append(roots, l)
			continue
		}
		if t.LevelByName(l.Parent) == nil {
			return nil, fmt.Errorf("line %d: level %q has unknown parent %q", l.Pos.Line, l.Name, l.Parent)
		}
		if existing, ok := childOf[l.Parent]; ok {
			return nil, fmt.Errorf("line %d: topology is not a linear chain — level %q forks (%q and %q share parent %q)",
				l.Pos.Line, l.Parent, existing.Name, l.Name, l.Parent)
		}
		childOf[l.Parent] = l
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("topology: want exactly one root level (no parent), found %d", len(roots))
	}

	chain := []*Level{roots[0]}
	seen := map[string]bool{roots[0].Name: true}
	for cur := roots[0]; ; {
		next, ok := childOf[cur.Name]
		if !ok {
			break
		}
		if seen[next.Name] {
			return nil, fmt.Errorf("topology: cycle through level %q", next.Name)
		}
		seen[next.Name] = true
		chain = append(chain, next)
		cur = next
	}
	if len(chain) != len(t.Levels) {
		return nil, fmt.Errorf("topology: %d level(s) not reachable from the root in a single chain", len(t.Levels)-len(chain))
	}
	return chain, nil
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
	chain, err := s.Topology.Chain()
	if err != nil {
		return nil, false, err
	}
	anchorIdx := -1
	for i, l := range chain {
		if l.Name == sub.Anchor {
			anchorIdx = i
			break
		}
	}
	if anchorIdx < 0 {
		return nil, false, fmt.Errorf("line %d: subject %q anchors at unknown level %q", sub.Pos.Line, sub.Name, sub.Anchor)
	}
	virtualAnchor = chain[anchorIdx].Virtual
	for i := 0; i <= anchorIdx; i++ {
		if !chain[i].Virtual {
			cols = append(cols, chain[i].Name+"_id")
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
	chain, err := s.Topology.Chain()
	if err != nil {
		return nil, err
	}
	anchorIdx := -1
	for i, l := range chain {
		if l.Name == sub.Anchor {
			anchorIdx = i
			break
		}
	}
	if anchorIdx < 0 {
		return nil, fmt.Errorf("subject %q anchors at unknown level %q", sub.Name, sub.Anchor)
	}
	var free []string
	for i := anchorIdx + 1; i < len(chain); i++ {
		if !chain[i].Virtual {
			free = append(free, chain[i].Name+"_id")
		}
	}
	return free, nil
}
