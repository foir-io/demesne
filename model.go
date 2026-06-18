package demesne

import "fmt"

// Computed model over a parsed Spec: the linear topology chain, the derived
// claims contract, scope-column pinning per the §6.2 templates, and relation
// cost classification (§7). These are the inputs both the validators (V1–V10)
// and the emitters consume. Each function is a pure derivation — no I/O.

// CostClass is whether a term compiles to an inline sargable predicate or a
// SECURITY DEFINER function call (§7 / V3).
type CostClass int

const (
	Inline  CostClass = iota // sargable column equality
	Definer                  // a SECURITY DEFINER EXISTS over an edge/role store
	Closure                  // an indexed lookup over a trigger-maintained transitive closure (write-amplified)
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

// CostClass classifies a relation by how it must be joined: a foreign-key column
// equality is inline+sargable; a closure lookup is an indexed read over a
// trigger-maintained transitive-closure table (write-amplified — WS3 Phase C);
// everything else (edge / role / composition) is a definer-function join (§7, V3).
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

// subjectByName returns the named subject, or nil.
func (s *Spec) subjectByName(name string) *Subject {
	for _, sub := range s.Subjects {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

// levelIsVirtual reports whether the named topology level is virtual (no scope
// column / claim key). Unknown levels are treated as non-virtual.
func (s *Spec) levelIsVirtual(name string) bool {
	if l := s.Topology.LevelByName(name); l != nil {
		return l.Virtual
	}
	return false
}

// objectByName returns the named object, or nil.
func (s *Spec) objectByName(name string) *Object {
	for _, o := range s.Objects {
		if o.Name == name {
			return o
		}
	}
	return nil
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

	var roots int
	indeg := map[string]int{}          // level name → number of parents
	children := map[string][]*Level{}  // parent name → children, in declaration order
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

	// Kahn's algorithm → a deterministic topological order (every parent before
	// each child, even when a level has multiple parents — a DAG). Levels still in
	// the graph after the sort form a cycle or are unreachable.
	var order []*Level
	var queue []*Level
	for _, l := range t.Levels { // declaration order → deterministic
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

// AncestorPaths returns EVERY root→level path through the topology DAG (one path
// per distinct route, root first). A single-parent level has exactly one path
// (the chain/tree case); a multi-parent level has one per parent lineage (WS3
// Phase B) — these become the OR branches of the object's containment predicate.
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

// AncestorPath returns the UNIQUE root→level path, erroring if the level has more
// than one (a multi-parent lineage). Used where a single linear path is required
// — subject pinning and role-store scope columns. Phase B confines multi-parent
// to OBJECT containment; subjects and roles still anchor at unique-path levels.
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

// descendants returns every level strictly below the named level (every level
// some of whose ancestor paths pass through it), in topological order.
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

// ClaimsContract is the set of JWT claim keys the spec implies (V5): one claim
// key per non-virtual level (its declared `claim`, else `<level>_id`), plus each
// subject's `identifies` key. Sorted + de-duplicated. WithRLS / session minting
// are generated from this set. It is the flat KEY view of ClaimsContractEntries()
// (the structured contract that also carries each key's source); both stay in
// lockstep because this delegates to it.
func (s *Spec) ClaimsContract() ([]string, error) {
	entries, err := s.ClaimsContractEntries()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(entries)) // entries are sorted by key
	for i, e := range entries {
		out[i] = e.Key
	}
	return out, nil
}

// PinnedColumns returns the claim keys a subject's reachability predicate pins to
// per the §6.2 templates: every NON-virtual level's claim key (its declared
// `claim`, else `<level>_id`) from the root down to (and including) the subject's
// anchor. A subject whose anchor is the virtual root pins nothing — unconditional
// reach (the operator). The boolean reports whether the anchor level is virtual.
//
// reach self vs descendants share the same pinned set; they differ only in
// whether levels BELOW the anchor are free (descendants spans the subtree) —
// see FreeColumns. Sibling isolation (V7) is a consequence of a non-empty
// pinned set.
func (s *Spec) PinnedColumns(sub *Subject) (cols []string, virtualAnchor bool, err error) {
	// The pinned set is the anchor's root→anchor path (its ancestor path in the
	// tree) — the chain-era "root down to the anchor", now path-aware (WS3).
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
			free = append(free, l.claimKey())
		}
	}
	return free, nil
}
