package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// Scaffold heuristics (WS4): turn an introspected Schema into a STARTER
// `.demesne` spec, so adopting Demesne on an existing database isn't a blank
// page. The schema alone cannot decide policy — in particular it cannot tell a
// tenancy LEVEL (a container every row is scoped within) from an owner PRINCIPAL
// (a customer/user a row belongs to); both look like "a table many rows FK to."
// So the output is explicitly a DRAFT: it infers the tenancy hierarchy from the
// foreign-key graph, emits containment-only (`@scoped`) objects, and leaves owner
// axes / roles / descriptors / subjects for the human to add. It is generated to
// PARSE; it is not guaranteed to express the real policy.

// ScaffoldOptions tunes starter-spec generation.
type ScaffoldOptions struct {
	// MinContainerRefs: a table referenced by at least this many distinct other
	// tables is treated as a tenancy level. Default 3 (a real tenancy container is
	// referenced widely; a lower bound pulls in owner-principal tables).
	MinContainerRefs int
}

// scafFKGraph holds the foreign-key aggregates the scaffolder reasons over.
type scafFKGraph struct {
	refsTo  map[string]map[string]bool // container → set of referencing tables
	colInto map[string]map[string]int  // container → fk column name → count
	fkOut   map[string]map[string]bool // table → set of containers it references
}

// scafBuildFKGraph aggregates the schema's foreign keys (ignoring self-FKs and
// any FK that isn't a clean `<x>_id → <container>.id`, which don't signal a
// tenancy level).
func (sc *Schema) scafBuildFKGraph() scafFKGraph {
	g := scafFKGraph{
		refsTo:  map[string]map[string]bool{},
		colInto: map[string]map[string]int{},
		fkOut:   map[string]map[string]bool{},
	}
	for _, fk := range sc.fks {
		if fk.Table == fk.RefTable {
			continue
		}
		// Only clean `<x>_id → <container>.id` foreign keys signal a tenancy level.
		// A FK to a non-`id` key (e.g. model_key → models.key) is a domain
		// reference, not a containment axis whose scope column is `<level>_id`.
		if !strings.HasSuffix(fk.Column, "_id") || fk.RefColumn != "id" {
			continue
		}
		if g.refsTo[fk.RefTable] == nil {
			g.refsTo[fk.RefTable] = map[string]bool{}
			g.colInto[fk.RefTable] = map[string]int{}
		}
		g.refsTo[fk.RefTable][fk.Table] = true
		g.colInto[fk.RefTable][fk.Column]++
		if g.fkOut[fk.Table] == nil {
			g.fkOut[fk.Table] = map[string]bool{}
		}
		g.fkOut[fk.Table][fk.RefTable] = true
	}
	return g
}

// scafDetectLevels picks the level containers: FK targets referenced by >=
// threshold distinct tables, named from their dominant FK column (minus _id).
func scafDetectLevels(g scafFKGraph, threshold int) (isLevel map[string]bool, levelName map[string]string) {
	isLevel = map[string]bool{}
	levelName = map[string]string{} // container table → level name
	for c, refs := range g.refsTo {
		if len(refs) < threshold {
			continue
		}
		best, bestN := "", -1
		for col, n := range g.colInto[c] {
			if n > bestN || (n == bestN && col < best) {
				best, bestN = col, n
			}
		}
		name := strings.TrimSuffix(best, "_id")
		if name == "" {
			continue
		}
		isLevel[c] = true
		levelName[c] = name
	}
	return isLevel, levelName
}

// scafComputeDepths computes each level's depth + parent: a level's parent is
// the DEEPEST other level its own table references (so customers→{tenants,
// projects} parents to project, not tenant). Depth memoised over the
// level-only FK graph.
func scafComputeDepths(g scafFKGraph, isLevel map[string]bool) (depth map[string]int, parentTable map[string]string) {
	depth = map[string]int{}
	parentTable = map[string]string{} // container → parent container
	var computeDepth func(c string) int
	computeDepth = func(c string) int {
		if d, ok := depth[c]; ok {
			return d
		}
		depth[c] = 0 // guard against cycles
		best, bestD := "", -1
		for ref := range g.fkOut[c] {
			if !isLevel[ref] || ref == c {
				continue
			}
			d := computeDepth(ref)
			if d > bestD || (d == bestD && ref < best) {
				best, bestD = ref, d
			}
		}
		if best != "" {
			parentTable[c] = best
			depth[c] = bestD + 1
		} else {
			depth[c] = 0
		}
		return depth[c]
	}
	for c := range isLevel {
		computeDepth(c)
	}
	return depth, parentTable
}

// scafSelectTree keeps a single-root tree: choose the most-referenced root, then
// keep only levels whose root-ward chain reaches it. Others are reported
// (dropped), not emitted (a multi-root topology is invalid; the human picks).
func scafSelectTree(g scafFKGraph, isLevel map[string]bool, levelName, parentTable map[string]string) (inTree map[string]bool, dropped []string) {
	roots := []string{}
	for c := range isLevel {
		if parentTable[c] == "" {
			roots = append(roots, c)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(g.refsTo[roots[i]]) != len(g.refsTo[roots[j]]) {
			return len(g.refsTo[roots[i]]) > len(g.refsTo[roots[j]])
		}
		return roots[i] < roots[j]
	})
	chosenRoot := roots[0]
	inTree = map[string]bool{}
	for c := range isLevel {
		r := c
		for parentTable[r] != "" {
			r = parentTable[r]
		}
		if r == chosenRoot {
			inTree[c] = true
		} else {
			dropped = append(dropped, levelName[c])
		}
	}
	return inTree, dropped
}

// scafOrderKept orders the kept levels root→leaf (by depth, then name) for the
// topology block.
func scafOrderKept(inTree map[string]bool, depth map[string]int, levelName map[string]string) []string {
	kept := []string{}
	for c := range inTree {
		kept = append(kept, c)
	}
	sort.Slice(kept, func(i, j int) bool {
		if depth[kept[i]] != depth[kept[j]] {
			return depth[kept[i]] < depth[kept[j]]
		}
		return levelName[kept[i]] < levelName[kept[j]]
	})
	return kept
}

// scafScopePath returns the longest root→leaf chain of level columns table t
// fully carries (deepest-first prefix), or nil if it carries none.
func (sc *Schema) scafScopePath(t string, kept []string, levelName, parentTable map[string]string) []string {
	// The level columns this table carries.
	has := map[string]bool{}
	for _, c := range kept {
		if sc.hasColumn(t, levelName[c]+"_id") {
			has[levelName[c]] = true
		}
	}
	// Longest root→leaf chain fully present.
	var path []string
	for _, c := range kept { // kept is root→leaf order
		ln := levelName[c]
		if !has[ln] {
			continue
		}
		parentOK := parentTable[c] == "" || (len(path) > 0 && path[len(path)-1] == levelName[parentTable[c]])
		if parentOK {
			path = append(path, ln)
		}
	}
	return path
}

// scafRenderTopology writes the topology block (and any dropped-container note).
func scafRenderTopology(b *strings.Builder, kept []string, levelName, parentTable map[string]string, inTree map[string]bool, dropped []string) {
	b.WriteString("topology {\n")
	for _, c := range kept {
		if parentTable[c] != "" && inTree[parentTable[c]] {
			fmt.Fprintf(b, "  level %s parent %s\n", levelName[c], levelName[parentTable[c]])
		} else {
			fmt.Fprintf(b, "  level %s\n", levelName[c])
		}
	}
	b.WriteString("}\n")
	if len(dropped) > 0 {
		sort.Strings(dropped)
		fmt.Fprintf(b, "// Other container(s) not in the chosen tree (would fork the root): %s\n", strings.Join(dropped, ", "))
	}
	b.WriteString("\n")
}

// scafRenderObjects writes one @scoped object per non-level table whose level
// columns form a root→leaf prefix, plus a note for any left unscoped.
func (sc *Schema) scafRenderObjects(b *strings.Builder, kept []string, isLevel map[string]bool, levelName, parentTable map[string]string) {
	objTables := []string{}
	for t := range sc.tables {
		if !isLevel[t] {
			objTables = append(objTables, t)
		}
	}
	sort.Strings(objTables)
	var unscoped []string
	for _, t := range objTables {
		path := sc.scafScopePath(t, kept, levelName, parentTable)
		if len(path) == 0 {
			unscoped = append(unscoped, t)
			continue
		}
		fmt.Fprintf(b, "object %s {\n", t)
		fmt.Fprintf(b, "  table  %s\n", t)
		fmt.Fprintf(b, "  scoped %s\n", strings.Join(path, " > "))
		b.WriteString("  permission view   = @scoped @rls maps select\n")
		b.WriteString("  permission edit   = @scoped @rls maps update\n")
		b.WriteString("  permission create = @scoped @rls maps insert\n")
		b.WriteString("  permission delete = @scoped @rls maps delete\n")
		b.WriteString("}\n\n")
	}
	if len(unscoped) > 0 {
		sort.Strings(unscoped)
		shown := unscoped
		const maxShown = 20
		suffix := ""
		if len(unscoped) > maxShown {
			shown = unscoped[:maxShown]
			suffix = fmt.Sprintf(", … (+%d more)", len(unscoped)-maxShown)
		}
		fmt.Fprintf(b, "// Not scaffolded (no tenancy scope columns found): %s%s\n", strings.Join(shown, ", "), suffix)
	}
}

// Scaffold renders a starter `.demesne` spec from the schema's foreign-key graph.
func (sc *Schema) Scaffold(opts ScaffoldOptions) (string, error) {
	threshold := opts.MinContainerRefs
	if threshold <= 0 {
		threshold = 3
	}

	g := sc.scafBuildFKGraph()

	isLevel, levelName := scafDetectLevels(g, threshold)
	if len(isLevel) == 0 {
		return "", fmt.Errorf("scaffold: no tenancy container found (no table referenced by >= %d others via FK) — supply foreign keys, or lower MinContainerRefs", threshold)
	}

	depth, parentTable := scafComputeDepths(g, isLevel)
	inTree, dropped := scafSelectTree(g, isLevel, levelName, parentTable)
	kept := scafOrderKept(inTree, depth, levelName)

	levelOfCol := map[string]string{} // "<name>_id" → level name (for object scoping)
	for _, c := range kept {
		levelOfCol[levelName[c]+"_id"] = levelName[c]
	}

	// --- render ---------------------------------------------------------------
	var b strings.Builder
	fmt.Fprintf(&b, "// Demesne starter spec — GENERATED by Scaffold from %d tables, %d foreign keys.\n", len(sc.tables), len(sc.fks))
	b.WriteString("// THIS IS A DRAFT. Every line is a heuristic guess from the FK graph — review it.\n")
	b.WriteString("// Enforcement here is CONTAINMENT-ONLY (@scoped): a row is visible iff its scope\n")
	b.WriteString("// columns match the session. Add owner axes, roles, descriptors, and subjects to\n")
	b.WriteString("// express real policy. A 'level' below may actually be an owner PRINCIPAL (e.g. a\n")
	b.WriteString("// customers table) — if so, make it an owner relation, not a topology level.\n\n")

	scafRenderTopology(&b, kept, levelName, parentTable, inTree, dropped)
	sc.scafRenderObjects(&b, kept, isLevel, levelName, parentTable)

	return b.String(), nil
}
