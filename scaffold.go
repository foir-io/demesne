package demesne

import (
	"fmt"
	"sort"
	"strings"
)

type ScaffoldOptions struct {
	MinContainerRefs int
}

type scafFKGraph struct {
	refsTo  map[string]map[string]bool
	colInto map[string]map[string]int
	fkOut   map[string]map[string]bool
}

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

func scafDetectLevels(g scafFKGraph, threshold int) (isLevel map[string]bool, levelName map[string]string) {
	isLevel = map[string]bool{}
	levelName = map[string]string{}
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

func scafComputeDepths(g scafFKGraph, isLevel map[string]bool) (depth map[string]int, parentTable map[string]string) {
	depth = map[string]int{}
	parentTable = map[string]string{}
	var computeDepth func(c string) int
	computeDepth = func(c string) int {
		if d, ok := depth[c]; ok {
			return d
		}
		depth[c] = 0
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

func (sc *Schema) scafScopePath(t string, kept []string, levelName, parentTable map[string]string) []string {

	has := map[string]bool{}
	for _, c := range kept {
		if sc.hasColumn(t, levelName[c]+"_id") {
			has[levelName[c]] = true
		}
	}

	var path []string
	for _, c := range kept {
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

	levelOfCol := map[string]string{}
	for _, c := range kept {
		levelOfCol[levelName[c]+"_id"] = levelName[c]
	}

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
