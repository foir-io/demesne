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

// Scaffold renders a starter `.demesne` spec from the schema's foreign-key graph.
func (sc *Schema) Scaffold(opts ScaffoldOptions) (string, error) {
	threshold := opts.MinContainerRefs
	if threshold <= 0 {
		threshold = 3
	}

	// Foreign-key aggregates (ignore self-FKs — those are hierarchies, not
	// tenancy containers; they belong to `via closure`, not the topology).
	refsTo := map[string]map[string]bool{} // container → set of referencing tables
	colInto := map[string]map[string]int{} // container → fk column name → count
	fkOut := map[string]map[string]bool{}  // table → set of containers it references
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
		if refsTo[fk.RefTable] == nil {
			refsTo[fk.RefTable] = map[string]bool{}
			colInto[fk.RefTable] = map[string]int{}
		}
		refsTo[fk.RefTable][fk.Table] = true
		colInto[fk.RefTable][fk.Column]++
		if fkOut[fk.Table] == nil {
			fkOut[fk.Table] = map[string]bool{}
		}
		fkOut[fk.Table][fk.RefTable] = true
	}

	// Level containers: FK targets referenced by >= threshold distinct tables.
	isLevel := map[string]bool{}
	levelName := map[string]string{} // container table → level name (from its dominant FK column, minus _id)
	for c, refs := range refsTo {
		if len(refs) < threshold {
			continue
		}
		best, bestN := "", -1
		for col, n := range colInto[c] {
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
	if len(isLevel) == 0 {
		return "", fmt.Errorf("scaffold: no tenancy container found (no table referenced by >= %d others via FK) — supply foreign keys, or lower MinContainerRefs", threshold)
	}

	// Level depth + parent: a level's parent is the DEEPEST other level its own
	// table references (so customers→{tenants,projects} parents to project, not
	// tenant). Depth memoised over the level-only FK graph.
	depth := map[string]int{}
	var parentTable = map[string]string{} // container → parent container
	var computeDepth func(c string) int
	computeDepth = func(c string) int {
		if d, ok := depth[c]; ok {
			return d
		}
		depth[c] = 0 // guard against cycles
		best, bestD := "", -1
		for ref := range fkOut[c] {
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

	// Keep a single-root tree: choose the most-referenced root, then keep only
	// levels whose root-ward chain reaches it. Others are reported, not emitted
	// (a multi-root topology is invalid; the human picks).
	roots := []string{}
	for c := range isLevel {
		if parentTable[c] == "" {
			roots = append(roots, c)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(refsTo[roots[i]]) != len(refsTo[roots[j]]) {
			return len(refsTo[roots[i]]) > len(refsTo[roots[j]])
		}
		return roots[i] < roots[j]
	})
	chosenRoot := roots[0]
	inTree := map[string]bool{}
	var dropped []string
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

	// Order the kept levels root→leaf (by depth, then name) for the topology block.
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

	b.WriteString("topology {\n")
	for _, c := range kept {
		if parentTable[c] != "" && inTree[parentTable[c]] {
			fmt.Fprintf(&b, "  level %s parent %s\n", levelName[c], levelName[parentTable[c]])
		} else {
			fmt.Fprintf(&b, "  level %s\n", levelName[c])
		}
	}
	b.WriteString("}\n")
	if len(dropped) > 0 {
		sort.Strings(dropped)
		fmt.Fprintf(&b, "// Other container(s) not in the chosen tree (would fork the root): %s\n", strings.Join(dropped, ", "))
	}
	b.WriteString("\n")

	// Objects: every non-level table whose level columns form a root→leaf prefix.
	objTables := []string{}
	for t := range sc.tables {
		if !isLevel[t] {
			objTables = append(objTables, t)
		}
	}
	sort.Strings(objTables)
	var unscoped []string
	for _, t := range objTables {
		// The level columns this table carries, deepest-first.
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
		if len(path) == 0 {
			unscoped = append(unscoped, t)
			continue
		}
		fmt.Fprintf(&b, "object %s {\n", t)
		fmt.Fprintf(&b, "  table  %s\n", t)
		fmt.Fprintf(&b, "  scoped %s\n", strings.Join(path, " > "))
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
		fmt.Fprintf(&b, "// Not scaffolded (no tenancy scope columns found): %s%s\n", strings.Join(shown, ", "), suffix)
	}
	return b.String(), nil
}
