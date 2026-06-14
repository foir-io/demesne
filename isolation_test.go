package demesne

import (
	"fmt"
	"math/rand"
	"testing"
)

// V7 — the isolation meta-invariant, as a GENERATIVE property over random
// linear topologies + subjects (RFC §9). This is the template-level half: it
// proves the §6.2 scope-column model fails closed between siblings and only
// grants unconditional reach to a virtual-anchored subject — independent of the
// emitted SQL. The SQL-level half (assert the *emitted predicate* grants no
// cross-sibling row) binds in once the RLS emitter exists and reuses this same
// generator.
//
// The theorem asserted for EVERY generated (topology, subject):
//  1. A subject anchored at a NON-virtual level pins a non-empty scope-column
//     set whose deepest column is the anchor's own — so two subjects at sibling
//     anchor nodes are isolated by construction (fail-closed between siblings).
//  2. A subject pins the EMPTY set iff its anchor is virtual (the sanctioned
//     operator bypass) — there is no accidental unconditional reach.
//  3. `reach descendants` frees exactly the non-virtual columns below the
//     anchor; `reach self` frees none. Adding a deeper level regenerates the
//     same two templates (variable depth, two templates).

func TestV7_IsolationProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE6E5)) // fixed seed → reproducible
	for iter := 0; iter < 2000; iter++ {
		spec := genSpec(rng)
		chain, err := spec.Topology.Chain()
		if err != nil {
			t.Fatalf("iter %d: generated a non-linear topology: %v", iter, err)
		}
		nonVirtual := map[string]bool{}
		for _, l := range chain {
			if !l.Virtual {
				nonVirtual[l.Name] = true
			}
		}
		for _, sub := range spec.Subjects {
			cols, virtual, err := spec.PinnedColumns(sub)
			if err != nil {
				t.Fatalf("iter %d: PinnedColumns(%s): %v", iter, sub.Name, err)
			}

			// (2) empty pins iff virtual anchor.
			if (len(cols) == 0) != virtual {
				t.Fatalf("iter %d: subject %s anchor=%s pins=%v virtual=%v — empty-pin must equal virtual-anchor",
					iter, sub.Name, sub.Anchor, cols, virtual)
			}

			// (1) non-virtual anchor ⇒ deepest pinned column is the anchor's own.
			if !virtual {
				want := sub.Anchor + "_id"
				if cols[len(cols)-1] != want {
					t.Fatalf("iter %d: subject %s deepest pin = %q, want anchor column %q (sibling isolation)",
						iter, sub.Name, cols[len(cols)-1], want)
				}
			}

			// (3) descendants frees below-anchor non-virtual columns; self frees none.
			free, err := spec.FreeColumns(sub)
			if err != nil {
				t.Fatalf("iter %d: FreeColumns(%s): %v", iter, sub.Name, err)
			}
			if sub.Reach == "self" && len(free) != 0 {
				t.Fatalf("iter %d: subject %s reach=self but frees %v", iter, sub.Name, free)
			}
			// pinned ∪ free must cover exactly the non-virtual chain (no column
			// is both pinned and free; none is dropped).
			seen := map[string]int{}
			for _, c := range cols {
				seen[c]++
			}
			for _, c := range free {
				seen[c]++
			}
			for c, n := range seen {
				if n != 1 {
					t.Fatalf("iter %d: subject %s column %q appears %d times across pinned+free", iter, sub.Name, c, n)
				}
			}
			if sub.Reach == "descendants" && len(seen) != len(nonVirtual) {
				t.Fatalf("iter %d: subject %s descendants pinned+free covers %d cols, want all %d non-virtual",
					iter, sub.Name, len(seen), len(nonVirtual))
			}
		}
	}
}

// TestV7_DepthRegeneratesSameTemplate is the concrete §6.2 claim: a
// tenant-anchored descendants subject frees one more column when a level is
// inserted, with no new template.
func TestV7_DepthRegeneratesSameTemplate(t *testing.T) {
	two := mustSpec(t, `
		topology { level tenant level project parent tenant }
		subject admin { anchor tenant reach descendants identifies sub roles none }
	`)
	three := mustSpec(t, `
		topology { level tenant level workspace parent tenant level project parent workspace }
		subject admin { anchor tenant reach descendants identifies sub roles none }
	`)
	free2, _ := two.FreeColumns(two.Subjects[0])
	free3, _ := three.FreeColumns(three.Subjects[0])
	if !eqStrs(free2, []string{"project_id"}) {
		t.Errorf("2-chain admin@tenant frees %v, want [project_id]", free2)
	}
	if !eqStrs(free3, []string{"workspace_id", "project_id"}) {
		t.Errorf("3-chain admin@tenant frees %v, want [workspace_id project_id]", free3)
	}
	// pinned is identical (just tenant_id) — the template didn't change.
	p2, _, _ := two.PinnedColumns(two.Subjects[0])
	p3, _, _ := three.PinnedColumns(three.Subjects[0])
	if !eqStrs(p2, []string{"tenant_id"}) || !eqStrs(p3, []string{"tenant_id"}) {
		t.Errorf("admin@tenant pins changed across depth: %v vs %v", p2, p3)
	}
}

// genSpec builds a random linear-chain topology (optionally with a virtual
// root) and one subject per level × reach mode.
func genSpec(rng *rand.Rand) *Spec {
	depth := 1 + rng.Intn(5) // 1..5 levels
	virtualRoot := rng.Intn(2) == 0
	top := &Topology{}
	names := make([]string, depth)
	for i := 0; i < depth; i++ {
		names[i] = fmt.Sprintf("l%d", i)
		lv := &Level{Name: names[i]}
		if i == 0 {
			lv.Virtual = virtualRoot
		} else {
			lv.Parents = []string{names[i-1]}
		}
		top.Levels = append(top.Levels, lv)
	}
	s := &Spec{Topology: top}
	n := 0
	for i := 0; i < depth; i++ {
		for _, reach := range []string{"self", "descendants"} {
			s.Subjects = append(s.Subjects, &Subject{
				Name:       fmt.Sprintf("s%d", n),
				Anchor:     names[i],
				Reach:      reach,
				Identifies: "sub",
			})
			n++
		}
	}
	return s
}

func mustSpec(t *testing.T, src string) *Spec {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}
