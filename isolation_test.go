package demesne

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestV7_IsolationProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE6E5))
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

			if (len(cols) == 0) != virtual {
				t.Fatalf("iter %d: subject %s anchor=%s pins=%v virtual=%v — empty-pin must equal virtual-anchor",
					iter, sub.Name, sub.Anchor, cols, virtual)
			}

			if !virtual {
				want := sub.Anchor + "_id"
				if cols[len(cols)-1] != want {
					t.Fatalf("iter %d: subject %s deepest pin = %q, want anchor column %q (sibling isolation)",
						iter, sub.Name, cols[len(cols)-1], want)
				}
			}

			free, err := spec.FreeColumns(sub)
			if err != nil {
				t.Fatalf("iter %d: FreeColumns(%s): %v", iter, sub.Name, err)
			}
			if sub.Reach == "self" && len(free) != 0 {
				t.Fatalf("iter %d: subject %s reach=self but frees %v", iter, sub.Name, free)
			}

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

	p2, _, _ := two.PinnedColumns(two.Subjects[0])
	p3, _, _ := three.PinnedColumns(three.Subjects[0])
	if !eqStrs(p2, []string{"tenant_id"}) || !eqStrs(p3, []string{"tenant_id"}) {
		t.Errorf("admin@tenant pins changed across depth: %v vs %v", p2, p3)
	}
}

func genSpec(rng *rand.Rand) *Spec {
	depth := 1 + rng.Intn(5)
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
