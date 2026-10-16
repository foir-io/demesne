package demesne

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func compositionDefiner(t *testing.T) GenFn {
	t.Helper()
	s, err := Parse(compositionSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	for _, d := range defs {
		if d.Name == "record_composition_comp_parent" {
			return d
		}
	}
	t.Fatal("no record_composition_comp_parent definer")
	return GenFn{}
}

func TestCreateSQL_ACompositionDefinerIsOneStatementPerAccess(t *testing.T) {
	sql := compositionDefiner(t).CreateSQL()
	hasFragments(t, "composition definer", sql,
		"RETURNS boolean\nLANGUAGE plpgsql\nSTABLE\nSTRICT\nSECURITY DEFINER\nSET search_path = public\nAS $$\n#variable_conflict use_column\nBEGIN\n",
		"  IF p_access = 'read' THEN\n    RETURN EXISTS (SELECT 1 FROM record_relationships e WHERE ",
		"  IF p_access = 'write' THEN\n    RETURN EXISTS (",
		"  IF p_access = 'delete' THEN\n    RETURN EXISTS (",
		"  END IF;\n  RETURN false;\nEND\n$$;",
	)
	if strings.Contains(sql, "CASE p_access") || strings.Contains(sql, "LANGUAGE sql") {
		t.Errorf("composition definer is still one SQL statement over every access:\n%s", sql)
	}
	if n := strings.Count(sql, "RETURN EXISTS"); n != 3 {
		t.Errorf("composition definer has %d access statements, want 3:\n%s", n, sql)
	}
}

func TestCreateSQL_StrictOnlyWhenMarked(t *testing.T) {
	plain := GenFn{Name: "f", Sig: "p_x text", Body: "EXISTS (SELECT 1 FROM t WHERE t.id = p_x)"}
	if sql := plain.CreateSQL(); strings.Contains(sql, "STRICT") {
		t.Errorf("an unmarked definer rendered STRICT:\n%s", sql)
	}
	plain.Strict = true
	hasFragments(t, "strict definer", plain.CreateSQL(), "LANGUAGE sql\nSTABLE\nSTRICT\nSECURITY DEFINER\n", "  SELECT EXISTS (SELECT 1 FROM t WHERE t.id = p_x);")
}

func TestBindsEvery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sig       string
		disjuncts [][]string
		want      bool
	}{
		{"every argument equal to a column", "p_a text, p_b text", [][]string{{"a = p_a", "kind = 'x'", "b = p_b"}}, true},
		{"an argument no conjunct binds", "p_a text, p_b text", [][]string{{"a = p_a", "kind = 'x'"}}, false},
		{"an argument bound only inside a disjunction", "p_a text", [][]string{{"(a IS NULL OR a = p_a)"}}, false},
		{"an argument tested for absence", "p_a text", [][]string{{"(a IS NULL OR p_a = '' OR a = p_a)"}}, false},
		{"a second disjunct that leaves an argument free", "p_a text, p_b text", [][]string{{"a = p_a", "b = p_b"}, {"a = p_a"}}, false},
		{"every disjunct binding every argument", "p_a text, p_b text", [][]string{{"a = p_a", "b = p_b"}, {"g.a = p_a", "gc.b = p_b"}}, true},
		{"a longer name ending in the argument", "p_id text", [][]string{{"a = pp_id"}}, false},
		{"no arguments", "", [][]string{{"a = 'x'"}}, true},
	} {
		if got := bindsEvery(tc.sig, tc.disjuncts...); got != tc.want {
			t.Errorf("%s: bindsEvery = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStrict_AScopedProbeIsNotStrictAndTheRestOfTheLadderIs(t *testing.T) {
	e := emitReach(t, reachFixture)
	for name, want := range map[string]bool{
		"approvals_reach":              true,
		"approvals_reach_set":          true,
		"approvals_reach_unscoped":     true,
		"approvals_reach_unscoped_set": true,
		"approvals_reach_in_space":     false,
		"approvals_reach_in_folder":    false,
	} {
		if got := e.definer(t, name).Strict; got != want {
			t.Errorf("%s Strict = %v, want %v", name, got, want)
		}
	}
}

func TestStrict_TheDefinersAPolicyCallsWithAClaimAreStrict(t *testing.T) {
	s, err := Parse(armProbeSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	strict := map[string]bool{}
	for _, d := range defs {
		strict[d.Name] = d.Strict
	}
	for _, name := range []string{
		"resource_acl_grants_record",
		"team_acl_grants",
		"group_can_view",
		"record_can_view",
		"record_composition_comp_parent",
		"record_composition_slice_root",
	} {
		got, ok := strict[name]
		if !ok {
			t.Errorf("no %s definer", name)
			continue
		}
		if !got {
			t.Errorf("%s is not strict, so a call with an absent claim is planned and run to answer false", name)
		}
	}
}

var argOutsideEquality = regexp.MustCompile(`(\w+) (IS NULL|IS NOT NULL|= '')|COALESCE\((\w+)`)

func TestStrict_NoStrictDefinerReadsAnArgumentOutsideAnEquality(t *testing.T) {
	specs := map[string]string{"composition": compositionSpec, "arm probe": armProbeSpec, "reach": reachFixture}
	paths, err := filepath.Glob("examples/*.demesne")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		specs[p] = string(b)
	}
	checked := 0
	for label, src := range specs {
		s, err := Parse(src)
		if err != nil {
			t.Fatalf("%s: parse: %v", label, err)
		}
		defs, err := s.EmitDefiners()
		if err != nil {
			continue
		}
		for _, d := range defs {
			if !d.Strict {
				continue
			}
			checked++
			text := d.Text()
			for _, arg := range sigArgs(d.Sig) {
				if arg == d.ArmParam {
					continue
				}
				if !strings.Contains(text, " = "+arg) {
					t.Errorf("%s: strict %s never compares %s to a column:\n%s", label, d.Name, arg, text)
				}
				for _, m := range argOutsideEquality.FindAllStringSubmatch(text, -1) {
					if m[1] == arg || m[3] == arg {
						t.Errorf("%s: strict %s reads %s outside an equality (%q), so a null there may not answer false:\n%s", label, d.Name, arg, m[0], text)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no strict definer was checked")
	}
}
