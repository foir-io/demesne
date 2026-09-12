package demesne

import (
	"strings"
	"testing"
)

// ============================================================================
// A GRANT'S REACH IS SPLICED AS A SET, AND CALLED AS A SCALAR.
//
// Both forms are emitted for every grant because they answer different
// questions in different places, and each is the wrong shape in the other's:
//
//	<table>_reach(grantee, value)  -> boolean. "Does this grantee reach THIS
//	                                  value." Correct inside another definer's
//	                                  body, where the value is a parameter and
//	                                  the call happens once.
//	<table>_reach_set(grantee)     -> SETOF. "What does this grantee reach."
//	                                  Correct in an RLS predicate, spliced as
//	                                  `<col> IN (SELECT …)`.
//
// WHY THE DISTINCTION IS WORTH EMITTING TWO FUNCTIONS FOR. A SECURITY DEFINER
// carrying a SET clause cannot be inlined — each blocks it independently — so
// the scalar form spliced into a policy is re-entered once per candidate row. A
// policy predicate runs on every row a sort or an aggregate has to consider and
// LIMIT cannot short-circuit it, so that cost is linear in the TABLE rather than
// in the grant. The set form resolves once as a hashed subplan.
//
// THEY ARE THE SAME PREDICATE:
//
//	EXISTS (SELECT 1 FROM T WHERE grantee = $1 AND level = row)
//	  ≡  row IN (SELECT level FROM T WHERE grantee = $1)
//
// ⚠️ Equal in a POSITIVE context, which is the only context a reach appears in.
// The two differ in three-valued logic — `x IN (…)` yields NULL where EXISTS
// yields false, when x is NULL or the set contains one — and a policy admits on
// TRUE, so NULL and false are the same admission. A reach is only ever OR'd into
// a predicate and is never negated; if that ever changes, this equivalence is
// the thing to re-derive rather than assume.
//
// The semantic half of this — that the two forms admit the same rows against a
// live database — belongs in a platform repo, where the database is. This module
// is pure, so what it can prove is the SHAPE: that both are emitted, and that
// each is used where it belongs.
// ============================================================================

// loadGrantSpec is the fixture shared by this file: grantSpec declares an
// `impersonation` grant with both bounds (active + expires), which is what makes
// the bound-parity assertion below non-vacuous.
func loadGrantSpec(t *testing.T) *Spec {
	t.Helper()
	sp, err := Parse(grantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(sp); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return sp
}

func TestGrantReachSet_BothFormsAreEmittedForEveryGrant(t *testing.T) {
	s := loadGrantSpec(t)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	byName := map[string]GenFn{}
	for _, d := range defs {
		byName[d.Name] = d
	}

	if len(s.Grants) == 0 {
		t.Fatal("the fixture spec declares no grants, so this test measured nothing — " +
			"which is indistinguishable from a pass")
	}

	for _, g := range s.Grants {
		scalar, ok := byName[g.Table+"_reach"]
		if !ok {
			t.Errorf("grant %q: no scalar %s_reach definer — another definer's body calls it, "+
				"so removing it breaks the recursion rather than merely the policies", g.Name, g.Table)
			continue
		}
		if scalar.Returns != "" && scalar.Returns != "boolean" {
			t.Errorf("grant %q: the scalar reach returns %q, want boolean", g.Name, scalar.Returns)
		}
		if !strings.HasPrefix(scalar.Body, "EXISTS (") {
			t.Errorf("grant %q: the scalar reach is not an EXISTS: %s", g.Name, scalar.Body)
		}

		set, ok := byName[g.Table+"_reach_set"]
		if !ok {
			t.Errorf("grant %q: no %s_reach_set definer — the policies would fall back to a "+
				"per-row scalar probe", g.Name, g.Table)
			continue
		}
		if want := "SETOF " + s.idType(); set.Returns != want {
			t.Errorf("grant %q: the set reach returns %q, want %q", g.Name, set.Returns, want)
		}
		// It selects the LEVEL column keyed by the GRANTEE column: the same two
		// columns the scalar compares, read in the other direction.
		if !strings.HasPrefix(set.Body, g.LevelCol+" FROM "+g.Table+" WHERE "+g.GranteeCol+" = user_id") {
			t.Errorf("grant %q: the set reach does not select %s keyed by %s: %s",
				g.Name, g.LevelCol, g.GranteeCol, set.Body)
		}
		// Whatever bounds the scalar bounds the set. A grant whose rows expire
		// must expire in both, or the set form would admit a revoked grant.
		for _, bound := range []struct{ col, frag string }{
			{g.ActiveCol, g.ActiveCol + " IS NULL"},
			{g.ExpiresCol, g.ExpiresCol + " > now()"},
		} {
			if bound.col == "" {
				continue
			}
			if !strings.Contains(set.Body, bound.frag) {
				t.Errorf("grant %q: the set reach drops the %q bound the scalar carries — it "+
					"would admit a grant the scalar refuses:\n  scalar: %s\n  set:    %s",
					g.Name, bound.col, scalar.Body, set.Body)
			}
		}
	}
}

// The policies splice the SET form. This is the half that costs, and a
// regression here is silent: the scalar is a valid boolean predicate, so a
// policy built on it is correct and merely slow.
func TestGrantReachSet_PoliciesSpliceTheSetFormAndNotTheScalar(t *testing.T) {
	s := loadGrantSpec(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	var sawSet int
	for _, p := range res.Policies {
		for _, pred := range []string{p.Using, p.Check} {
			if pred == "" {
				continue
			}
			for _, g := range s.Grants {
				scalarCall := s.definerSchema() + "." + g.Table + "_reach("
				if strings.Contains(pred, scalarCall) {
					t.Errorf("policy %s calls the per-row scalar %s — spliced into a predicate it "+
						"is re-entered once per candidate row:\n%s", p.Name, scalarCall, pred)
				}
				setCall := s.definerSchema() + "." + g.Table + "_reach_set("
				if strings.Contains(pred, setCall) {
					sawSet++
					// And it is a membership test on a COLUMN, not a bare call:
					// the row's own value has to be on the left or the predicate
					// says nothing about the row.
					if !strings.Contains(pred, " IN (SELECT "+setCall) {
						t.Errorf("policy %s calls %s outside an `IN (SELECT …)`, so it is not "+
							"testing the row against the reach:\n%s", p.Name, setCall, pred)
					}
				}
			}
		}
	}
	if sawSet == 0 {
		t.Fatal("no policy in the fixture spec splices a grant reach at all, so this test " +
			"measured nothing — which is indistinguishable from a pass")
	}
}

// A definer's BODY still calls the scalar. The set form is not a replacement:
// inside a definer the value under test is a parameter, the call happens once,
// and a membership test against a set would be strictly more work for the same
// answer.
func TestGrantReachSet_DefinerBodiesStillCallTheScalar(t *testing.T) {
	s := loadGrantSpec(t)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}

	var callers int
	for _, d := range defs {
		if strings.HasSuffix(d.Name, "_reach") || strings.HasSuffix(d.Name, "_reach_set") {
			continue // the reach definers themselves
		}
		for _, g := range s.Grants {
			if strings.Contains(d.Body, g.Table+"_reach(user_id") {
				callers++
			}
			if strings.Contains(d.Body, g.Table+"_reach_set(") {
				t.Errorf("definer %s calls the SET form in its body; inside a definer the value "+
					"is a parameter and the scalar answers it in one comparison:\n%s", d.Name, d.Body)
			}
		}
	}
	if callers == 0 {
		t.Skip("no definer in the fixture spec calls a grant reach from its body; the " +
			"negative assertion above still ran")
	}
}
