package demesne

import (
	"strings"
	"testing"
)

const selfTermSpec = `
topology { level tenant level project parent tenant }
vocabulary v { permission c:r }
subject principal { anchor tenant reach descendants identifies actor_id roles configurable v binds admin }
object thing {
  table  things
  scoped tenant
  permission view   = @scoped + @self(actor_col) @rls maps select
  permission create = @scoped @rls maps insert selfcheck actor_col
}
`

func TestSelfTerm_TopLevelDisjunctBoundToPrincipal(t *testing.T) {
	s := mustSpec(t, selfTermSpec)
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	cs := findPolicy(rls, "things_select")
	if cs == nil {
		t.Fatalf("no things_select (unsupported: %v)", rls.Unsupported)
	}
	self := "actor_col = (current_setting('request.jwt.claims', true)::json ->> 'actor_id')"
	if !strings.HasPrefix(cs.Using, self) {
		t.Errorf("@self must be a TOP-LEVEL disjunct bound to the principal's Identifies, not inside containment:\n%s", cs.Using)
	}
	if !strings.Contains(cs.Using, "OR (tenant_id") {
		t.Errorf("containment should be a separate OR branch:\n%s", cs.Using)
	}
	if strings.Contains(cs.Using, "'sub'") {
		t.Errorf("@self must resolve the principal claim, not a hardcoded 'sub':\n%s", cs.Using)
	}
}

func TestSelfCheck_WrapsInsertGuardBoundToPrincipal(t *testing.T) {
	s := mustSpec(t, selfTermSpec)
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	ci := findPolicy(rls, "things_insert")
	if ci == nil {
		t.Fatalf("no things_insert (unsupported: %v)", rls.Unsupported)
	}
	guard := "(actor_col IS NULL OR actor_col = (current_setting('request.jwt.claims', true)::json ->> 'actor_id')) AND ("
	if !strings.HasPrefix(ci.Check, guard) {
		t.Errorf("selfcheck must AND a (col IS NULL OR col = principal) guard over the whole predicate:\n%s", ci.Check)
	}
	if !strings.Contains(ci.Check, "tenant_id = ") {
		t.Errorf("insert guard should still carry the scope predicate:\n%s", ci.Check)
	}
	if strings.Contains(ci.Check, "'sub'") {
		t.Errorf("selfcheck must resolve the principal claim, not a hardcoded 'sub':\n%s", ci.Check)
	}
}
