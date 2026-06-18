package demesne

import (
	"strings"
	"testing"
)

// The governed-table schema is spec-declared (`tables schema "<name>"`) and qualifies
// every emitted DDL reference to an adopter table — ENABLE/FORCE RLS, CREATE POLICY,
// and the closure/group CREATE TRIGGER. Omitting the block defaults to "public" (the
// Postgres default schema), so existing specs emit byte-identically. This closes the
// portability gap for an adopter whose governed tables don't live in `public`.

const tableSchemaSpec = `
tables schema "app"
topology { level tenant level project parent tenant }
vocabulary v { permission a:read  preset r @ project = a:read }
subject member { anchor tenant reach descendants identifies sub roles configurable v binds admin }
object thing {
  table  things
  scoped tenant > project
  relation m: member via role
  permission view = m @rls maps select
}
`

func TestTableSchema_EnablementAndPolicy(t *testing.T) {
	s := mustSpec(t, tableSchemaSpec)
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if got := rls.EnablementSQL(); !strings.Contains(got, "ALTER TABLE app.things ENABLE ROW LEVEL SECURITY") ||
		!strings.Contains(got, "ALTER TABLE app.things FORCE ROW LEVEL SECURITY") {
		t.Errorf("EnablementSQL did not qualify with the declared schema:\n%s", got)
	}
	if strings.Contains(rls.EnablementSQL(), "public.") {
		t.Errorf("EnablementSQL still references public.:\n%s", rls.EnablementSQL())
	}
	pol := rls.PolicySQL("authenticated")
	if !strings.Contains(pol, "ON app.things") {
		t.Errorf("PolicySQL did not qualify with the declared schema:\n%s", pol)
	}
	if strings.Contains(pol, "public.") {
		t.Errorf("PolicySQL still references public.:\n%s", pol)
	}
}

// Default (no `tables schema` block) → "public", byte-identical with prior behaviour.
func TestTableSchema_DefaultsToPublic(t *testing.T) {
	const src = `
topology { level tenant level project parent tenant }
vocabulary v { permission a:read  preset r @ project = a:read }
subject member { anchor tenant reach descendants identifies sub roles configurable v binds admin }
object thing { table things; scoped tenant > project; relation m: member via role; permission view = m @rls maps select }
`
	s := mustSpec(t, src)
	rls, _ := s.EmitRLS()
	if !strings.Contains(rls.EnablementSQL(), "ALTER TABLE public.things") {
		t.Errorf("default enablement should use public.:\n%s", rls.EnablementSQL())
	}
	if !strings.Contains(rls.PolicySQL("authenticated"), "ON public.things") {
		t.Errorf("default policy should use public.:\n%s", rls.PolicySQL("authenticated"))
	}
}

// The closure-trigger DDL binds ON the declared table schema.
func TestTableSchema_ClosureTrigger(t *testing.T) {
	s := mustSpec(t, "tables schema \"app\"\n"+closureSpec)
	sql := s.TriggersSQL()
	if !strings.Contains(sql, "ON app.folders") {
		t.Errorf("closure trigger did not bind ON the declared schema:\n%s", sql)
	}
	if strings.Contains(sql, "ON public.folders") {
		t.Errorf("closure trigger still binds ON public.:\n%s", sql)
	}
}

// The group-rebuild trigger DDL binds ON the declared table schema.
func TestTableSchema_GroupTrigger(t *testing.T) {
	s := mustSpec(t, "tables schema \"app\"\n"+groupSpec)
	triggers := s.EmitGroupTriggers()
	if len(triggers) == 0 {
		t.Fatal("no group triggers emitted")
	}
	sql := triggers[0].TriggerSQL()
	if !strings.Contains(sql, "ON app.group_members") {
		t.Errorf("group trigger did not bind ON the declared schema:\n%s", sql)
	}
	if strings.Contains(sql, "ON public.group_members") {
		t.Errorf("group trigger still binds ON public.:\n%s", sql)
	}
}

// A duplicate `tables schema` block is rejected (mirrors the definers block).
func TestTableSchema_DuplicateRejected(t *testing.T) {
	const src = `
tables schema "app"
tables schema "other"
topology { level tenant }
vocabulary v { permission a:read  preset r @ tenant = a:read }
subject member { anchor tenant reach descendants identifies sub roles configurable v binds admin }
object thing { table things; scoped tenant; relation m: member via role; permission view = m @rls maps select }
`
	if _, err := Parse(src); err == nil {
		t.Error("expected a duplicate tables block to be rejected")
	}
}
