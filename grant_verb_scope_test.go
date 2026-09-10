package demesne

import (
	"strings"
	"testing"
)

// A grant's reach is one predicate and it was spliced into every table op
// alike, so a grant that exists to let a holder READ what it reaches also let
// it rewrite and destroy those rows. The permission expression cannot narrow
// that, because it never sees the reach.
//
// `confers` bounds the grant to named ops. A grant with no clause confers all
// of them, so a spec written before the clause existed emits exactly as before.
const verbScopeSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
  level org      parent project
}
vocabulary admin { permission content:read permission content:write
  preset tenant_owner @ tenant = *
  rank tenant_owner > tenant_owner }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant readonly at org via edge readonly_edge(principal_id, org_id) active revoked_at confers select
grant unbounded at org via edge unbounded_edge(principal_id, org_id) active revoked_at

subject admin    { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
subject reader   { anchor org;    reach via grant readonly;  identifies customer_id; roles none }
subject anyone   { anchor org;    reach via grant unbounded; identifies customer_id; roles none }

object doc {
  table  docs
  scoped tenant > project > org
  relation owner: reader via customer_id
  permission view   = owner @rls maps select
  permission edit   = owner @rls maps update
  permission create = owner @rls maps insert
  permission drop   = owner @rls maps delete
}
`

func emitVerbScope(t *testing.T) *RLSResult {
	t.Helper()
	s, err := Parse(verbScopeSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	return rls
}

func predicateFor(t *testing.T, rls *RLSResult, name string) string {
	t.Helper()
	for _, p := range rls.Policies {
		if p.Name == name {
			if p.Using != "" {
				return p.Using
			}
			return p.Check
		}
	}
	t.Fatalf("no %s policy emitted", name)
	return ""
}

// The headline, as a differential: the SAME reach is present on the op the
// grant confers and absent on the three it does not, so the outcome tracks the
// clause rather than some blanket presence or absence.
func TestGrantVerbs_ReachAppliesOnlyToConferredOps(t *testing.T) {
	rls := emitVerbScope(t)
	const reach = "auth.readonly_edge_reach("

	if got := predicateFor(t, rls, "docs_select"); !strings.Contains(got, reach) {
		t.Errorf("select is conferred but carries no reach:\n%s", got)
	}
	for _, name := range []string{"docs_update", "docs_insert", "docs_delete"} {
		if got := predicateFor(t, rls, name); strings.Contains(got, reach) {
			t.Errorf("%s is not conferred yet carries the reach, so a read grant confers a write:\n%s", name, got)
		}
	}
}

// The default has to stay every op, or adding the clause to the engine would
// silently narrow every grant already written without one.
func TestGrantVerbs_NoClauseConfersEveryOp(t *testing.T) {
	rls := emitVerbScope(t)
	const reach = "auth.unbounded_edge_reach("
	for _, name := range []string{"docs_select", "docs_update", "docs_insert", "docs_delete"} {
		if got := predicateFor(t, rls, name); !strings.Contains(got, reach) {
			t.Errorf("%s lost the reach of a grant that names no verbs; the default must be every op:\n%s", name, got)
		}
	}
}

// A misspelt verb must fail loudly. Left unchecked it narrows the grant to
// nothing in silence: the reach joins no policy and the grant reads as declared
// while conferring nothing.
func TestGrantVerbs_UnknownVerbIsRefused(t *testing.T) {
	spec := strings.Replace(verbScopeSpec, "confers select", "confers slect", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil {
		t.Fatal("a grant conferring an unknown verb was accepted; it would confer no reach at all and read as declared")
	}
	if !strings.Contains(err.Error(), "slect") {
		t.Errorf("the refusal must name the offending verb, got: %v", err)
	}
}

func TestGrantVerbs_DuplicateVerbIsRefused(t *testing.T) {
	spec := strings.Replace(verbScopeSpec, "confers select", "confers select, select", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil {
		t.Fatal("a grant naming the same verb twice was accepted")
	}
}
