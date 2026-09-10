package demesne

import (
	"strings"
	"testing"
)

// A wildcard says two things at once, and they are not equally safe. It says a
// row carrying NULL at a level belongs to no instance of that level, and it says
// such a row is in scope for a caller standing in one instance.
//
// Reading a row that belongs to everyone is the point of a shared tier. WRITING
// one from inside a single instance is a caller reaching outside the instance
// that confines it: the row belongs to no one, so nothing at that level refuses.
//
// Bounding the wildcard to named ops splits the two. On an op the wildcard does
// not name, the level confines normally and the NULL row falls out of scope.
const wildcardVerbSpec = `
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
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }

// the shared tier is readable by an org-claimed caller, and writable only by one
// standing in the row's own org
object doc {
  table  docs
  scoped tenant > project > org wildcard confers select
  permission view   = @scoped @rls maps select
  permission create = @scoped @rls maps insert
  permission edit   = @scoped @rls maps update
  permission drop   = @scoped @rls maps delete
}

// unbounded: today's behaviour, every op admits NULL
object legacy {
  table  legacies
  scoped tenant > project > org wildcard
  permission view = @scoped @rls maps select
  permission edit = @scoped @rls maps update
}
`

func wildcardPred(t *testing.T, name string) string {
	t.Helper()
	s, err := Parse(wildcardVerbSpec)
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

// The headline, as a differential on one object: the same level admits NULL on
// the op it confers and confines on the three it does not.
func TestScopeWildcardVerbs_AdmitsNullOnlyOnConferredOps(t *testing.T) {
	const nullAdmit = "org_id IS NULL"

	if got := wildcardPred(t, "docs_select"); !strings.Contains(got, nullAdmit) {
		t.Errorf("select is conferred but the shared tier is not readable:\n%s", got)
	}
	for _, name := range []string{"docs_update", "docs_delete", "docs_insert"} {
		got := wildcardPred(t, name)
		if strings.Contains(got, nullAdmit) {
			t.Errorf("%s admits a row belonging to no org to a caller standing in one, so the shared tier is writable from inside a single org:\n%s", name, got)
		}
		if !strings.Contains(got, "IS NOT DISTINCT FROM") {
			t.Errorf("%s dropped the level's admission for a caller carrying no claim, which confines them by a level they do not stand in:\n%s", name, got)
		}
	}
}

// The half of the wildcard that is NOT bounded. A caller carrying no claim at
// the level was never confined by it, so a row belonging to no instance must
// stay reachable on every op. Withdrawing that would hide rows that are nobody's
// from everybody, which is a worse failure than the hole being closed.
func TestScopeWildcardVerbs_NoClaimCallerKeepsTheSharedTierOnEveryOp(t *testing.T) {
	for _, name := range []string{"docs_select", "docs_update", "docs_delete", "docs_insert"} {
		got := wildcardPred(t, name)
		// Either shape admits a caller with no claim against a NULL row:
		// `org_id IS NULL OR ...` on a conferred op, `IS NOT DISTINCT FROM` on
		// a bounded one. A bare equality on either would strand them.
		if !strings.Contains(got, "org_id IS NULL") && !strings.Contains(got, "IS NOT DISTINCT FROM") {
			t.Errorf("%s confines a caller who carries no org claim, stranding them from rows belonging to no org:\n%s", name, got)
		}
	}
}

// The default has to stay every op, or adding the clause silently confines every
// wildcard already written without one.
func TestScopeWildcardVerbs_UnboundedAdmitsNullEverywhere(t *testing.T) {
	for _, name := range []string{"legacies_select", "legacies_update"} {
		if got := wildcardPred(t, name); !strings.Contains(got, "org_id IS NULL") {
			t.Errorf("%s lost its wildcard; a bare `wildcard` must still admit NULL on every op:\n%s", name, got)
		}
	}
}

// A misspelt op widens rather than narrows here, which is the dangerous
// direction: the level confines on the op that was meant to stay open.
func TestScopeWildcardVerbs_UnknownVerbIsRefused(t *testing.T) {
	spec := strings.Replace(wildcardVerbSpec, "wildcard confers select", "wildcard confers slect", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil {
		t.Fatal("a wildcard bounded to an unknown verb was accepted; it confines the op it was meant to open")
	}
	if !strings.Contains(err.Error(), "slect") {
		t.Errorf("the refusal must name the offending verb, got: %v", err)
	}
}

// Bounding a level that carries no wildcard is a spec error rather than a no-op,
// because the author plainly meant one and would not otherwise be told.
func TestScopeWildcardVerbs_BoundingAnUndeclaredWildcardIsRefused(t *testing.T) {
	spec := strings.Replace(wildcardVerbSpec,
		"scoped tenant > project > org wildcard confers select",
		"scoped tenant > project confers select > org wildcard", 1)
	s, err := Parse(spec)
	if err != nil {
		return // a parse refusal is an acceptable refusal
	}
	if err := Validate(s); err == nil {
		t.Fatal("bounding a level that declares no wildcard was accepted silently")
	}
}
