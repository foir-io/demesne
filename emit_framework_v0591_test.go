package demesne

import (
	"strings"
	"testing"
)

func mustValidSpec(t *testing.T, src string) *Spec {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

// With >1 rolestore the holds surface is suffixed per rolestore
// (Holds<Name>/AssignmentsSQL<Name>/ResolveHeld<Name>/holdsResolver<Name>) so each is
// independently addressable (EID-371 §4.7). foir has exactly one rolestore, so this path
// was unexercised there — prove it generates a distinct, parseable surface per rolestore.
func TestEmitFramework_MultiRolestore(t *testing.T) {
	const spec = `
topology { level tenant level project parent tenant }

vocabulary staff {
  permission docs:read
  permission docs:publish
  preset viewer @ tenant = docs:read
  preset admin  @ tenant = *
  rank admin > viewer
}
vocabulary ops {
  permission jobs:run
  permission jobs:cancel
  preset operator @ tenant = jobs:run
  preset lead     @ tenant = *
  rank lead > operator
}

rolestore staff { assignments staff_grants kind grantee_kind = "staff" subject grantee_id scope tenant_id project_id rolejoin role_id roles id key revoked revoked_at }
rolestore ops   { assignments ops_grants   kind grantee_kind = "ops"   subject grantee_id scope tenant_id project_id rolejoin role_id roles id key revoked revoked_at }

subject staffer { anchor tenant reach descendants identifies sub   roles configurable staff binds admin }
subject opser   { anchor tenant reach descendants identifies opsid roles configurable ops   binds owner }

object doc {
  table docs
  scoped tenant > project
  relation admin: staffer via role
  relation owner: opser   via owner_id
  permission view    = admin + owner @rls maps select
  permission publish = docs:publish @pdp
  permission run     = jobs:run @pdp
}
`
	s := mustValidSpec(t, spec)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"var holdsResolverStaff =", "const AssignmentsSQLStaff =",
		"func ResolveHeldStaff(", "func HoldsStaff(",
		"var holdsResolverOps =", "const AssignmentsSQLOps =",
		"func ResolveHeldOps(", "func HoldsOps(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("multi-rolestore output missing %q", want)
		}
	}
	if strings.Contains(src, "func Holds(ctx") {
		t.Errorf("with >1 rolestore Holds must be suffixed, not bare:\n%s", src)
	}
	// Both @pdp verbs are covered by a rolestore vocabulary, so NO orphan banner.
	if strings.Contains(src, "no rolestore vocabulary covers") {
		t.Errorf("unexpected orphan banner — both vocabularies have rolestores:\n%s", src)
	}
}

// A @pdp verb whose permission no rolestore vocabulary covers compiles (its Can<Verb>(held)
// is emitted) but has no generated resolver to produce `held` — the emitter banners it so the
// gap isn't silent (EID-371 §4.7). Here the `ops` vocab is `roles configurable` (a scope gate)
// but has no rolestore block, so jobs:run has no resolver.
func TestEmitFramework_OrphanPDPBanner(t *testing.T) {
	const spec = `
topology { level tenant level project parent tenant }

vocabulary staff {
  permission docs:read
  permission docs:publish
  preset viewer @ tenant = docs:read
  preset admin  @ tenant = *
  rank admin > viewer
}
vocabulary ops {
  permission jobs:run
}

rolestore staff { assignments staff_grants kind grantee_kind = "staff" subject grantee_id scope tenant_id project_id rolejoin role_id roles id key revoked revoked_at }

subject staffer { anchor tenant reach descendants identifies sub   roles configurable staff binds admin }
subject opser   { anchor tenant reach descendants identifies opsid roles configurable ops   binds owner }

object doc {
  table docs
  scoped tenant > project
  relation admin: staffer via role
  relation owner: opser   via owner_id
  permission view = admin + owner @rls maps select
  permission run  = jobs:run @pdp
}
`
	s := mustValidSpec(t, spec)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"these @pdp verbs need a permission no rolestore vocabulary covers",
		`doc.run (needs "jobs:run")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("orphan @pdp banner missing %q:\n%s", want, src)
		}
	}
}
