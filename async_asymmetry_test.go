package demesne

import (
	"strings"
	"testing"
)

const asyncGrantSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant racl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked async
  permission view = owner + grantee:read @rls maps select
}`

// `async` REQUIRES `tracked` — the affordance index is built off the changelog feed.
func TestAsync_RequiresTracked(t *testing.T) {
	spec := strings.Replace(asyncGrantSpec, `"doc" tracked async`, `"doc" async`, 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "without `tracked`") {
		t.Fatalf("async without tracked must be rejected, got: %v", err)
	}
}

// A valid `async` spec validates, the surface-token set names the index base, and the V12
// floor-asymmetry oracle is GREEN (no floor artifact references the async surface).
func TestAsync_ValidSpecPassesAndOracleGreen(t *testing.T) {
	s, err := Parse(asyncGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("valid tracked async spec must pass, got: %v", err)
	}
	toks := s.asyncSurfaceTokens()
	if len(toks) != 1 || toks[0] != "auth.docs_grantee_async" {
		t.Fatalf("asyncSurfaceTokens = %v, want [auth.docs_grantee_async]", toks)
	}
	if err := validateAsyncFloorAsymmetry(s); err != nil {
		t.Errorf("oracle must be green (floor references no async surface), got: %v", err)
	}
}

// The detection core: the base token substring-matches the table + every fn (apply/rebuild/
// affordance), and does NOT match the legitimate sync grant definer (no false positive).
func TestAsync_FloorAsymmetryDetectsLeak(t *testing.T) {
	tokens := []string{"auth.docs_grantee_async"}
	// A floor body that (wrongly) calls the async affordance fn → caught via the base prefix.
	leak := []string{"SELECT auth.docs_grantee_async_affordance(docs.id, 'customer', x)"}
	if got := asyncTokensInBodies(leak, tokens); len(got) != 1 || got[0] != "auth.docs_grantee_async" {
		t.Errorf("leak not detected: %v", got)
	}
	// The real sync grant definer + the materialized flat member must NOT match.
	clean := []string{
		"EXISTS (SELECT 1 FROM auth.resource_acl_grants_record(p, r, a))",
		"auth.docs_team_flat_member(docs.id, claim)",
	}
	if got := asyncTokensInBodies(clean, tokens); len(got) != 0 {
		t.Errorf("false positive on clean floor bodies: %v", got)
	}
}

// In this increment the `async` flag is INERT (the index emitter is the next increment), so
// a `tracked async` spec emits byte-identical SQL to the same spec with `tracked` only.
func TestAsync_ByteIdenticalWhenInert(t *testing.T) {
	emit := func(src string) string {
		s, err := Parse(src)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := Validate(s); err != nil {
			t.Fatalf("validate: %v", err)
		}
		res, err := s.EmitRLS()
		if err != nil {
			t.Fatalf("emit rls: %v", err)
		}
		defs, err := s.EmitDefiners()
		if err != nil {
			t.Fatalf("emit definers: %v", err)
		}
		return DefinersSQL(defs) + "\n" + res.PolicySQL("authenticated") + "\n" +
			s.TriggersSQL() + "\n" + s.FlatsSQL() + "\n" + s.ChangelogSQL()
	}
	trackedOnly := strings.Replace(asyncGrantSpec, `"doc" tracked async`, `"doc" tracked`, 1)
	if emit(asyncGrantSpec) != emit(trackedOnly) {
		t.Error("`async` must be inert in this increment — emitted SQL differs from the tracked-only spec")
	}
}

// A spec with no `async` relation makes the V12 oracle a no-op (byte-identical guarantee).
func TestAsync_NoneIsNoOp(t *testing.T) {
	spec := strings.Replace(asyncGrantSpec, `"doc" tracked async`, `"doc"`, 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.hasAsync() || len(s.asyncSurfaceTokens()) != 0 {
		t.Fatal("non-async spec must report no async surface")
	}
	if err := validateAsyncFloorAsymmetry(s); err != nil {
		t.Errorf("oracle must be a no-op for a non-async spec, got: %v", err)
	}
}
