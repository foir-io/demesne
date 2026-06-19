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

// The async index emits its full surface (table + maintenance + read fns + shared cursor),
// and — the real teeth — the V12 floor-asymmetry oracle is STILL green with that surface
// present: the floor (RLS + definers + flat/closure/changelog writers) references none of it.
func TestAsync_EmitsIndexAndOracleStillGreen(t *testing.T) {
	s, err := Parse(asyncGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	async := s.AsyncSQL()
	for _, want := range []string{
		"auth._authz_async_cursor", "auth.docs_grantee_async ", "auth.docs_grantee_async_apply()",
		"auth.docs_grantee_async_rebuild()", "auth.docs_grantee_async_affordance(",
		"auth.docs_grantee_async_watermark()", "pg_snapshot_xmin(pg_current_snapshot())",
		"resource_type", // the rel discriminator this index consumes (DiscrimVal)
	} {
		if !strings.Contains(async, want) {
			t.Errorf("AsyncSQL missing %q", want)
		}
	}
	// The async fns must NOT be in the kernel definer set (so V11 fails the build on any floor
	// reference); the V12 oracle proves the live floor references no async surface.
	defs, _ := s.EmitDefiners()
	for _, d := range defs {
		if strings.Contains(d.Name, "_async") {
			t.Errorf("async fn %q leaked into the kernel definer set", d.Name)
		}
	}
	if err := validateAsyncFloorAsymmetry(s); err != nil {
		t.Errorf("oracle must be green with the async surface present, got: %v", err)
	}
}

// The changelog gains the per-row txid (xid8) ONLY when the spec uses `async` — Foir (tracked,
// no async) keeps the changelog byte-identical.
func TestAsync_ChangelogTxidIsAsyncOnly(t *testing.T) {
	withAsync, _ := Parse(asyncGrantSpec)
	if !strings.Contains(withAsync.ChangelogTableSQL(), "txid xid8 NOT NULL DEFAULT pg_current_xact_id()") {
		t.Error("async spec changelog must carry the txid column")
	}
	trackedOnly, _ := Parse(strings.Replace(asyncGrantSpec, `"doc" tracked async`, `"doc" tracked`, 1))
	if strings.Contains(trackedOnly.ChangelogTableSQL(), "txid") {
		t.Error("non-async (tracked-only) changelog must NOT carry txid — byte-identical for Foir")
	}
	if trackedOnly.AsyncSQL() != "" {
		t.Error("non-async spec must emit no async surface")
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
