package demesne

import (
	"reflect"
	"strings"
	"testing"
)

// virtualRootSpec — a topology with a VIRTUAL root (no scope claim), to prove a
// scope presented for a virtual level is rejected, and a spec-declared RLS role +
// claims accessor flow through the session envelope.
const virtualRootSpec = `
claims via "app.ctx" jsonb role app_user
topology {
  level platform virtual
  level tenant   parent platform
}
vocabulary admin { permission x:read  preset v @ tenant = x:read }
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing {
  table  things
  scoped tenant
  relation m: admin via role
  permission view = m @rls maps select
}
`

// --- (1) the structured contract --------------------------------------------

func TestSession_ClaimsContractEntries(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

	// The flat contract is unchanged: scope keys (tenant_id, project_id) + identity
	// keys (sub, customer_id), sorted.
	flat, err := s.ClaimsContract()
	if err != nil {
		t.Fatalf("ClaimsContract: %v", err)
	}
	wantFlat := []string{"customer_id", "project_id", "sub", "tenant_id"}
	if !reflect.DeepEqual(flat, wantFlat) {
		t.Errorf("ClaimsContract = %v, want %v", flat, wantFlat)
	}

	// The structured form carries each key's source.
	entries, err := s.ClaimsContractEntries()
	if err != nil {
		t.Fatalf("ClaimsContractEntries: %v", err)
	}
	want := []ClaimEntry{
		{Key: "customer_id", Level: "", Subjects: []string{"customer"}},
		{Key: "project_id", Level: "project", Subjects: nil},
		{Key: "sub", Level: "", Subjects: []string{"admin"}},
		{Key: "tenant_id", Level: "tenant", Subjects: nil},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("ClaimsContractEntries =\n  %+v\nwant\n  %+v", entries, want)
	}
}

// --- (2) the derived claims-builder -----------------------------------------

func TestSession_BuildClaims(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

	// An admin's id lands under its identity key (sub); scopes under the level keys.
	admin, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"tenant": "t1", "project": "p1"}})
	if err != nil {
		t.Fatalf("admin BuildClaims: %v", err)
	}
	if !reflect.DeepEqual(admin, map[string]string{"sub": "u1", "tenant_id": "t1", "project_id": "p1"}) {
		t.Errorf("admin claims = %v", admin)
	}

	// A customer's id lands under customer_id (its own identity key), NOT sub.
	cust, err := s.BuildClaims(Principal{Subject: "customer", ID: "c1", Scopes: map[string]string{"tenant": "t1", "project": "p1"}})
	if err != nil {
		t.Fatalf("customer BuildClaims: %v", err)
	}
	if !reflect.DeepEqual(cust, map[string]string{"customer_id": "c1", "tenant_id": "t1", "project_id": "p1"}) {
		t.Errorf("customer claims = %v", cust)
	}
	if _, ok := cust["sub"]; ok {
		t.Error("a customer's spec-derived claims must NOT set sub (its identity is customer_id)")
	}

	// Unknown subject / unknown level are rejected.
	if _, err := s.BuildClaims(Principal{Subject: "nope", ID: "x"}); err == nil {
		t.Error("BuildClaims accepted an unknown subject")
	}
	if _, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"galaxy": "g"}}); err == nil {
		t.Error("BuildClaims accepted a scope for an unknown level")
	}
}

// A scope presented for a VIRTUAL level (no scope claim) is rejected; an id is only
// set when supplied.
func TestSession_BuildClaims_VirtualAndEmpty(t *testing.T) {
	s := mustSpec(t, virtualRootSpec)

	if _, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"platform": "anything"}}); err == nil {
		t.Error("BuildClaims accepted a scope for a virtual level")
	}

	// No id supplied → no identity key; a real (non-virtual) scope still maps.
	got, err := s.BuildClaims(Principal{Subject: "admin", Scopes: map[string]string{"tenant": "t1"}})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	if !reflect.DeepEqual(got, map[string]string{"tenant_id": "t1"}) {
		t.Errorf("claims = %v, want only tenant_id", got)
	}
}

// A subject with NO identity key rejects a supplied id (fail-closed: never mint a
// claim no policy reads).
func TestSession_BuildClaims_NoIdentityKey(t *testing.T) {
	s := &Spec{
		Topology: &Topology{Levels: []*Level{{Name: "tenant"}}},
		Subjects: []*Subject{{Name: "svc", Anchor: "tenant", Reach: "self"}}, // no Identifies
	}
	if _, err := s.BuildClaims(Principal{Subject: "svc", ID: "x"}); err == nil {
		t.Error("BuildClaims accepted an id for a subject with no identity key")
	}
	// Without an id it is fine (a no-claim principal).
	if _, err := s.BuildClaims(Principal{Subject: "svc"}); err != nil {
		t.Errorf("BuildClaims rejected a no-id principal: %v", err)
	}
}

// BuildClaims maps scopes via claimKey() and the identity via the subject's declared
// `identifies` — NOT the `<level>_id` / `sub` conventions. A spec that overrides both
// pins this: a regression to the conventions would produce org_id/team_id/sub and fail.
func TestSession_BuildClaims_ClaimKeyOverride(t *testing.T) {
	const src = `
topology {
  level org  claim org_ref
  level team parent org claim team_ref
}
vocabulary admin { permission a:read  preset v @ team = a:read }
subject admin { anchor team; reach descendants; identifies who; roles configurable admin; binds admin }
object thing { table things; scoped org > team; relation m: admin via role; permission view = m @rls maps select }
`
	s := mustSpec(t, src)

	got, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"org": "o1", "team": "tm1"}})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	want := map[string]string{"who": "u1", "org_ref": "o1", "team_ref": "tm1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildClaims with overrides = %v, want %v", got, want)
	}

	// The contract reflects the override keys, not the conventions.
	flat, err := s.ClaimsContract()
	if err != nil {
		t.Fatalf("ClaimsContract: %v", err)
	}
	if !reflect.DeepEqual(flat, []string{"org_ref", "team_ref", "who"}) {
		t.Errorf("contract = %v, want [org_ref team_ref who]", flat)
	}
}

func TestSession_MintClaimsFor(t *testing.T) {
	s := mustSpec(t, runtimeSpec)
	got, err := s.MintClaimsFor(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"tenant": "t1", "project": "p1"}})
	if err != nil {
		t.Fatalf("MintClaimsFor: %v", err)
	}
	// Deterministic, sorted-key JSON (encoding/json sorts map keys).
	if got != `{"project_id":"p1","sub":"u1","tenant_id":"t1"}` {
		t.Errorf("MintClaimsFor = %s", got)
	}
}

// --- (3) the WithRLS-shaped session envelope --------------------------------

func TestSession_EnvelopeDefault(t *testing.T) {
	s := mustSpec(t, runtimeSpec) // no claims block → default role + GUC

	if got := s.SetRoleSQL(true); got != "SET LOCAL ROLE authenticated" {
		t.Errorf("SetRoleSQL(true) = %q", got)
	}
	if got := s.SetRoleSQL(false); got != "SET ROLE authenticated" {
		t.Errorf("SetRoleSQL(false) = %q", got)
	}
	seq := s.SessionSetupSQL(true)
	want := []string{"SET LOCAL ROLE authenticated", "SELECT set_config('request.jwt.claims', $1, true)"}
	if !reflect.DeepEqual(seq, want) {
		t.Errorf("SessionSetupSQL(true) = %v, want %v", seq, want)
	}
}

func TestSession_EnvelopeSpecDeclared(t *testing.T) {
	s := mustSpec(t, virtualRootSpec) // claims via "app.ctx" jsonb role app_user

	if s.Claims == nil || s.Claims.Role != "app_user" || s.Claims.Setting != "app.ctx" || s.Claims.Cast != "jsonb" {
		t.Fatalf("claims block not parsed: %+v", s.Claims)
	}
	if got := s.SetRoleSQL(true); got != "SET LOCAL ROLE app_user" {
		t.Errorf("SetRoleSQL(true) = %q", got)
	}
	seq := s.SessionSetupSQL(true)
	want := []string{"SET LOCAL ROLE app_user", "SELECT set_config('app.ctx', $1, true)"}
	if !reflect.DeepEqual(seq, want) {
		t.Errorf("SessionSetupSQL(true) = %v, want %v", seq, want)
	}
}

// The `role` keyword parses with NO cast present (the cast-disambiguation path).
func TestSession_RoleWithoutCast(t *testing.T) {
	const src = `
claims via "x" role app_user
topology { level tenant }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; relation m: admin via role; permission view = m @rls maps select }
`
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Claims == nil || s.Claims.Role != "app_user" || s.Claims.Cast != "json" {
		t.Fatalf("role/cast mis-parsed: %+v", s.Claims)
	}
}

func TestSession_RenderClaimsContractEntriesGo(t *testing.T) {
	s := mustSpec(t, runtimeSpec)
	got, err := s.RenderClaimsContractEntriesGo("Contract")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"type DemesneClaimEntry struct {",
		"var Contract = []DemesneClaimEntry{",
		`{Key: "customer_id", Level: "", Subjects: []string{"customer"}},`,
		`{Key: "project_id", Level: "project", Subjects: nil},`,
		`{Key: "sub", Level: "", Subjects: []string{"admin"}},`,
		`{Key: "tenant_id", Level: "tenant", Subjects: nil},`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered artifact missing %q:\n%s", want, got)
		}
	}
}
