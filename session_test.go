package demesne

import (
	"reflect"
	"strings"
	"testing"
)

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

func TestSession_ClaimsContractEntries(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

	flat, err := s.ClaimsContract()
	if err != nil {
		t.Fatalf("ClaimsContract: %v", err)
	}
	wantFlat := []string{"customer_id", "project_id", "sub", "tenant_id"}
	if !reflect.DeepEqual(flat, wantFlat) {
		t.Errorf("ClaimsContract = %v, want %v", flat, wantFlat)
	}

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

func TestSession_BuildClaims(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

	admin, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"tenant": "t1", "project": "p1"}})
	if err != nil {
		t.Fatalf("admin BuildClaims: %v", err)
	}
	if !reflect.DeepEqual(admin, map[string]string{"sub": "u1", "tenant_id": "t1", "project_id": "p1"}) {
		t.Errorf("admin claims = %v", admin)
	}

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

	if _, err := s.BuildClaims(Principal{Subject: "nope", ID: "x"}); err == nil {
		t.Error("BuildClaims accepted an unknown subject")
	}
	if _, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"galaxy": "g"}}); err == nil {
		t.Error("BuildClaims accepted a scope for an unknown level")
	}
}

func TestSession_BuildClaims_VirtualAndEmpty(t *testing.T) {
	s := mustSpec(t, virtualRootSpec)

	if _, err := s.BuildClaims(Principal{Subject: "admin", ID: "u1", Scopes: map[string]string{"platform": "anything"}}); err == nil {
		t.Error("BuildClaims accepted a scope for a virtual level")
	}

	got, err := s.BuildClaims(Principal{Subject: "admin", Scopes: map[string]string{"tenant": "t1"}})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	if !reflect.DeepEqual(got, map[string]string{"tenant_id": "t1"}) {
		t.Errorf("claims = %v, want only tenant_id", got)
	}
}

func TestSession_BuildClaims_NoIdentityKey(t *testing.T) {
	s := &Spec{
		Topology: &Topology{Levels: []*Level{{Name: "tenant"}}},
		Subjects: []*Subject{{Name: "svc", Anchor: "tenant", Reach: "self"}},
	}
	if _, err := s.BuildClaims(Principal{Subject: "svc", ID: "x"}); err == nil {
		t.Error("BuildClaims accepted an id for a subject with no identity key")
	}

	if _, err := s.BuildClaims(Principal{Subject: "svc"}); err != nil {
		t.Errorf("BuildClaims rejected a no-id principal: %v", err)
	}
}

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

	if got != `{"project_id":"p1","sub":"u1","tenant_id":"t1"}` {
		t.Errorf("MintClaimsFor = %s", got)
	}
}

func TestSession_EnvelopeDefault(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

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
	s := mustSpec(t, virtualRootSpec)

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
