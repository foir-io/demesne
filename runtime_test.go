package demesne

import (
	"testing"
)

// runtimeSpec — a customer-owned record plane plus an admin verb PDP, enough to
// exercise all three runtime helpers.
const runtimeSpec = `
topology { level tenant level project parent tenant }
vocabulary admin { permission content:write  preset ed @ project = content:write }
vocabulary cust  { permission self:read }
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object record {
  table  records
  scoped tenant > project
  relation owner: customer via customer_id
  permission view = owner @rls maps select
}
procedures admin {
  records.v1.RecordsService/UpdateRecord -> content:write
}
ungoverned admin {
  records.v1.RecordsService/GetRecord : "read path"
}
`

func TestRuntime_MintClaims(t *testing.T) {
	s := mustSpec(t, runtimeSpec)

	// A customer presents its subset of the contract; the JSON is deterministic.
	got, err := s.MintClaims(map[string]string{"customer_id": "c1", "tenant_id": "t1", "project_id": "p1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got != `{"customer_id":"c1","project_id":"p1","tenant_id":"t1"}` {
		t.Errorf("minted claims = %s", got)
	}

	// A key outside the contract is rejected (typo / stale-key protection).
	if _, err := s.MintClaims(map[string]string{"tenant_id": "t1", "tenantId": "oops"}); err == nil {
		t.Error("MintClaims accepted a key not in the contract")
	}

	// The set-GUC statement targets the spec's claims setting.
	if sql := s.ClaimsSetSQL(true); sql != "SELECT set_config('request.jwt.claims', $1, true)" {
		t.Errorf("ClaimsSetSQL = %q", sql)
	}
}

func TestRuntime_PDPAuthorize(t *testing.T) {
	s := mustSpec(t, runtimeSpec)
	pdps, err := s.EmitPDP()
	if err != nil {
		t.Fatalf("emit pdp: %v", err)
	}
	pdp := pdps["admin"]
	if pdp == nil {
		t.Fatal("no admin PDP")
	}

	hasWrite := func(perm string) bool { return perm == "content:write" }
	noPerm := func(string) bool { return false }

	if d := pdp.Authorize("records.v1.RecordsService/UpdateRecord", hasWrite); d != Allow {
		t.Errorf("holder of content:write should be allowed, got %s", d)
	}
	if d := pdp.Authorize("records.v1.RecordsService/UpdateRecord", noPerm); d != Deny {
		t.Errorf("caller lacking content:write should be denied, got %s", d)
	}
	if d := pdp.Authorize("records.v1.RecordsService/GetRecord", noPerm); d != NotGoverned {
		t.Errorf("an exempt procedure should be ungoverned, got %s", d)
	}
	if d := pdp.Authorize("records.v1.RecordsService/Unknown", hasWrite); d != NotGoverned {
		t.Errorf("an unlisted procedure should be ungoverned, got %s", d)
	}
}

func TestRuntime_PointCheckSQL(t *testing.T) {
	s := mustSpec(t, runtimeSpec)
	got, err := s.PointCheckSQL("record")
	if err != nil {
		t.Fatalf("point-check: %v", err)
	}
	if got != "SELECT EXISTS (SELECT 1 FROM records WHERE id = $1)" {
		t.Errorf("PointCheckSQL = %q", got)
	}
	if _, err := s.PointCheckSQL("nope"); err == nil {
		t.Error("PointCheckSQL accepted an unknown object")
	}
}
