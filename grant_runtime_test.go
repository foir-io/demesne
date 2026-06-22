package demesne

import (
	"reflect"
	"testing"
)

const fullGrantSpec = `
topology { level platform virtual  level tenant parent platform }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at
  pk id granted by granted_by revoked by revoked_by created created_at
  column reason
subject operator { anchor platform; reach via grant impersonation; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; relation m: admin via role; permission view = m @rls maps select }
`

const minimalGrantSpec = `
topology { level platform virtual  level tenant parent platform }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
grant simple at tenant via edge simple_grants(grantee_id, tenant_id)
subject operator { anchor platform; reach via grant simple; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; relation m: admin via role; permission view = m @rls maps select }
`

func TestGrant_FullSurface(t *testing.T) {
	s := mustSpec(t, fullGrantSpec)
	g, err := s.GrantSurface("impersonation")
	if err != nil {
		t.Fatalf("GrantSurface: %v", err)
	}

	sql, args := g.GrantInsert("g1", "u1", "t1", "granter1", "2030-01-01T00:00:00Z", map[string]any{"reason": "audit me"})

	wantSQL := "INSERT INTO impersonation_grants (id, grantee_id, tenant_id, granted_by, expires_at, reason) " +
		"VALUES ($1, $2, $3, $4, $5, $6) " +
		"RETURNING id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason"
	if sql != wantSQL {
		t.Errorf("GrantInsert SQL:\n got: %s\nwant: %s", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{"g1", "u1", "t1", "granter1", "2030-01-01T00:00:00Z", "audit me"}) {
		t.Errorf("GrantInsert args = %v", args)
	}

	wantRevoke := "UPDATE impersonation_grants SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL " +
		"RETURNING id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason"
	if got := g.RevokeSQL(); got != wantRevoke {
		t.Errorf("RevokeSQL:\n got: %s\nwant: %s", got, wantRevoke)
	}

	wantList := "SELECT id, grantee_id, tenant_id, granted_by, expires_at, created_at, revoked_at, revoked_by, reason " +
		"FROM impersonation_grants " +
		"WHERE ($1::text IS NULL OR grantee_id = $1) AND ($2::text IS NULL OR tenant_id = $2) " +
		"AND (NOT $3::boolean OR (revoked_at IS NULL AND expires_at > now())) ORDER BY created_at DESC"
	if got := g.ListSQL(); got != wantList {
		t.Errorf("ListSQL:\n got: %s\nwant: %s", got, wantList)
	}
}

func TestGrant_MinimalSurface(t *testing.T) {
	s := mustSpec(t, minimalGrantSpec)
	g, err := s.GrantSurface("simple")
	if err != nil {
		t.Fatalf("GrantSurface: %v", err)
	}
	if g.PK != "id" {
		t.Errorf("PK should default to id, got %q", g.PK)
	}

	sql, args := g.GrantInsert("g1", "u1", "t1", "ignored", nil, nil)
	if sql != "INSERT INTO simple_grants (id, grantee_id, tenant_id) VALUES ($1, $2, $3) RETURNING id, grantee_id, tenant_id" {
		t.Errorf("GrantInsert SQL = %q", sql)
	}
	if !reflect.DeepEqual(args, []any{"g1", "u1", "t1"}) {
		t.Errorf("GrantInsert args = %v", args)
	}

	if got := g.RevokeSQL(); got != "DELETE FROM simple_grants WHERE id = $1" {
		t.Errorf("RevokeSQL = %q", got)
	}

	wantList := "SELECT id, grantee_id, tenant_id FROM simple_grants " +
		"WHERE ($1::text IS NULL OR grantee_id = $1) AND ($2::text IS NULL OR tenant_id = $2) AND (NOT $3::boolean OR (TRUE))"
	if got := g.ListSQL(); got != wantList {
		t.Errorf("ListSQL:\n got: %s\nwant: %s", got, wantList)
	}
}

func TestGrant_ActivePredicate(t *testing.T) {
	s := mustSpec(t, fullGrantSpec)
	full, _ := s.GrantSurface("impersonation")
	if got := full.activePredicate("ig."); got != "ig.revoked_at IS NULL AND ig.expires_at > now()" {
		t.Errorf("full predicate = %q", got)
	}

	revokedOnly := &GrantSurface{ActiveCol: "revoked_at"}
	if got := revokedOnly.activePredicate(""); got != "revoked_at IS NULL" {
		t.Errorf("revoked-only = %q", got)
	}

	expiryOnly := &GrantSurface{ExpiresCol: "expires_at"}
	if got := expiryOnly.activePredicate(""); got != "expires_at > now()" {
		t.Errorf("expiry-only = %q", got)
	}

	if got := (&GrantSurface{}).activePredicate(""); got != "TRUE" {
		t.Errorf("neither = %q", got)
	}
}

func TestGrant_ExtraColumns(t *testing.T) {
	const src = `
topology { level platform virtual  level tenant parent platform }
vocabulary admin { permission a:read  preset v @ tenant = a:read }
grant g at tenant via edge edges(grantee_id, tenant_id) pk id column reason column note
subject operator { anchor platform; reach via grant g; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
object thing { table things; scoped tenant; relation m: admin via role; permission view = m @rls maps select }
`
	s := mustSpec(t, src)
	g, err := s.GrantSurface("g")
	if err != nil {
		t.Fatalf("GrantSurface: %v", err)
	}
	if !reflect.DeepEqual(g.ExtraCols, []string{"reason", "note"}) {
		t.Fatalf("ExtraCols = %v, want [reason note]", g.ExtraCols)
	}

	sql, args := g.GrantInsert("g1", "u1", "t1", "", nil, map[string]any{"reason": "r"})
	wantSQL := "INSERT INTO edges (id, grantee_id, tenant_id, reason, note) VALUES ($1, $2, $3, $4, $5) " +
		"RETURNING id, grantee_id, tenant_id, reason, note"
	if sql != wantSQL {
		t.Errorf("GrantInsert SQL:\n got: %s\nwant: %s", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{"g1", "u1", "t1", "r", nil}) {
		t.Errorf("args = %v, want [g1 u1 t1 r <nil>]", args)
	}
}

func TestGrant_NoSuchGrant(t *testing.T) {
	s := mustSpec(t, fullGrantSpec)
	if _, err := s.GrantSurface("nope"); err == nil {
		t.Error("expected an error for an unknown grant name")
	}
}
