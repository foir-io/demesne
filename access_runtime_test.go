package demesne

import (
	"strings"
	"testing"
)

// The access runtime surface projects the descriptor layout and builds the
// read/write SQL from it — one source of truth, so a handler never re-derives the
// grant store's columns / discriminator / accessor name.
func TestResourceAccessSurface(t *testing.T) {
	s, err := Parse(adminOwnerSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	r, err := s.ResourceAccessSurface("record")
	if err != nil {
		t.Fatalf("surface: %v", err)
	}

	if r.Table != "records" || strings.Join(r.ScopeCols, ",") != "tenant_id,project_id" || r.ModeCol != "access_mode" {
		t.Errorf("projection wrong: table=%q scope=%v mode=%q", r.Table, r.ScopeCols, r.ModeCol)
	}
	// adminOwnerSpec opens read on "public_project" and lists "customer" grants.
	if !r.IsReadMode("public_project") || r.IsReadMode("private") {
		t.Errorf("read-mode projection wrong")
	}
	if !r.GrantKindAllowed("customer") || r.GrantKindAllowed("nobody") {
		t.Errorf("grant-kind projection wrong")
	}

	if got := r.ModeSQL(); got != "SELECT access_mode FROM records WHERE id = $1" {
		t.Errorf("ModeSQL = %q", got)
	}
	if got := r.SetVisibilitySQL(); got != "UPDATE records SET access_mode = $1 WHERE id = $2" {
		t.Errorf("SetVisibilitySQL = %q", got)
	}
	if got := r.AccessorsSQL(); got != "SELECT source, principal_kind, principal_id, access FROM auth.records_accessors($1)" {
		t.Errorf("AccessorsSQL = %q", got)
	}

	// GrantInsert carries the scope, the resource_type discriminator, the grant
	// tuple, and the matching conflict key — the discriminated-store shape.
	sql, args := r.GrantInsert([]string{"t1", "p1"}, "rec1", "customer", "cust9", "read")
	wantSQL := "INSERT INTO resource_acl (tenant_id, project_id, resource_type, resource_id, principal_kind, principal_id, access) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (resource_type, resource_id, principal_kind, principal_id, access) DO NOTHING RETURNING created_at"
	if sql != wantSQL {
		t.Errorf("GrantInsert sql:\n got %q\nwant %q", sql, wantSQL)
	}
	if strings.Join(toStr(args), ",") != "t1,p1,record,rec1,customer,cust9,read" {
		t.Errorf("GrantInsert args = %v", args)
	}

	// RevokeDelete with an access level pins all five columns; without, omits it.
	del, dargs := r.RevokeDelete("rec1", "customer", "cust9", "read")
	if del != "DELETE FROM resource_acl WHERE resource_id = $1 AND resource_type = $2 AND principal_kind = $3 AND principal_id = $4 AND access = $5" {
		t.Errorf("RevokeDelete = %q", del)
	}
	if strings.Join(toStr(dargs), ",") != "rec1,record,customer,cust9,read" {
		t.Errorf("RevokeDelete args = %v", dargs)
	}
	delAll, _ := r.RevokeDelete("rec1", "customer", "cust9", "")
	if strings.Contains(delAll, "access =") {
		t.Errorf("RevokeDelete(all) should not pin access: %q", delAll)
	}

	if got := r.ListGrantsSQL(); got != "SELECT principal_kind, principal_id, access, created_at FROM resource_acl WHERE resource_id = $1 AND resource_type = $2 ORDER BY created_at" {
		t.Errorf("ListGrantsSQL = %q", got)
	}
	if strings.Join(toStr(r.ListGrantsArgs("rec1")), ",") != "rec1,record" {
		t.Errorf("ListGrantsArgs = %v", r.ListGrantsArgs("rec1"))
	}
}

func toStr(args []any) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a.(string)
	}
	return out
}
