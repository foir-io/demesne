package demesne

import (
	"strings"
	"testing"
)

// The runtime ResourceAccessSurface (the handler's grant/visibility/expand SQL
// source) projects from a pure-relation object: its layout, the discriminated
// grant-store shape, the allowed kinds + read modes, and the generated SQL.
func TestResourceAccessSurface_PureProjection(t *testing.T) {
	pure, err := Parse(storeManagePureSpec)
	if err != nil {
		t.Fatalf("parse pure: %v", err)
	}
	if err := Validate(pure); err != nil {
		t.Fatalf("validate pure: %v", err)
	}
	for _, tc := range []struct{ obj, table, discrim string }{
		{"record", "records", "record"},
		{"file", "files", "file"},
	} {
		ps, err := pure.ResourceAccessSurface(tc.obj)
		if err != nil {
			t.Fatalf("pure surface %s: %v", tc.obj, err)
		}
		// Layout + projected vocab.
		if ps.Table != tc.table || ps.ModeCol != "access_mode" {
			t.Errorf("%s: Table/ModeCol wrong: %+v", tc.obj, ps)
		}
		if !ps.IsReadMode("public") || ps.IsReadMode("private") {
			t.Errorf("%s: read-mode projection wrong", tc.obj)
		}
		if !ps.GrantKindAllowed("customer") || ps.GrantKindAllowed("nobody") {
			t.Errorf("%s: grant-kind projection wrong", tc.obj)
		}

		// The generated SQL shapes, carrying the discriminator constant.
		ins, args := ps.GrantInsert([]string{"t1", "p1"}, "r1", "customer", "c1", "read")
		wantIns := "INSERT INTO resource_acl (tenant_id, project_id, resource_type, resource_id, principal_kind, principal_id, access) " +
			"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (resource_type, resource_id, principal_kind, principal_id, access) DO NOTHING RETURNING created_at"
		if ins != wantIns {
			t.Errorf("%s GrantInsert sql:\n got %q\nwant %q", tc.obj, ins, wantIns)
		}
		if strings.Join(toStr(args), ",") != "t1,p1,"+tc.discrim+",r1,customer,c1,read" {
			t.Errorf("%s GrantInsert args = %v", tc.obj, args)
		}
		if got, want := ps.ModeSQL(), "SELECT access_mode FROM "+tc.table+" WHERE id = $1"; got != want {
			t.Errorf("%s ModeSQL = %q, want %q", tc.obj, got, want)
		}
		if got, want := ps.SetVisibilitySQL(), "UPDATE "+tc.table+" SET access_mode = $1 WHERE id = $2"; got != want {
			t.Errorf("%s SetVisibilitySQL = %q, want %q", tc.obj, got, want)
		}
		if got, want := ps.ListGrantsSQL(), "SELECT principal_kind, principal_id, access, created_at FROM resource_acl WHERE resource_id = $1 AND resource_type = $2 ORDER BY created_at"; got != want {
			t.Errorf("%s ListGrantsSQL = %q, want %q", tc.obj, got, want)
		}
		if got, want := ps.AccessorsSQL(), "SELECT source, principal_kind, principal_id, access FROM auth."+tc.table+"_accessors($1)"; got != want {
			t.Errorf("%s AccessorsSQL = %q, want %q", tc.obj, got, want)
		}
	}
}
