package demesne

import (
	"strings"
	"testing"
)

func TestPermissionExport_EmitsThePolicyOverParameters(t *testing.T) {
	e := emitReach(t, reachFixture)
	d := e.definer(t, "folder_write_allowed")
	if d.Sig != "check_folder_id text, row_estate_id text, row_space_id text" {
		t.Errorf("sig = %q", d.Sig)
	}
	if d.Returns != "" {
		t.Errorf("an export returns boolean, got %q", d.Returns)
	}
	want := e.policy(t, "folders_update").Using + " FROM (SELECT check_folder_id AS id, row_estate_id AS estate_id, row_space_id AS space_id) AS folders"
	if d.Body != want {
		t.Errorf("body\n got: %s\nwant: %s", d.Body, want)
	}
}

func TestPermissionExport_CarriesTheRequire(t *testing.T) {
	src := strings.Replace(reachFixture, "  export edit as", "  require edit = @self(owner_id)\n  export edit as", 1)
	src = strings.Replace(src, "row_space_id)", "row_space_id, owner_id text as row_owner_id)", 1)
	e := emitReach(t, src)
	body := e.definer(t, "folder_write_allowed").Body
	req := e.policy(t, "folders_update_require")
	if !req.Restrictive || req.Using == "" {
		t.Fatalf("the require must emit a restrictive policy to be carried: %+v", req)
	}
	want := "(" + e.policy(t, "folders_update").Using + ") AND (" + req.Using + ") FROM (SELECT check_folder_id AS id, row_estate_id AS estate_id, row_space_id AS space_id, row_owner_id AS owner_id) AS folders"
	if body != want {
		t.Errorf("an export is the permissive policy AND its require\n got: %s\nwant: %s", body, want)
	}
}

func TestPermissionExport_Refusals(t *testing.T) {
	base := "export edit as folder_write_allowed(id text as check_folder_id, estate_id text as row_estate_id, space_id text as row_space_id)"
	cases := []struct {
		name, new string
		want      []string
	}{
		{"unbound column", "export edit as folder_write_allowed(id text as check_folder_id, estate_id text as row_estate_id)", []string{`reads row column "space_id", which no parameter binds`}},
		{"unsupported type", "export edit as folder_write_allowed(id money as check_folder_id, estate_id text as row_estate_id, space_id text as row_space_id)", []string{`unsupported type "money"`}},
		{"repeated parameter", "export edit as folder_write_allowed(id text as p, estate_id text as p, space_id text as row_space_id)", []string{"twice"}},
		{"predicate-only permission", "export bound as folder_write_allowed(id text as check_folder_id)", []string{"needs a permission that maps a table operation"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustRefuse(t, strings.Replace(reachFixture, base, tc.new, 1), tc.want...)
		})
	}
	t.Run("name collides with a generated function", func(t *testing.T) {
		s, err := Parse(strings.Replace(reachFixture, "as folder_write_allowed(", "as paths_reachable(", 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "collides with a generated function") {
			t.Fatalf("want a collision refusal, got %v", err)
		}
	})
}
