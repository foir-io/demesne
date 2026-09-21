package demesne

import (
	"strings"
	"testing"
)

const accessorDepthSpec = `
topology { level estate level space parent estate level folder parent space }
vocabulary crew { permission asset:read preset reader @ space = asset:read }
rolestore crew {
 assignments assignments kind member_kind = "crew" subject member_id
 scope estate_ref space_ref rolejoin role_id roles id key revoked ended_at
}
subject crew { anchor estate reach descendants identifies sub roles configurable crew binds admin }
subject member { anchor space reach self identifies member_ref roles none binds owner }
subject estate_member { anchor estate reach self identifies member_ref roles none binds owner }
subject folder_member { anchor folder reach self identifies member_ref roles none binds owner }
object asset {
 table assets scoped SCOPE
 relation owner: estate_member | member | folder_member via owner_id
 relation grantee: estate_member | member | folder_member via grant asset_acl(asset_id, principal_kind, principal_id, access)
 permission view = @app_scope + owner + grantee:read @rls maps select
}
`

func TestAccessorRoleJoinWidensAtTheDeepestSharedLevel(t *testing.T) {
	for _, tc := range []struct{ name, scope, join string }{
		{"object as deep as the store", "estate > space", "ra.estate_ref = r.estate_id AND (ra.space_ref IS NULL OR ra.space_ref = r.space_id)"},
		{"object deeper than the store", "estate > space > folder", "ra.estate_ref = r.estate_id AND (ra.space_ref IS NULL OR ra.space_ref = r.space_id)"},
		{"object shallower than the store", "estate", "(ra.estate_ref IS NULL OR ra.estate_ref = r.estate_id)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustSpec(t, strings.Replace(accessorDepthSpec, "SCOPE", tc.scope, 1))
			if err := Validate(s); err != nil {
				t.Fatalf("validate: %v", err)
			}
			defs, err := s.EmitDefiners()
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range defs {
				if d.Name != "assets_accessors_conditional" {
					continue
				}
				line := ""
				for _, l := range strings.Split(d.Body, "\n") {
					if strings.Contains(l, "JOIN assignments ra ON") {
						line = l
					}
				}
				want := "JOIN assignments ra ON ra.member_kind = 'crew' AND ra.ended_at IS NULL AND " + tc.join
				if strings.TrimSpace(line) != want {
					t.Fatalf("role join\n got: %s\nwant: %s", strings.TrimSpace(line), want)
				}
				return
			}
			t.Fatal("no assets_accessors definer")
		})
	}
}
