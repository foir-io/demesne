package demesne

import (
	"strings"
	"testing"
)

func findPolicy(r *RLSResult, name string) *Policy {
	for i := range r.Policies {
		if r.Policies[i].Name == name {
			return &r.Policies[i]
		}
	}
	return nil
}

// claim helper for building expected strings in tests.
const (
	cSub      = "(current_setting('request.jwt.claims', true)::json ->> 'sub')"
	cTenant   = "(current_setting('request.jwt.claims', true)::json ->> 'tenant_id')"
	cProject  = "(current_setting('request.jwt.claims', true)::json ->> 'project_id')"
	cCustomer = "(current_setting('request.jwt.claims', true)::json ->> 'customer_id')"
	cMember   = "(current_setting('request.jwt.claims', true)::json ->> 'member_id')"
)

// TestEmitRLS_RoleTerms exercises role-walk + via-role emission on a clean
// sub-row object: inline owner, a via-role relation (admin_has_<obj>_role), and
// a role-walk into the parent level (is_<level>_admin).
func TestEmitRLS_RoleTerms(t *testing.T) {
	src := `
	  topology { level platform virtual level tenant parent platform level project parent tenant }
	  vocabulary v { permission a:b preset member @ project = a:b preset tadmin @ tenant = a:b rank tadmin > member }
	  rolestore admin {
	    assignments role_assignments
	    kind        principal_kind = "admin"
	    subject     principal_id
	    scope       tenant_id project_id
	    rolejoin    role_id roles id key
	    revoked     revoked_at
	  }
	  subject operator { anchor platform reach descendants identifies sub via membership admin_users(id, is_platform_admin) roles none }
	  subject admin    { anchor tenant   reach descendants identifies sub roles configurable v binds admin }
	  subject customer { anchor project  reach self        identifies customer_id roles configurable v binds owner }
	  object thing {
	    table  things
	    scoped tenant > project
	    relation tenant: tenant   via tenant_id
	    relation member: admin    via role
	    relation owner:  customer via customer_id
	    permission view = owner + member + tenant->owner @rls maps select
	  }`
	spec, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(spec); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res, err := spec.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	pol := findPolicy(res, "things_select")
	if pol == nil {
		t.Fatalf("no things_select policy (unsupported: %v)", res.Unsupported)
	}
	for _, frag := range []string{
		"customer_id = " + cCustomer,                                     // inline owner
		"auth.admin_has_thing_role(" + cSub + ", tenant_id, project_id)", // via role
		"auth.is_tenant_admin(" + cSub + ", tenant_id)",                  // role-walk
	} {
		if !strings.Contains(pol.Using, frag) {
			t.Errorf("things_select missing %q in:\n%s", frag, pol.Using)
		}
	}
}
