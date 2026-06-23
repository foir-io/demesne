package demesne

import (
	"strings"
	"testing"
)

const gateBaseSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin { permission c:r  preset pa @ project = c:r }
vocabulary cust  { permission self:read }
rolestore admin {
  assignments ra
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
subject service  { anchor project reach self identifies sub roles none }
object record {
  table  records
  scoped tenant > project
  relation owner:       customer | service via customer_id
  relation admin_owner: admin via admin_owner_id
  relation grantee:     customer | admin via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  relation comp_parent: record via composition record_relationships(from_record_id, to_record_id) where kind = "composition"
  permission view   = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:read   + comp_parent   @rls maps select
  permission edit   = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:write  + comp_parent   @rls maps update
  permission create = @app_scope(exclude admin_owner) + owner + admin_owner                                  @rls maps insert
  permission delete = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:delete + comp_parent   @rls maps delete
}
`

func withGate(gate string) string {
	return strings.Replace(gateBaseSpec, "  permission delete", "  "+gate+"\n  permission delete", 1)
}

func TestGate_ParsesAndValidates(t *testing.T) {
	s, err := Parse(withGate("gate create via comp_parent -> edit"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	var rec *Object
	for _, o := range s.Objects {
		if o.Name == "record" {
			rec = o
		}
	}
	if rec == nil || len(rec.Gates) != 1 {
		t.Fatalf("expected 1 gate on record, got %+v", rec)
	}
	g := rec.Gates[0]
	if g.Verb != "create" || g.Relation != "comp_parent" || g.Perm != "edit" {
		t.Fatalf("gate parsed wrong: verb=%q relation=%q perm=%q", g.Verb, g.Relation, g.Perm)
	}
}

func TestGate_EmitsNoRLS(t *testing.T) {
	base, err := Parse(gateBaseSpec)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	gated, err := Parse(withGate("gate create via comp_parent -> edit"))
	if err != nil {
		t.Fatalf("parse gated: %v", err)
	}
	bres, err := base.EmitRLS()
	if err != nil {
		t.Fatalf("emit base: %v", err)
	}
	gres, err := gated.EmitRLS()
	if err != nil {
		t.Fatalf("emit gated: %v", err)
	}
	if bres.PolicySQL("authenticated") != gres.PolicySQL("authenticated") {
		t.Fatal("gate changed the generated RLS floor; it must emit no policy difference")
	}
}

func TestGate_Validation(t *testing.T) {
	cases := []struct {
		name string
		gate string
		want string
	}{
		{"unknown relation", "gate create via nope -> edit", "unknown relation"},
		{"perm absent on target", "gate create via comp_parent -> frobnicate", "no permission \"frobnicate\""},
		{"verb not a permission", "gate publish via comp_parent -> edit", "does not declare as a permission"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(withGate(tc.gate))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(s)
			if err == nil {
				t.Fatalf("expected validation error for %q", tc.gate)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
