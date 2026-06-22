package demesne

import (
	"strings"
	"testing"
)

const grantRelPureSpec = `
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
  permission view   = @app_scope(exclude admin_owner) + owner + admin_owner + mode access_mode = "public" + grantee:read   @rls maps select
  permission edit   = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:write                               @rls maps update
  permission delete = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:delete                              @rls maps delete
}
`

func grantFnByName(t *testing.T, s *Spec, name string) string {
	t.Helper()
	dfns, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	for _, d := range dfns {
		if d.Name == name {
			return d.CreateSQL()
		}
	}
	t.Fatalf("definer %q not generated; have: %s", name, definerNames(dfns))
	return ""
}

func definerNames(dfns []GenFn) string {
	var ns []string
	for _, d := range dfns {
		ns = append(ns, d.Name)
	}
	return strings.Join(ns, ", ")
}

func TestGrantRelation_EmitsPerKindDefinersAndCalls(t *testing.T) {
	s, err := Parse(grantRelPureSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dfns, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	defs := DefinersSQL(dfns)
	for _, want := range []string{
		"FUNCTION auth.resource_acl_grants_record(p_customer_id text, p_record_id text, p_access text)",
		"FUNCTION auth.resource_acl_grants_record_admin(p_admin_id text, p_record_id text, p_access text)",
		"resource_type = 'record'",
		"principal_kind = 'customer'",
		"principal_kind = 'admin'",
	} {
		if !strings.Contains(defs, want) {
			t.Errorf("definers missing %q:\n%s", want, defs)
		}
	}

	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sel := policyByCmd(res, "records", "SELECT").Using

	for _, want := range []string{
		"auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id'), records.id, 'read')",
		"auth.resource_acl_grants_record_admin((current_setting('request.jwt.claims', true)::json ->> 'sub'), records.id, 'read')",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("select policy missing %q:\n%s", want, sel)
		}
	}

	del := policyByCmd(res, "records", "DELETE").Using
	if !strings.Contains(del, "records.id, 'delete')") {
		t.Errorf("delete policy missing delete-class grant:\n%s", del)
	}
}

func TestGrantRelation_BareDefaultsToOpClass(t *testing.T) {
	spec := strings.NewReplacer(
		"grantee:read", "grantee",
		"grantee:write", "grantee",
		"grantee:delete", "grantee",
	).Replace(grantRelPureSpec)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	if !strings.Contains(policyByCmd(res, "records", "SELECT").Using, "records.id, 'read')") {
		t.Error("bare grantee on select should default to read access")
	}
	if !strings.Contains(policyByCmd(res, "records", "UPDATE").Using, "records.id, 'write')") {
		t.Error("bare grantee on update should default to write access")
	}
}

func policyByCmd(res *RLSResult, table, cmd string) Policy {
	for _, p := range res.Policies {
		if p.Table == table && p.Cmd == cmd {
			return p
		}
	}
	return Policy{}
}
