package demesne

import (
	"strings"
	"testing"
)

// Primitive 1 of the descriptor→pure-relation epic: the access-class GRANT RELATION
// (`via grant`). It is the de-prescribed form of the descriptor's `grants` list —
// a generic relation over a 4-column ACL edge, referenced per-permission with an
// access class (`grantee:read`). These tests prove it emits BYTE-IDENTICAL SQL to
// the descriptor grant list, so a content object can drop the descriptor for plain
// relations as a provable refactor.

// The control: the descriptor grant list (customer + admin) over a discriminated
// resource_acl store, with owner + admin-owner + a read mode.
const grantRelControlSpec = `
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
  descriptor {
    owner       customer | service via customer_id
    admin owner admin via admin_owner_id
    mode        via access_mode
    modes       private + read "public" + list "customer" + list "admin"
    grants      via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view   = @app_scope + @descriptor @rls maps select
  permission edit   = @app_scope + @descriptor @rls maps update
  permission delete = @app_scope + @descriptor @rls maps delete
}
`

// The hybrid: identical, except the grant LIST is expressed as a `via grant`
// RELATION referenced with an access class. Owner/admin-owner/mode stay in the
// descriptor (those are other primitives); only the grant is de-prescribed. Because
// @descriptor (owner+admin-owner+read) flattens first and grantee:<class> appends
// after, the final OR order matches the control's — so the policy is byte-identical.
const grantRelHybridSpec = `
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
  relation grantee: customer | admin via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  descriptor {
    owner       customer | service via customer_id
    admin owner admin via admin_owner_id
    mode        via access_mode
    modes       private + read "public"
  }
  permission view   = @app_scope + @descriptor + grantee:read   @rls maps select
  permission edit   = @app_scope + @descriptor + grantee:write  @rls maps update
  permission delete = @app_scope + @descriptor + grantee:delete @rls maps delete
}
`

// grantFnByName returns the CreateSQL of the generated definer with the given name.
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

// The grant relation reproduces the descriptor grant list byte-for-byte: same RLS
// policy SQL and the same per-kind grant definers. This is the refactor gate.
func TestGrantRelation_ByteIdenticalToDescriptor(t *testing.T) {
	ctrl, err := Parse(grantRelControlSpec)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	if err := Validate(ctrl); err != nil {
		t.Fatalf("validate control: %v", err)
	}
	hyb, err := Parse(grantRelHybridSpec)
	if err != nil {
		t.Fatalf("parse hybrid: %v", err)
	}
	if err := Validate(hyb); err != nil {
		t.Fatalf("validate hybrid: %v", err)
	}

	ctrlRLS, err := ctrl.EmitRLS()
	if err != nil {
		t.Fatalf("emit ctrl rls: %v", err)
	}
	hybRLS, err := hyb.EmitRLS()
	if err != nil {
		t.Fatalf("emit hyb rls: %v", err)
	}
	cSQL := ctrlRLS.PolicySQL("authenticated")
	hSQL := hybRLS.PolicySQL("authenticated")
	if cSQL != hSQL {
		t.Errorf("policy SQL differs between descriptor and grant-relation forms:\n--- descriptor ---\n%s\n--- grant relation ---\n%s", cSQL, hSQL)
	}

	// The per-kind grant definers must be byte-identical too (same names, bodies).
	for _, name := range []string{"resource_acl_grants_record", "resource_acl_grants_record_admin"} {
		c := grantFnByName(t, ctrl, name)
		h := grantFnByName(t, hyb, name)
		if c != h {
			t.Errorf("grant definer %q differs:\n--- descriptor ---\n%s\n--- grant relation ---\n%s", name, c, h)
		}
	}
}

// The grant relation emits the expected SQL on its own (not just relative to the
// descriptor): one EXISTS definer per kind, discriminated, and per-class RLS calls.
func TestGrantRelation_EmitsPerKindDefinersAndCalls(t *testing.T) {
	s, err := Parse(grantRelHybridSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
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
	// view → grantee:read: customer read against customer_id, admin against sub.
	for _, want := range []string{
		"auth.resource_acl_grants_record((current_setting('request.jwt.claims', true)::json ->> 'customer_id'), records.id, 'read')",
		"auth.resource_acl_grants_record_admin((current_setting('request.jwt.claims', true)::json ->> 'sub'), records.id, 'read')",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("select policy missing %q:\n%s", want, sel)
		}
	}
	// delete → grantee:delete carries the delete access class.
	del := policyByCmd(res, "records", "DELETE").Using
	if !strings.Contains(del, "records.id, 'delete')") {
		t.Errorf("delete policy missing delete-class grant:\n%s", del)
	}
}

// A bare `grantee` (no access class) defaults to the op's class — read on select,
// write on update — exactly as the descriptor grant list does.
func TestGrantRelation_BareDefaultsToOpClass(t *testing.T) {
	spec := strings.NewReplacer(
		"@app_scope + @descriptor + grantee:read", "@app_scope + @descriptor + grantee",
		"@app_scope + @descriptor + grantee:write", "@app_scope + @descriptor + grantee",
		"@app_scope + @descriptor + grantee:delete", "@app_scope + @descriptor + grantee",
	).Replace(grantRelHybridSpec)
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

// policyByCmd returns the named table's policy for a command.
func policyByCmd(res *RLSResult, table, cmd string) Policy {
	for _, p := range res.Policies {
		if p.Table == table && p.Cmd == cmd {
			return p
		}
	}
	return Policy{}
}
