package demesne

import (
	"strings"
	"testing"
)

// A discriminated grant edge lets several grant relations share ONE physical
// store, each filtering its rows by a constant — the general capability behind a
// unified resource_acl(resource_type, resource_id, …). The engine does not
// prescribe the shape; the spec author opts in.
const sharedAclSpec = `
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
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at
subject operator { anchor platform reach via grant impersonation identifies sub roles none }
subject admin    { anchor tenant   reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project  reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view = owner + mode access_mode = "public_project" + grantee:read @rls maps select
}
object note {
  table  notes
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note"
  permission view = owner + grantee:read @rls maps select
}
`

func TestDiscriminatedGrantEdge_SharedStore(t *testing.T) {
	s, err := Parse(sharedAclSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	body := map[string]string{}
	for _, d := range defs {
		body[d.Name] = d.Body
	}

	// Each descriptor gets its OWN collision-free definer over the shared table,
	// named by the object (not just the table), each gated by its discriminator.
	doc, ok := body["resource_acl_grants_doc"]
	if !ok {
		t.Fatalf("no resource_acl_grants_doc definer; have %v", grantKeys(body))
	}
	if !strings.HasPrefix(doc, "EXISTS (SELECT 1 FROM resource_acl WHERE ") ||
		!strings.Contains(doc, "resource_type = 'doc'") ||
		!strings.Contains(doc, "principal_kind = 'customer'") {
		t.Errorf("doc grant definer wrong:\n%s", doc)
	}
	note, ok := body["resource_acl_grants_note"]
	if !ok {
		t.Fatalf("no resource_acl_grants_note definer; have %v", grantKeys(body))
	}
	if !strings.Contains(note, "resource_type = 'note'") {
		t.Errorf("note grant definer missing its discriminator:\n%s", note)
	}
	// No bare resource_acl_grants — a shared store is always suffixed.
	if _, bad := body["resource_acl_grants"]; bad {
		t.Error("a bare resource_acl_grants definer was emitted for a shared store")
	}

	// The RLS read policy calls the object-suffixed definer.
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	psql := res.PolicySQL("authenticated")
	if !strings.Contains(psql, "resource_acl_grants_doc(") || !strings.Contains(psql, "resource_acl_grants_note(") {
		t.Errorf("RLS policies do not call the suffixed grant definers:\n%s", psql)
	}
}

// A bare (undiscriminated) edge is unchanged: <table>_grants, no discriminator —
// the capability is purely additive.
func TestDiscriminatedGrantEdge_BareUnchanged(t *testing.T) {
	s, err := Parse(reachGrantSpec) // record_acl, no `where`
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	var found bool
	for _, d := range defs {
		if d.Name == "record_acl_grants" {
			found = true
			if strings.Contains(d.Body, "resource_type") {
				t.Errorf("bare edge leaked a discriminator:\n%s", d.Body)
			}
		}
		if strings.HasPrefix(d.Name, "record_acl_grants_") {
			t.Errorf("bare edge got an object suffix: %s", d.Name)
		}
	}
	if !found {
		t.Error("bare edge did not emit record_acl_grants")
	}
}

func TestDiscriminatedGrantEdge_Rejects(t *testing.T) {
	const head = `topology { level a }
vocabulary cust { permission self:read }
subject customer { anchor a reach self identifies customer_id roles configurable cust binds owner }
`
	descr := func(obj, where string) string {
		return `object ` + obj + ` {
  table ` + obj + `s
  scoped a
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access)` + where + `
  permission view = owner + grantee:read @rls maps select
}
`
	}
	cases := []struct {
		name, spec, want string
	}{
		{
			name: "shared store, one bare",
			spec: head + descr("doc", ` where resource_type = "doc"`) + descr("note", ``),
			want: "is not discriminated",
		},
		{
			name: "shared store, same discriminator value",
			spec: head + descr("doc", ` where resource_type = "x"`) + descr("note", ` where resource_type = "x"`),
			want: "SAME discriminator value",
		},
		{
			name: "shared store, different discriminator column",
			spec: head + descr("doc", ` where resource_type = "doc"`) + descr("note", ` where kind2 = "note"`),
			want: "SAME column",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.spec)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// The @store_manage write-moat dispatches per resource_type to the matching
// kind's can-edit, fail-closed — the engine-generated write governance for a
// shared resource_acl.
const storeManageSpec = `
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
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at
subject operator { anchor platform reach via grant impersonation identifies sub roles none }
subject admin    { anchor tenant   reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project  reach self identifies customer_id roles configurable cust binds owner }
object record {
  table  records
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view = @app_scope + owner + grantee:read  @rls maps select
  permission edit = @app_scope + owner + grantee:write @rls maps update
}
object file {
  table  files
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "file"
  permission view = @app_scope + owner + grantee:read  @rls maps select
  permission edit = @app_scope + owner + grantee:write @rls maps update
}
object resource_grant {
  table  resource_acl
  scoped tenant > project
  permission view   = @store_manage @rls maps select
  permission create = @store_manage @rls maps insert
  permission delete = @store_manage @rls maps delete
}
`

func TestStoreManage_DispatchPerKind(t *testing.T) {
	s, err := Parse(storeManageSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	body := map[string]string{}
	for _, d := range defs {
		body[d.Name] = d.Body
	}
	// Per-kind can-edit definers exist (the dispatch targets).
	for _, k := range []string{"record_can_edit", "file_can_edit"} {
		if b, ok := body[k]; !ok || !strings.HasPrefix(b, "EXISTS (SELECT 1 FROM ") {
			t.Errorf("missing/wrong %s definer: %q", k, b)
		}
	}
	// The dispatch CASEs the discriminator to each kind's can-edit, fail-closed.
	mng, ok := body["resource_acl_manage"]
	if !ok {
		t.Fatalf("no resource_acl_manage dispatch; have %v", grantKeys(body))
	}
	for _, want := range []string{
		"CASE p_type",
		"WHEN 'record' THEN auth.record_can_edit(p_id)",
		"WHEN 'file' THEN auth.file_can_edit(p_id)",
		"ELSE false END",
	} {
		if !strings.Contains(mng, want) {
			t.Errorf("dispatch missing %q:\n%s", want, mng)
		}
	}
	// The write-governance policies call the dispatch over the row's own columns.
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	psql := res.PolicySQL("authenticated")
	if !strings.Contains(psql, "auth.resource_acl_manage(resource_type, resource_id)") {
		t.Errorf("resource_grant policies do not call the dispatch:\n%s", psql)
	}
}

func TestStoreManage_Rejects(t *testing.T) {
	const head = `topology { level a }
vocabulary cust { permission self:read }
subject customer { anchor a reach self identifies customer_id roles configurable cust binds owner }
`
	cases := []struct{ name, spec, want string }{
		{
			name: "no descriptor backs the store",
			spec: head + `object g { table empty_acl scoped a permission create = @store_manage @rls maps insert }`,
			want: "no object uses its table",
		},
		{
			name: "store not discriminated",
			spec: head + `object rec {
  table records scoped a
  relation owner:   customer via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access)
  permission view = owner + grantee:read  @rls maps select
  permission edit = owner + grantee:write @rls maps update
}
object g { table resource_acl scoped a permission create = @store_manage @rls maps insert }`,
			want: "not discriminated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.spec)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := Validate(s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func grantKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
