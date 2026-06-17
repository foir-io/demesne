package demesne

import (
	"strings"
	"testing"
)

// The grant write-moat (@store_manage) dispatches over grant RELATIONS, so the
// resource_grant governance object keeps working when record/file go pure. These
// golden tests pin the generated dispatch (auth.resource_acl_manage(type,id) CASE
// → <kind>_can_edit) and the per-kind can-edit definers, with two kinds (record +
// file) sharing one discriminated store.

const storeManageHead = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin { permission c:r  preset pa @ project = c:r }
vocabulary cust  { permission self:read }
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
subject service  { anchor project reach self identifies sub roles none }
object resource_grant {
  table  resource_acl
  scoped tenant > project
  permission view   = @store_manage   @rls maps select
  permission create = @store_manage   @rls maps insert
  permission edit   = @store_manage   @rls maps update
  permission delete = @store_manage   @rls maps delete
}
`

const storeManagePureSpec = storeManageHead + `
object record {
  table records
  scoped tenant > project
  relation owner:   customer | service via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  permission view   = @app_scope + owner + mode access_mode = "public" + grantee:read @rls maps select
  permission edit   = @app_scope + owner + grantee:write  @rls maps update
  permission create = @app_scope + owner                  @rls maps insert
  permission delete = @app_scope + owner + grantee:delete @rls maps delete
}
object file {
  table files
  scoped tenant > project
  relation owner:   customer | service via customer_id
  relation grantee: customer via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "file"
  permission view   = @app_scope + owner + mode access_mode = "public" + grantee:read @rls maps select
  permission edit   = @app_scope + owner + grantee:write  @rls maps update
  permission create = @app_scope + owner                  @rls maps insert
  permission delete = @app_scope + owner + grantee:delete @rls maps delete
}
`

func TestStoreManagePure_EmitsDispatch(t *testing.T) {
	pure, err := Parse(storeManagePureSpec)
	if err != nil {
		t.Fatalf("parse pure: %v", err)
	}
	if err := Validate(pure); err != nil {
		t.Fatalf("validate pure: %v", err)
	}

	// The resource_acl write-moat policies call the per-kind dispatch over the row's
	// own discriminator + id columns.
	pRLS, err := pure.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	acl := onlyTable(pRLS, "resource_acl").PolicySQL("authenticated")
	if !strings.Contains(acl, "auth.resource_acl_manage(resource_type, resource_id)") {
		t.Errorf("resource_acl policies do not call the dispatch:\n%s", acl)
	}

	// The per-kind can-edit definers are EXISTS-over-the-resource shapes.
	for _, name := range []string{"record_can_edit", "file_can_edit"} {
		b := grantFnByName(t, pure, name)
		if !strings.Contains(b, "EXISTS (SELECT 1 FROM ") {
			t.Errorf("definer %q wrong shape:\n%s", name, b)
		}
	}

	// The dispatch CASEs over both kinds, fail-closed.
	mng := grantFnByName(t, pure, "resource_acl_manage")
	for _, want := range []string{
		"WHEN 'record' THEN auth.record_can_edit(p_id)",
		"WHEN 'file' THEN auth.file_can_edit(p_id)",
	} {
		if !strings.Contains(mng, want) {
			t.Errorf("resource_acl_manage missing %q:\n%s", want, mng)
		}
	}
}

// onlyTable returns a copy of the RLSResult restricted to one table's policies.
func onlyTable(res *RLSResult, table string) *RLSResult {
	out := &RLSResult{}
	for _, p := range res.Policies {
		if p.Table == table {
			out.Policies = append(out.Policies, p)
		}
	}
	return out
}
