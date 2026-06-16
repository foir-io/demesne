package demesne

import (
	"strings"
	"testing"
)

// Primitive 4: the grant write-moat (@store_manage) must dispatch over grant
// RELATIONS, not only descriptors — so the resource_grant governance object keeps
// working when record/file/note go pure. This proves the generated dispatch
// (auth.resource_acl_manage(type,id) CASE → <kind>_can_edit) and the per-kind
// can-edit definers are byte-identical between the descriptor and pure-relation
// forms, with two kinds (record + file) sharing one discriminated store.

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

const storeManageDescriptorSpec = storeManageHead + `
object record {
  table records
  scoped tenant > project
  descriptor {
    owner  customer | service via customer_id
    mode   via access_mode
    modes  private + read "public" + list "customer"
    grants via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "record"
  }
  permission view   = @app_scope + @descriptor @rls maps select
  permission edit   = @app_scope + @descriptor @rls maps update
  permission create = @app_scope + @descriptor @rls maps insert
  permission delete = @app_scope + @descriptor @rls maps delete
}
object file {
  table files
  scoped tenant > project
  descriptor {
    owner  customer | service via customer_id
    mode   via access_mode
    modes  private + read "public" + list "customer"
    grants via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "file"
  }
  permission view   = @app_scope + @descriptor @rls maps select
  permission edit   = @app_scope + @descriptor @rls maps update
  permission create = @app_scope + @descriptor @rls maps insert
  permission delete = @app_scope + @descriptor @rls maps delete
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

func TestStoreManagePure_ByteIdenticalToDescriptor(t *testing.T) {
	desc, err := Parse(storeManageDescriptorSpec)
	if err != nil {
		t.Fatalf("parse descriptor: %v", err)
	}
	if err := Validate(desc); err != nil {
		t.Fatalf("validate descriptor: %v", err)
	}
	pure, err := Parse(storeManagePureSpec)
	if err != nil {
		t.Fatalf("parse pure: %v", err)
	}
	if err := Validate(pure); err != nil {
		t.Fatalf("validate pure: %v", err)
	}

	// resource_acl policy SQL (the @store_manage moat) is byte-identical.
	dRLS, _ := desc.EmitRLS()
	pRLS, _ := pure.EmitRLS()
	dACL := onlyTable(dRLS, "resource_acl").PolicySQL("authenticated")
	pACL := onlyTable(pRLS, "resource_acl").PolicySQL("authenticated")
	if dACL != pACL {
		t.Errorf("resource_acl policies differ:\n--- descriptor ---\n%s\n--- pure ---\n%s", dACL, pACL)
	}

	// The dispatch + per-kind can-edit definers are byte-identical.
	for _, name := range []string{"resource_acl_manage", "record_can_edit", "file_can_edit"} {
		if d, p := grantFnByName(t, desc, name), grantFnByName(t, pure, name); d != p {
			t.Errorf("definer %q differs:\n--- descriptor ---\n%s\n--- pure ---\n%s", name, d, p)
		}
	}

	// Sanity: the dispatch CASEs over both kinds.
	mng := grantFnByName(t, pure, "resource_acl_manage")
	for _, want := range []string{"WHEN 'record' THEN auth.record_can_edit(p_id)", "WHEN 'file' THEN auth.file_can_edit(p_id)"} {
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
