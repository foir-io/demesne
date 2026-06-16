package demesne

import "testing"

// The runtime ResourceAccessSurface (the handler's grant/visibility/expand SQL
// source) must project byte-identically from a pure-relation object as from the
// descriptor form — so dropping the descriptor needs no handler change.
func TestResourceAccessSurface_PureMatchesDescriptor(t *testing.T) {
	desc, err := Parse(storeManageDescriptorSpec)
	if err != nil {
		t.Fatalf("parse descriptor: %v", err)
	}
	pure, err := Parse(storeManagePureSpec)
	if err != nil {
		t.Fatalf("parse pure: %v", err)
	}
	for _, obj := range []string{"record", "file"} {
		ds, err := desc.ResourceAccessSurface(obj)
		if err != nil {
			t.Fatalf("descriptor surface %s: %v", obj, err)
		}
		ps, err := pure.ResourceAccessSurface(obj)
		if err != nil {
			t.Fatalf("pure surface %s: %v", obj, err)
		}
		// Layout + projected vocab.
		if ds.Table != ps.Table || ds.ModeCol != ps.ModeCol {
			t.Errorf("%s: Table/ModeCol differ: %+v vs %+v", obj, ds, ps)
		}
		if !ds.IsReadMode("public") || !ps.IsReadMode("public") {
			t.Errorf("%s: both should report 'public' as a read mode", obj)
		}
		if ds.GrantKindAllowed("customer") != ps.GrantKindAllowed("customer") {
			t.Errorf("%s: customer grant-kind mismatch", obj)
		}
		// The generated SQL shapes must be identical (string-for-string).
		scope := []string{"t1", "p1"}
		dIns, _ := ds.GrantInsert(scope, "r1", "customer", "c1", "read")
		pIns, _ := ps.GrantInsert(scope, "r1", "customer", "c1", "read")
		if dIns != pIns {
			t.Errorf("%s GrantInsert differs:\n%s\n%s", obj, dIns, pIns)
		}
		if ds.SetVisibilitySQL() != ps.SetVisibilitySQL() ||
			ds.ListGrantsSQL() != ps.ListGrantsSQL() ||
			ds.AccessorsSQL() != ps.AccessorsSQL() ||
			ds.ModeSQL() != ps.ModeSQL() {
			t.Errorf("%s: a generated SQL shape differs", obj)
		}
	}
}
