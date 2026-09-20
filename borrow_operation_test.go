package demesne

import (
	"strings"
	"testing"
)

func TestBorrowOperation_CompilesThePredicateForTheNamedOp(t *testing.T) {
	e := emitReach(t, reachFixture)

	read := e.definer(t, "catalog_can_bound_for_select")
	if read.Sig != "p_catalog_id text" {
		t.Errorf("catalog_can_bound_for_select sig = %q", read.Sig)
	}
	hasFragments(t, "catalog_can_bound_for_select", read.Body,
		"EXISTS (SELECT 1 FROM catalogs WHERE catalogs.id = p_catalog_id AND (",
		"((folder_id IS NULL OR folder_id = "+claimSQL("folder_id")+") OR folder_id IN (SELECT auth.paths_up_reach_set("+claimSQL("folder_id")+")) OR "+claimSQL("view_mode")+" = 'all')",
		claimSQL("kind")+" = 'staff'")

	strict := e.definer(t, "catalog_can_bound")
	hasFragments(t, "catalog_can_bound", strict.Body, "folder_id IS NOT DISTINCT FROM "+claimSQL("folder_id"), claimSQL("kind")+" = 'staff'")
	lacksFragments(t, "catalog_can_bound", strict.Body, "paths_up_reach_set", "paths_reach_set", "view_mode")

	if got := e.policy(t, "entries_select").Using; !strings.Contains(got, "auth.catalog_can_bound_for_select(catalog_id)") || strings.Contains(got, "auth.catalog_can_bound(") {
		t.Errorf("entries_select must borrow the read form only:\n%s", got)
	}
	upd := e.policy(t, "entries_update")
	for _, half := range []string{upd.Using, upd.Check} {
		if !strings.Contains(half, "auth.catalog_can_bound(catalog_id)") || strings.Contains(half, "_for_select") {
			t.Errorf("entries_update must borrow the strict form only:\n%s", half)
		}
	}
}

func TestBorrowOperation_Refusals(t *testing.T) {
	t.Run("mapped permission", func(t *testing.T) {
		src := strings.Replace(reachFixture, "via object catalog->bound on catalog_id for select", "via object asset->view on catalog_id for select", 1)
		mustRefuse(t, src, "already maps select", "predicate-only")
	})
	t.Run("unknown operation", func(t *testing.T) {
		src := strings.Replace(reachFixture, "via object catalog->bound on catalog_id for select", "via object catalog->bound on catalog_id for upsert", 1)
		mustRefuse(t, src, `unknown operation "upsert"`)
	})
}
