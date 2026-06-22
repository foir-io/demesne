package demesne

import (
	"strings"
	"testing"
)

// EID-364 — the 1-hop composition-parent cascade (`via composition`): a composed
// CHILD record is accessible at the SAME verb the caller passes on its composition
// PARENT, reached through a structural edge table (record_relationships). This mirrors
// Foir's own record object (owner + admin_owner + discriminated grant + public mode)
// plus the composition relation, so the test pins the cascade as it ships.
const compositionSpec = `
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
  permission view   = @app_scope(exclude admin_owner) + owner + admin_owner + mode access_mode = "public" + grantee:read   + comp_parent   @rls maps select
  permission edit   = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:write  + comp_parent   @rls maps update
  permission delete = @app_scope(exclude admin_owner) + owner + admin_owner + grantee:delete + comp_parent   @rls maps delete
}
`

func TestComposition_CascadeWiringAndDefiner(t *testing.T) {
	s, err := Parse(compositionSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Parser carried the columns + kind filter onto the AST.
	var vc *ViaComposition
	for _, o := range s.Objects {
		for _, r := range o.Relations {
			if v, ok := r.Repr.(ViaComposition); ok {
				vv := v
				vc = &vv
			}
		}
	}
	if vc == nil {
		t.Fatal("no ViaComposition relation parsed")
	}
	if vc.Table != "record_relationships" || vc.ChildCol != "from_record_id" || vc.ParentCol != "to_record_id" || vc.KindCol != "kind" || vc.KindVal != "composition" {
		t.Fatalf("parsed ViaComposition = %+v", *vc)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	// Each verb's policy carries the cascade term at its OWN access class (the calling
	// verb is threaded through — read on select, write on update, delete on delete).
	for _, tc := range []struct{ policy, access string }{
		{"records_select", "read"}, {"records_update", "write"}, {"records_delete", "delete"},
	} {
		p := findPolicy(rls, tc.policy)
		if p == nil {
			t.Fatalf("no %s (unsupported: %v)", tc.policy, rls.Unsupported)
		}
		want := "auth.record_composition_comp_parent(records.id, '" + tc.access + "')"
		if !strings.Contains(p.Using+p.Check, want) {
			t.Errorf("%s missing cascade term %q:\n%s", tc.policy, want, p.Using+p.Check)
		}
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	var fn *GenFn
	for i := range defs {
		if defs[i].Name == "record_composition_comp_parent" {
			fn = &defs[i]
		}
	}
	if fn == nil {
		t.Fatal("no record_composition_comp_parent definer (RLS term would dangle)")
	}
	if fn.Sig != "p_record_id text, p_access text" {
		t.Errorf("definer sig = %q", fn.Sig)
	}
	// EXISTS over the edge, gated by the kind discriminator + the child column equal to
	// this row; each per-access branch is a CORRELATED EXISTS over the object table at
	// the parent row (NOT a join — the edge table shares tenant_id/project_id, so a join
	// would make the parent predicate's unqualified columns ambiguous).
	wantPrefix := "EXISTS (SELECT 1 FROM record_relationships e WHERE e.from_record_id = p_record_id AND e.kind = 'composition' AND CASE p_access "
	if !strings.HasPrefix(fn.Body, wantPrefix) {
		t.Errorf("definer body prefix mismatch:\n%s", fn.Body)
	}
	for _, frag := range []string{
		"WHEN 'read' THEN EXISTS (SELECT 1 FROM records WHERE records.id = e.to_record_id AND (",
		"WHEN 'write' THEN EXISTS (SELECT 1 FROM records WHERE records.id = e.to_record_id AND (",
		"WHEN 'delete' THEN EXISTS (SELECT 1 FROM records WHERE records.id = e.to_record_id AND (",
		"ELSE false END",
	} {
		if !strings.Contains(fn.Body, frag) {
			t.Errorf("definer body missing %q:\n%s", frag, fn.Body)
		}
	}

	// 1-HOP / RECURSION SAFETY: the parent predicate is built with composition PRUNED,
	// so the definer must NOT call ITSELF — a composition term at the parent would
	// re-enter this function (unbounded recursion / a cycle hang). This is the load-
	// bearing invariant of the prune.
	if strings.Contains(fn.Body, "record_composition_comp_parent") {
		t.Errorf("definer is self-recursive — composition was NOT pruned from the parent predicate:\n%s", fn.Body)
	}

	// The parent ACCESS is the object's real grant surface (not a stub): the read
	// branch borrows owner + the grant ACL at the parent (evaluated at the joined
	// `records` row, claims from the GUC).
	c := "(current_setting('request.jwt.claims', true)::json ->> 'customer_id')"
	if !strings.Contains(fn.Body, "customer_id = "+c) {
		t.Errorf("read branch does not borrow the parent's owner predicate:\n%s", fn.Body)
	}
	if !strings.Contains(fn.Body, "auth.resource_acl_grants") {
		t.Errorf("read branch does not borrow the parent's grant predicate (so a shared parent would not cascade):\n%s", fn.Body)
	}
}

// A composition relation without a kind discriminator is valid (the cascade applies to
// every edge in the table); the emitted definer then carries no kind filter.
func TestComposition_NoKindFilter(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		vocabulary v { permission self:read }
		subject customer { anchor project reach self identifies cust roles configurable v binds owner }
		object record {
		  table  records
		  scoped tenant > project
		  relation owner: customer via owner_id
		  relation comp_parent: record via composition edges(child_id, parent_id)
		  permission view = owner + comp_parent @rls maps select
		}`)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	for i := range defs {
		if defs[i].Name == "record_composition_comp_parent" {
			if strings.Contains(defs[i].Body, "AND e.kind") {
				t.Errorf("undiscriminated composition should emit no kind filter:\n%s", defs[i].Body)
			}
			if !strings.Contains(defs[i].Body, "WHERE e.child_id = p_record_id AND CASE p_access") {
				t.Errorf("undiscriminated composition body shape:\n%s", defs[i].Body)
			}
			return
		}
	}
	t.Fatal("no composition definer emitted")
}
