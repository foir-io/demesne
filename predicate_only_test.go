package demesne

import (
	"strings"
	"testing"
)

const predicateOnlyRoleStore = `
topology { level platform virtual level tenant parent platform level project parent tenant }
vocabulary v { permission a:b preset tadmin @ tenant = a:b }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin { anchor tenant reach descendants identifies sub roles configurable v binds admin }
`

func TestPredicateOnly_LentAuthorityViaObject(t *testing.T) {
	s := mustSpec(t, predicateOnlyRoleStore+`
object widget_control {
  table  widgets
  scoped tenant
  relation tenant: tenant via tenant_id
  permission control = tenant->owner @rls predicate
}
object widget_links {
  table  widget_links
  scoped platform
  relation key: widget_control via object widget_control->control on widget_id
  permission view = key @rls maps select
}
`)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	if p := findPolicy(rls, "widgets_select"); p != nil {
		t.Errorf("a predicate-only permission must emit NO policy on its own table, got: %s", p.Using)
	}

	links := findPolicy(rls, "widget_links_select")
	if links == nil {
		t.Fatalf("no widget_links_select (unsupported: %v)", rls.Unsupported)
	}
	if !strings.Contains(links.Using, "auth.widget_control_can_control(widget_id)") {
		t.Errorf("child must borrow the lent authority via the cross-object definer:\n%s", links.Using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	var can *GenFn
	for i := range defs {
		if defs[i].Name == "widget_control_can_control" {
			can = &defs[i]
		}
	}
	if can == nil {
		t.Fatal("the lent authority's definer widget_control_can_control was not generated")
	}
	sub := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"
	if !strings.HasPrefix(can.Body, "EXISTS (SELECT 1 FROM widgets WHERE widgets.id = p_widget_control_id AND (") {
		t.Errorf("definer must EXISTS over the parent by pk:\n%s", can.Body)
	}
	if !strings.Contains(can.Body, "auth.is_tenant_admin("+sub+", tenant_id)") {
		t.Errorf("definer must carry the tenant-scoped control authority:\n%s", can.Body)
	}
	if strings.Contains(can.Body, "project_id") {
		t.Errorf("the tenant-scoped control authority must carry no project condition:\n%s", can.Body)
	}
}

func TestPredicateOnly_UnreferencedRejected(t *testing.T) {
	s := mustSpec(t, predicateOnlyRoleStore+`
object widget_control {
  table  widgets
  scoped tenant
  relation tenant: tenant via tenant_id
  permission control = tenant->owner @rls predicate
}
`)
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "never borrowed") {
		t.Errorf("a predicate-only permission with no via-object borrowing it should be rejected as dead SQL, got: %v", err)
	}
}

func TestPredicateOnly_WithMapsRejected(t *testing.T) {
	s := mustSpec(t, predicateOnlyRoleStore+`
object widget_control {
  table  widgets
  scoped tenant
  relation tenant: tenant via tenant_id
  permission control = tenant->owner @rls maps select predicate
}
`)
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "predicate") {
		t.Errorf("`predicate` + `maps` should be rejected as contradictory, got: %v", err)
	}
}
