package demesne

import (
	"strings"
	"testing"
)

const bareSelfGrantSpec = `
topology { level platform virtual level tenant parent platform level project parent tenant }
vocabulary v { permission c:r }
grant g at tenant via edge grants_edge(grantee_id, tenant_id)
subject operator { anchor platform reach via grant g identifies sub roles none }
object grants_edge {
  table  grants_edge
  scoped tenant
  permission view = @self(grantee_id) @rls maps select
}
object other_thing {
  table  other_things
  scoped tenant
  permission view = @scoped @rls maps select
}
`

func TestGrantReach_SuppressedOnOwnSourceTable(t *testing.T) {
	s := mustSpec(t, bareSelfGrantSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sub := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"

	edge := findPolicy(rls, "grants_edge_select")
	if edge == nil {
		t.Fatalf("no grants_edge_select (unsupported: %v)", rls.Unsupported)
	}
	if edge.Using != "grantee_id = "+sub {
		t.Errorf("grant source table must be bare self-read (no reach on its own grant):\n%s", edge.Using)
	}

	other := findPolicy(rls, "other_things_select")
	if other == nil {
		t.Fatalf("no other_things_select")
	}
	if !strings.Contains(other.Using, "auth.grants_edge_reach("+sub+", tenant_id)") {
		t.Errorf("a normal tenant-scoped table should still get the operator reach:\n%s", other.Using)
	}
}
