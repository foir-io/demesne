package demesne

import (
	"strings"
	"testing"
)

// WS3 convergence — a level-scoped Grant and a per-row access-class grant relation
// are the SAME concept (a ReachGrant), enumerable as one, built from one shared
// shape — but they keep SEPARATE physical stores and specialized SQL (the moat).
const reachGrantSpec = `
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
  relation grantee: customer via grant record_acl(record_id, principal_kind, principal_id, access)
  permission view = owner + mode access_mode = "public_project" + grantee:read @rls maps select
}
`

func TestReachGrant_UnifiedConceptSeparateStores(t *testing.T) {
	s, err := Parse(reachGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// (1) Both grant constructs enumerate as ONE concept, each classified by its
	//     target granularity.
	grants := s.ReachGrants()
	if len(grants) != 2 {
		t.Fatalf("ReachGrants = %d, want 2 (a level grant + a per-row grant relation)", len(grants))
	}
	byEdge := map[string]ReachGrant{}
	for _, g := range grants {
		byEdge[g.EdgeTable()] = g
	}
	lvl, ok := byEdge["impersonation_grants"]
	if !ok || lvl.Granularity() != LevelReach || lvl.GranteeColumn() != "grantee_id" {
		t.Errorf("level grant: %+v (want LevelReach, grantee grantee_id)", lvl)
	}
	row, ok := byEdge["record_acl"]
	if !ok || row.Granularity() != RowReach || row.GranteeColumn() != "principal_id" {
		t.Errorf("acl edge: %+v (want RowReach, grantee principal_id)", row)
	}

	// (2) The stores are SEPARATE tables — NOT merged into one Zanzibar tuple store.
	if lvl.EdgeTable() == row.EdgeTable() {
		t.Error("the two grant stores collapsed into one table — the moat rejects a single tuple store")
	}

	// (3) Both definer bodies are the shared EXISTS-over-edge shape, each over its
	//     OWN edge with its OWN specialized, sargable conjuncts.
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	body := map[string]string{}
	for _, d := range defs {
		body[d.Name] = d.Body
	}
	reach := body["impersonation_grants_reach"]
	if !strings.HasPrefix(reach, "EXISTS (SELECT 1 FROM impersonation_grants WHERE ") ||
		!strings.Contains(reach, "grantee_id = user_id") ||
		!strings.Contains(reach, "tenant_id = check_tenant_id") {
		t.Errorf("level-grant definer not the shared shape over its own store:\n%s", reach)
	}
	acl := body["record_acl_grants"]
	if !strings.HasPrefix(acl, "EXISTS (SELECT 1 FROM record_acl WHERE ") ||
		!strings.Contains(acl, "principal_id = p_customer_id") ||
		!strings.Contains(acl, "access = p_access") {
		t.Errorf("acl-edge definer not the shared shape over its own store:\n%s", acl)
	}
	// Neither reads the other's table.
	if strings.Contains(reach, "record_acl") || strings.Contains(acl, "impersonation_grants") {
		t.Error("a grant definer reads the other grant's store — they are not independent")
	}
}

// grantEdgeExists is the single shared shape; identical conjuncts → identical SQL,
// regardless of which construct supplied them.
func TestReachGrant_SharedShapeBuilder(t *testing.T) {
	got := grantEdgeExists("t", "a = x", "b = y")
	if got != "EXISTS (SELECT 1 FROM t WHERE a = x AND b = y)" {
		t.Errorf("grantEdgeExists = %q", got)
	}
}
