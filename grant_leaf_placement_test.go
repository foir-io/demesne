package demesne

import (
	"strings"
	"testing"
)

// Where a grant's reach lands decides whether containment still binds, and the
// two placements differ only on INSERT. A top-level branch stands alone, so
// satisfying it satisfies the policy and the tenant and project conjuncts
// contribute nothing. A term spliced into containment has to satisfy them too.
//
// The distinction is not "is the grant at the object's leaf". It is "is the
// reaching subject anchored at the grant's own level", and this fixture carries
// both arms so neither can move without the other noticing:
//
//   - operator is anchored at platform and reaches via a TENANT grant. On an
//     object whose leaf IS tenant, that reach is the subject's whole warrant and
//     belongs at the top. Deciding this on the grant alone reroutes it into
//     containment, which narrows an authority meant to arrive from above.
//
//   - member is anchored at org and reaches via an ORG grant. On an object whose
//     leaf IS org, that reach names a peer rather than an authority over the
//     tree, so it must be conjoined with the levels above it. Left at the top it
//     would authorise an insert into another tenant's project outright.
const leafPlacementSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
  level org      parent project
}
vocabulary admin { permission content:read permission content:write
  preset tenant_owner @ tenant = *
  rank tenant_owner > tenant_owner }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant impersonation at tenant via edge impersonation_grants(grantee_id, tenant_id) active revoked_at
grant orgreach     at org    via edge org_member_grants(principal_id, org_id)      active revoked_at

subject operator { anchor platform; reach via grant impersonation; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
subject member   { anchor org;      reach via grant orgreach; identifies customer_id; roles none }

object tenantthing {
  table  tenantthings
  scoped tenant
  relation admin: admin via role
  permission view   = @session(admin) @rls maps select
  permission create = @session(admin) @rls maps insert
}
object record {
  table  records
  scoped tenant > project > org
  relation owner: member via customer_id
  permission view   = owner @rls maps select
  permission create = owner @rls maps insert
}
`

// topLevelBranches splits a policy expression on its TOP-LEVEL ORs, ignoring any
// OR nested inside parentheses. Substring matching cannot tell a term that stands
// alone from one buried in a conjunct, and that difference is the whole subject
// of this file.
func topLevelBranches(expr string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			depth--
		case 'O':
			if depth == 0 && strings.HasPrefix(expr[i:], "OR ") &&
				i > 0 && expr[i-1] == ' ' {
				out = append(out, strings.TrimSpace(expr[start:i]))
				start = i + 3
			}
		}
	}
	return append(out, strings.TrimSpace(expr[start:]))
}

func leafPolicyByName(t *testing.T, rls *RLSResult, name string) Policy {
	t.Helper()
	for _, p := range rls.Policies {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no %s policy emitted", name)
	return Policy{}
}

func emitLeafPlacement(t *testing.T) *RLSResult {
	t.Helper()
	s, err := Parse(leafPlacementSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	return rls
}

// The headline. A grant at the object's own leaf, reached by a subject anchored
// at that level, must not become a standalone branch: every top-level branch
// that carries the reach must carry the levels above it too, or an insert can
// name any tenant it likes.
func TestGrantReach_LeafLevelFromAnchoredSubjectStaysContained(t *testing.T) {
	ins := leafPolicyByName(t, emitLeafPlacement(t), "records_insert")
	if !strings.Contains(ins.Check, "auth.org_member_grants_reach(") {
		t.Fatalf("records_insert does not carry the org grant reach at all:\n%s", ins.Check)
	}
	for _, br := range topLevelBranches(ins.Check) {
		if !strings.Contains(br, "auth.org_member_grants_reach(") {
			continue
		}
		for _, above := range []string{"tenant_id", "project_id"} {
			if !strings.Contains(br, above) {
				t.Errorf("a top-level branch carries the org reach without %s, so an insert satisfies the policy on the grant alone:\n%s", above, br)
			}
		}
	}
}

// The other arm, and the reason the gate is not simply `g.Level != objLeaf`. A
// subject anchored ABOVE the level it reaches into keeps its top-level branch.
// Rerouting this one into containment rewrites live policies on tables that have
// nothing to do with org depth.
func TestGrantReach_LeafLevelFromSubjectAnchoredAboveStaysTopLevel(t *testing.T) {
	ins := leafPolicyByName(t, emitLeafPlacement(t), "tenantthings_insert")
	var standalone bool
	for _, br := range topLevelBranches(ins.Check) {
		if strings.Contains(br, "auth.impersonation_grants_reach(") && !strings.Contains(br, " AND ") {
			standalone = true
		}
	}
	if !standalone {
		t.Errorf("the operator's reach is no longer a top-level branch on an object whose leaf is the grant's own level; rerouting it narrows an authority that arrives from above:\n%s", ins.Check)
	}
}

// Containment is only in question at the leaf. A grant ABOVE the object's leaf
// was already contained and must stay so.
func TestGrantReach_AboveLeafRemainsContained(t *testing.T) {
	ins := leafPolicyByName(t, emitLeafPlacement(t), "records_insert")
	for _, br := range topLevelBranches(ins.Check) {
		if strings.Contains(br, "auth.impersonation_grants_reach(") && !strings.Contains(br, "project_id") {
			t.Errorf("the tenant grant reach escaped containment on an org-leafed object:\n%s", br)
		}
	}
}
