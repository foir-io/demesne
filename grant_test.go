package demesne

import (
	"strings"
	"testing"
)

// A spec whose operator is a SCOPED grant (the general replacement for an
// unconditional membership god-flag): the operator reaches a tenant subtree iff
// it holds an active row in the impersonation_grants edge, and nothing more.
const grantSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read  permission content:write
  preset project_viewer @ project = content:read
  preset project_admin  @ project = project_viewer + content:write
  preset tenant_owner   @ tenant  = *
  rank tenant_owner > project_admin > project_viewer
}
vocabulary customer {
  permission self:read
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at

subject operator { anchor platform; reach via grant impersonation; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }
subject customer { anchor project;  reach self; identifies customer_id; roles configurable customer; binds owner }

object project {
  table  projects
  level  project
  scoped tenant > project
  relation tenant: tenant via tenant_id
  relation admin:  admin  via role(rank >= project_admin)
  permission view = tenant->owner + @session            @rls maps select
  permission edit = tenant->owner + @session(admin)     @rls maps update
}
object record {
  table  records
  scoped tenant > project
  relation owner: customer via customer_id
  permission view = owner @rls maps select
}
`

func TestGrant_ScopedOperatorReplacesGodFlag(t *testing.T) {
	s, err := Parse(grantSpec)
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
	byName := map[string]GenFn{}
	for _, d := range defs {
		byName[d.Name] = d
	}

	// (1) The grant-reach definer exists, is tenant-scoped, and gates on active +
	//     non-expired — NOT an unconditional god predicate.
	reach, ok := byName["impersonation_grants_reach"]
	if !ok {
		t.Fatalf("no impersonation_grants_reach definer generated; got %v", keysOf(byName))
	}
	if reach.Sig != "user_id text, check_tenant_id text" {
		t.Errorf("reach sig = %q, want tenant-scoped (user_id text, check_tenant_id text)", reach.Sig)
	}
	for _, want := range []string{"FROM impersonation_grants", "grantee_id = user_id", "tenant_id = check_tenant_id", "revoked_at IS NULL", "expires_at > now()"} {
		if !strings.Contains(reach.Body, want) {
			t.Errorf("reach body missing %q:\n%s", want, reach.Body)
		}
	}

	// (2) There is NO unconditional god-flag definer (is_platform_admin et al.).
	if _, bad := byName["is_platform_admin"]; bad {
		t.Error("a god-flag definer is_platform_admin was generated — the operator must be grant-scoped")
	}

	// (3) The tenant role definer admits the operator via the SCOPED grant reach,
	//     not via an unconditional disjunct.
	ta, ok := byName["is_tenant_admin"]
	if !ok {
		t.Fatalf("no is_tenant_admin generated; got %v", keysOf(byName))
	}
	if !strings.Contains(ta.Body, "auth.impersonation_grants_reach(user_id, check_tenant_id) OR") {
		t.Errorf("is_tenant_admin should OR the scoped grant reach, got:\n%s", ta.Body)
	}
	if strings.Contains(ta.Body, "is_platform_admin") {
		t.Errorf("is_tenant_admin still references a god-flag:\n%s", ta.Body)
	}

	// (4) RLS: the operator reaches a record only through the tenant-scoped grant
	//     (no `... IS NULL` ambient cross-tenant view), and the closure holds.
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	var recSelect *Policy
	for i := range rls.Policies {
		if rls.Policies[i].Name == "records_select" {
			recSelect = &rls.Policies[i]
		}
	}
	if recSelect == nil {
		t.Fatal("no records_select policy emitted")
	}
	if !strings.Contains(recSelect.Using, "auth.impersonation_grants_reach(") {
		t.Errorf("records_select must grant the operator via the grant reach, got:\n%s", recSelect.Using)
	}
	// The reach is scoped to the row's own tenant_id (cascade), so a sibling
	// tenant is unreachable. The old god-branch `AND project_id ... IS NULL` must
	// be gone.
	if strings.Contains(recSelect.Using, "IS NULL") {
		t.Errorf("records_select still carries an ambient null-scope god view:\n%s", recSelect.Using)
	}
	if !strings.Contains(recSelect.Using, "tenant_id)") {
		t.Errorf("operator reach is not scoped to the row's tenant_id:\n%s", recSelect.Using)
	}
}

func keysOf(m map[string]GenFn) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
