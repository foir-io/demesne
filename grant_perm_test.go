package demesne

import (
	"strings"
	"testing"
)

// `via grant <name>` as a PERMISSION term (v0.43.0): a verb conferred by a declared
// grant's reach, emitted as a top-level branch. When it is the SOLE grant (no
// @scoped / owner / role term) the containment block is SUPPRESSED — so the verb is
// granted only to the grant's holders, NOT to in-scope members. This is the generic
// mechanism behind "operator-only writes" (e.g. billing): the tenant's own admins can
// read but are excluded from writing. The word "operator"/"impersonation" lives in
// the APP spec (the grant + subject), never in the engine.
const grantPermSpec = `
topology {
  level platform virtual
  level tenant   parent platform
}
vocabulary admin {
  permission content:read
  preset tenant_owner @ tenant = content:read
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at

subject operator { anchor platform; reach via grant impersonation; identifies sub; roles none }
subject admin    { anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }

object billing {
  table  billing_subscriptions
  scoped tenant
  permission view   = @scoped                  @rls maps select   // operator OR in-tenant
  permission create = via grant impersonation  @rls maps insert   // operator ONLY (in-tenant admin excluded)
}
`

func TestViaGrantPerm_OperatorOnlyWrite(t *testing.T) {
	s, err := Parse(grantPermSpec)
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
	pol := map[string]Policy{}
	for _, p := range rls.Policies {
		pol[p.Name] = p
	}

	reach := "auth.impersonation_grants_reach((current_setting('request.jwt.claims', true)::json ->> 'sub'), tenant_id)"

	// WRITE: `via grant impersonation` alone → the reach branch ONLY, no containment.
	create, ok := pol["billing_subscriptions_insert"]
	if !ok {
		t.Fatalf("no insert policy; got %v", policyNames(rls))
	}
	if create.Check != reach {
		t.Errorf("operator-only write should be exactly the grant reach, got:\n%s\nwant:\n%s", create.Check, reach)
	}
	if strings.Contains(create.Check, "tenant_id =") {
		t.Errorf("operator-only write leaked the containment branch (an in-tenant admin could write):\n%s", create.Check)
	}

	// READ: @scoped → operator reach OR in-tenant containment (the tenant's admin can read).
	view := pol["billing_subscriptions_select"].Using
	if !strings.Contains(view, reach) {
		t.Errorf("read lost the operator reach:\n%s", view)
	}
	if !strings.Contains(view, "tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'tenant_id')") {
		t.Errorf("read lost the in-tenant containment branch:\n%s", view)
	}
}

// A `via grant` term combined with @scoped dedupes against the auto-added operator
// reach (a tenant-leaf object already carries it in `top`), so the verb is not
// double-listed.
func TestViaGrantPerm_DedupesWithAutoReach(t *testing.T) {
	spec := strings.Replace(grantPermSpec,
		"permission view   = @scoped                  @rls maps select   // operator OR in-tenant",
		"permission view   = @scoped + via grant impersonation  @rls maps select", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, _ := s.EmitRLS()
	for _, p := range rls.Policies {
		if p.Name == "billing_subscriptions_select" {
			if n := strings.Count(p.Using, "impersonation_grants_reach"); n != 1 {
				t.Errorf("operator reach should appear exactly once (deduped), got %d:\n%s", n, p.Using)
			}
		}
	}
}

func TestViaGrantPerm_Errors(t *testing.T) {
	cases := []struct{ name, find, repl string }{
		{"unknown grant", "via grant impersonation  @rls maps insert", "via grant nope  @rls maps insert"},
		{"not rls", "via grant impersonation  @rls maps insert", "via grant impersonation  @pdp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := strings.Replace(grantPermSpec, c.find, c.repl, 1)
			s, err := Parse(spec)
			if err != nil {
				return // a parse-level rejection is also acceptable
			}
			if err := Validate(s); err == nil {
				t.Fatalf("expected a validation error for %q", c.name)
			}
		})
	}
}
