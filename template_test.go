package demesne

import (
	"strings"
	"testing"
)

// The generic permission-template primitive (the app-defined replacement for the
// removed settings/platform sugar). An object applies a template with `use`, may
// `omit` verbs, and may override a verb with its own permission line. A template
// has NO effect on emission — it is pure parse-time sugar resolved into the using
// object's Perms — so a `use contained` object emits exactly the containment
// policies the old `settings <table>` sugar produced.
const templateSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin {
  permission content:read
  preset tenant_owner @ tenant = content:read
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
subject customer { anchor project;  reach self; identifies customer_id; roles none; binds owner }

template contained {
  permission view   = @scoped @rls maps select
  permission create = @scoped @rls maps insert
  permission edit   = @scoped @rls maps update
  permission delete = @scoped @rls maps delete
}

object configs {
  table  configs
  scoped tenant > project
  use    contained
}
object docs {
  table  docs
  scoped tenant > project
  relation owner: customer via customer_id
  use    contained
  omit   delete
  permission view = owner @rls maps select
}
`

func TestTemplate_UseExpandsOverrideOmit(t *testing.T) {
	s, err := Parse(templateSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Expansion happens at parse time: the using objects carry real Perms.
	configs := s.objectByName("configs")
	if configs == nil || len(configs.Perms) != 4 {
		t.Fatalf("configs should inherit the template's 4 perms, got %d", len(configs.Perms))
	}
	// docs: template's view OVERRIDDEN by the object's own line, delete OMITTED →
	// view, create, edit (3 perms, no delete).
	docs := s.objectByName("docs")
	gotVerbs := map[string]bool{}
	for _, pm := range docs.Perms {
		gotVerbs[pm.Verb] = true
	}
	if gotVerbs["delete"] {
		t.Errorf("docs `omit delete` did not drop the delete perm: %v", gotVerbs)
	}
	for _, v := range []string{"view", "create", "edit"} {
		if !gotVerbs[v] {
			t.Errorf("docs missing inherited/own verb %q: %v", v, gotVerbs)
		}
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	pol := map[string]Policy{}
	for _, p := range rls.Policies {
		pol[p.Name] = p
	}

	// (1) A `use contained` object emits all four containment policies — the same
	//     shape the removed `settings <table>` sugar produced: scoped containment
	//     plus the operator impersonation grant, no owner axis.
	for _, op := range []string{"select", "insert", "update", "delete"} {
		p, ok := pol["configs_"+op]
		if !ok {
			t.Fatalf("configs missing %s policy from template; got %v", op, policyNames(rls))
		}
		pred := p.Using
		if pred == "" {
			pred = p.Check
		}
		if !strings.Contains(pred, "auth.impersonation_grants_reach(") {
			t.Errorf("configs_%s lost the operator grant (a @scoped containment policy):\n%s", op, pred)
		}
		if !strings.Contains(pred, "project_id = ") {
			t.Errorf("configs_%s lost project containment:\n%s", op, pred)
		}
		if strings.Contains(pred, "customer_id") {
			t.Errorf("configs_%s leaked an owner axis (it is containment-only):\n%s", op, pred)
		}
	}

	// (2) `omit delete` emits NO delete policy (an append-only-style table would use
	//     this to keep rows immutable — the engine simply emits no policy for it).
	if _, ok := pol["docs_delete"]; ok {
		t.Errorf("docs_delete policy was emitted despite `omit delete`")
	}

	// (3) The object's own `view` line OVERRODE the template's @scoped view → the
	//     docs select policy carries the owner axis, not bare containment.
	dv := pol["docs_select"].Using
	if !strings.Contains(dv, "customer_id = ") {
		t.Errorf("docs_select did not take the overriding owner view:\n%s", dv)
	}
	// …while the non-overridden verbs still come from the template (@scoped).
	di := pol["docs_insert"].Check
	if !strings.Contains(di, "auth.impersonation_grants_reach(") || strings.Contains(di, "customer_id") {
		t.Errorf("docs_insert should be the inherited @scoped containment policy:\n%s", di)
	}
}

func TestTemplate_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"unknown template", `
topology { level tenant }
template t { permission view = @scoped @rls maps select }
object x { table x; scoped tenant; use nope }`},
		{"omit without use", `
topology { level tenant }
object x { table x; scoped tenant; omit view }`},
		{"omit unknown verb", `
topology { level tenant }
template t { permission view = @scoped @rls maps select }
object x { table x; scoped tenant; use t; omit delete }`},
		{"duplicate template", `
topology { level tenant }
template t { permission view = @scoped @rls maps select }
template t { permission edit = @scoped @rls maps update }
object x { table x; scoped tenant; use t }`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.spec); err == nil {
				t.Fatalf("expected a parse error for %q, got nil", c.name)
			}
		})
	}
}

// A template that only carries permission lines — no table/scope/relations — is a
// pure, composable bundle; a stray non-permission statement inside it is rejected.
func TestTemplate_OnlyPermissionLines(t *testing.T) {
	const bad = `
topology { level tenant }
template t { table foo }`
	if _, err := Parse(bad); err == nil {
		t.Fatal("a template with a non-permission statement should fail to parse")
	}
}
