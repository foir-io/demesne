package demesne

import (
	"strings"
	"testing"
)

// WS4 — spec-vs-schema binding. ValidateAgainst checks every table/column the
// spec references actually exists in the target database, WITHOUT the engine
// touching a DB (the caller supplies an introspected Schema). This is the
// "configure authz for the tables in your database" promise's verification half.
const bindSpec = `
topology { level tenant level project parent tenant }
vocabulary admin { permission a:b preset p @ project = a:b }
vocabulary cust  { permission self:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject staff { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject owner { anchor project reach self        identifies owner_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation mgr:     staff via role
  relation owner:   owner via owner_id
  relation grantee: owner via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = mgr + owner + mode visibility = "public" + grantee:read @rls maps select
}
`

// fullSchema returns a Schema that satisfies bindSpec exactly.
func fullSchema() *Schema {
	sc := NewSchema()
	for _, c := range []string{"tenant_id", "project_id", "owner_id", "visibility"} {
		sc.AddColumn("docs", c, "text", c == "visibility")
	}
	for _, c := range []string{"principal_kind", "principal_id", "role_id", "revoked_at", "tenant_id", "project_id"} {
		sc.AddColumn("role_assignments", c, "text", c == "revoked_at")
	}
	sc.AddColumn("roles", "id", "text", false)
	sc.AddColumn("roles", "key", "text", false)
	for _, c := range []string{"doc_id", "principal_kind", "principal_id", "access"} {
		sc.AddColumn("doc_acl", c, "text", false)
	}
	return sc
}

func TestValidateAgainst_BindsToMatchingSchema(t *testing.T) {
	s := mustSpec(t, bindSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("spec invalid: %v", err)
	}
	if err := s.ValidateAgainst(fullSchema()); err != nil {
		t.Fatalf("spec should bind to a matching schema, got: %v", err)
	}
}

func TestValidateAgainst_ReportsMissingTableAndColumn(t *testing.T) {
	s := mustSpec(t, bindSpec)

	// Missing a referenced column (the descriptor mode column).
	sc := fullSchema()
	delete(sc.tables["docs"], "visibility")
	err := s.ValidateAgainst(sc)
	if err == nil || !strings.Contains(err.Error(), `table "docs" has no column "visibility"`) {
		t.Errorf("missing mode column should be reported, got: %v", err)
	}

	// Missing a whole referenced table (the grant store).
	sc2 := fullSchema()
	delete(sc2.tables, "doc_acl")
	err = s.ValidateAgainst(sc2)
	if err == nil || !strings.Contains(err.Error(), `table "doc_acl"`) {
		t.Errorf("missing grant table should be reported, got: %v", err)
	}

	// Missing a role-store column.
	sc3 := fullSchema()
	delete(sc3.tables["role_assignments"], "revoked_at")
	err = s.ValidateAgainst(sc3)
	if err == nil || !strings.Contains(err.Error(), `revoked_at`) {
		t.Errorf("missing role-store column should be reported, got: %v", err)
	}
}

// A level-entity object pins its own `id` as the leaf scope column — the binding
// check must look for `id`, not `<level>_id`.
func TestValidateAgainst_LevelEntityUsesIDColumn(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		subject admin { anchor tenant reach descendants identifies sub roles none }
		object project {
		  table projects
		  level project
		  scoped tenant > project
		  relation tenant: tenant via tenant_id
		  permission view = @scoped @rls maps select
		}`)
	sc := NewSchema()
	sc.AddColumn("projects", "id", "text", false)
	sc.AddColumn("projects", "tenant_id", "text", false)
	if err := s.ValidateAgainst(sc); err != nil {
		t.Fatalf("level-entity should bind (id + tenant_id present): %v", err)
	}
	// Drop `id` → the leaf scope column is missing.
	delete(sc.tables["projects"], "id")
	if err := s.ValidateAgainst(sc); err == nil || !strings.Contains(err.Error(), `no column "id"`) {
		t.Errorf("level-entity without its id column should fail, got: %v", err)
	}
}
