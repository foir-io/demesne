package demesne

import (
	"strings"
	"testing"
)

const trackedGrantSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via customer_id
  relation grantee: customer via grant racl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  permission view = owner + grantee:read @rls maps select
}`

func TestChangelog_TrackedGrantEmitsFeed(t *testing.T) {
	s, err := Parse(trackedGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	trigs := s.EmitChangelogTriggers()
	if len(trigs) != 1 {
		t.Fatalf("want 1 changelog trigger, got %d", len(trigs))
	}
	sql := s.ChangelogSQL()
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS auth._authz_changelog",
		"seq bigserial PRIMARY KEY",
		"CREATE OR REPLACE FUNCTION auth.racl_changelog()",
		"VALUES (NEW.resource_type, NEW.resource_id, NEW.principal_kind, NEW.principal_id, 'grant')",
		"VALUES (OLD.resource_type, OLD.resource_id, OLD.principal_kind, OLD.principal_id, 'revoke')",
		"CREATE TRIGGER racl_changelog AFTER INSERT OR DELETE ON public.racl FOR EACH ROW",
		"pg_notify('demesne_authz_changelog'",
		"'op', 'grant'",
		"'op', 'revoke'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("ChangelogSQL missing %q:\n%s", want, sql)
		}
	}
}

// A non-tracked grant store emits NO changelog — the modifier is opt-in, so any existing
// spec (Foir, until it opts in) is byte-identical.
func TestChangelog_UntrackedEmitsNothing(t *testing.T) {
	spec := strings.Replace(trackedGrantSpec, `"doc" tracked`, `"doc"`, 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if trigs := s.EmitChangelogTriggers(); len(trigs) != 0 {
		t.Errorf("untracked grant must emit no changelog trigger, got %d", len(trigs))
	}
	if s.ChangelogSQL() != "" {
		t.Errorf("untracked spec must emit no changelog SQL")
	}
}

// A single-kind (undiscriminated) tracked store uses the store name as `rel`.
func TestChangelog_UndiscriminatedRelIsTableName(t *testing.T) {
	spec := strings.Replace(trackedGrantSpec,
		`via grant racl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked`,
		`via grant racl(resource_id, principal_kind, principal_id, access) tracked`, 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sql := s.ChangelogSQL()
	if !strings.Contains(sql, "VALUES ('racl', NEW.resource_id") {
		t.Errorf("undiscriminated store should use the table name as rel:\n%s", sql)
	}
}
