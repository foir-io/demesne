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

// trackedObjectSpec opts the OBJECT TABLE into the changelog (EID-350) via
// `track owner` + `track visibility`, on top of a tracked grant store.
const trackedObjectSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via owner_id where owner_kind = "customer"
  relation grantee: customer via grant racl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  track owner
  track visibility
  permission view = owner + mode access_mode = "public" + grantee:read @rls maps select
}`

func TestChangelog_TrackObjectOwnerAndVisibility(t *testing.T) {
	s, err := Parse(trackedObjectSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	objTrigs := s.EmitObjectChangelogTriggers()
	if len(objTrigs) != 1 {
		t.Fatalf("want 1 object changelog trigger, got %d", len(objTrigs))
	}
	sql := s.ChangelogSQL()
	for _, want := range []string{
		// the shared feed table is emitted once (grant store + object table share it)
		"CREATE TABLE IF NOT EXISTS auth._authz_changelog",
		// owner transfer: old owner revoke + new owner grant, keyed by principal
		"CREATE OR REPLACE FUNCTION auth.docs_obj_changelog()",
		"IF (OLD.owner_id IS DISTINCT FROM NEW.owner_id) OR (OLD.owner_kind IS DISTINCT FROM NEW.owner_kind) THEN",
		"VALUES ('doc', NEW.id, COALESCE(OLD.owner_kind, ''), OLD.owner_id, 'revoke')",
		"VALUES ('doc', NEW.id, COALESCE(NEW.owner_kind, ''), NEW.owner_id, 'grant')",
		// visibility flip: resource-scoped (empty principal)
		"IF (OLD.access_mode IS DISTINCT FROM NEW.access_mode) THEN",
		"VALUES ('doc', NEW.id, '', '', 'visibility')",
		"'op', 'visibility'",
		// fires only on the tracked columns
		"CREATE TRIGGER docs_obj_changelog AFTER UPDATE OF owner_id, owner_kind, access_mode ON public.docs FOR EACH ROW",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("ChangelogSQL missing %q:\n%s", want, sql)
		}
	}
}

// `track owner` requires a discriminated owner column; `track visibility` requires
// a mode term — both fail closed at validation (else the emitted AFTER UPDATE OF
// would carry an empty column list).
func TestChangelog_TrackOwnerNeedsDiscriminatedOwner(t *testing.T) {
	// trackedGrantSpec's owner is a plain `via customer_id` (no discriminator).
	spec := strings.Replace(trackedGrantSpec, "  permission view =", "  track owner\n  permission view =", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "track owner") {
		t.Errorf("expected `track owner` validation error (no discriminated owner), got %v", err)
	}
}

func TestChangelog_TrackVisibilityNeedsModeTerm(t *testing.T) {
	// trackedGrantSpec has no `mode <col>` term.
	spec := strings.Replace(trackedGrantSpec, "  permission view =", "  track visibility\n  permission view =", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "track visibility") {
		t.Errorf("expected `track visibility` validation error (no mode term), got %v", err)
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
