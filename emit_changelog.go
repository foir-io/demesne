package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// Authz changelog (WS4, EID-345): an ordered, durable feed of access-changing writes —
// the zookie source (a `seq` watermark = "authorized as-of seq N") and the event stream a
// consumer Watches to react to grants/revokes (the WS5 realtime force-drop signal). It is
// OPT-IN per grant store via the `tracked` modifier, so a spec that tracks nothing emits
// none of this and its output is byte-identical.
//
// The changelog never participates in the RLS FLOOR — the floor reads only sync truth, so
// a lagging consumer of the changelog is an affordance/latency concern, never an
// authorization one (the WS4 fail-closed asymmetry; the validator enforces that no RLS
// term reads an async relation).

// ChangelogTableSQL renders the single shared changelog table (+ its cursor index). Emitted
// once when any store is tracked. `seq` is the monotonic cursor / zookie; `op` is
// 'grant' | 'revoke'; `rel` is the resource type (the store's discriminator value) or the
// store name, so a consumer can filter the feed.
func (s *Spec) changelogTable() string { return s.definerSchema() + "._authz_changelog" }

func (s *Spec) ChangelogTableSQL() string {
	t := s.changelogTable()
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %[1]s (\n"+
			"  seq bigserial PRIMARY KEY,\n"+
			"  rel text NOT NULL,\n"+
			"  resource_id text NOT NULL,\n"+
			"  principal_kind text NOT NULL,\n"+
			"  principal_id text NOT NULL,\n"+
			"  op text NOT NULL,\n"+
			"  at timestamptz NOT NULL DEFAULT now()\n"+
			");\n"+
			"CREATE INDEX IF NOT EXISTS _authz_changelog_seq_idx ON %[1]s (seq);\n"+
			"CREATE INDEX IF NOT EXISTS _authz_changelog_principal_idx ON %[1]s (principal_kind, principal_id);\n",
		t)
}

// ChangelogTrigger is the per-store append trigger: AFTER INSERT/DELETE on a tracked grant
// store, it appends a (rel, resource, principal, op) row to the changelog. `rel` is the
// row's discriminator value (the resource type) when the store is shared, else the store
// name — so one trigger captures every type the store holds.
type ChangelogTrigger struct {
	Schema       string // definer schema (the changelog + fn live here)
	TableSchema  string // the grant-store table's schema
	Changelog    string // qualified changelog table
	Table        string // the grant store
	RecordCol    string
	KindCol      string
	PrincipalCol string
	DiscrimCol   string // "" → rel is the store name constant
}

func (c ChangelogTrigger) schema() string {
	if c.Schema != "" {
		return c.Schema
	}
	return "auth"
}
func (c ChangelogTrigger) tableSchema() string {
	if c.TableSchema != "" {
		return c.TableSchema
	}
	return "public"
}
func (c ChangelogTrigger) fnName() string { return c.schema() + "." + c.Table + "_changelog" }

// relExpr is the SQL for the `rel` value from a NEW/OLD row: the discriminator column when
// shared (so the feed is filterable by resource type), else the store name as a constant.
func (c ChangelogTrigger) relExpr(rowVar string) string {
	if c.DiscrimCol != "" {
		return rowVar + "." + c.DiscrimCol
	}
	return "'" + c.Table + "'"
}

// ChangelogChannel is the LISTEN/NOTIFY channel the append trigger publishes each event
// on, so a consumer (the WS5 realtime gateway) reacts to a grant/revoke near-instantly
// instead of polling. The payload is the event as JSON
// ({rel, resource_id, principal_kind, principal_id, op}). It is a fixed contract string
// shared with the (out-of-process, non-Go) consumer.
const ChangelogChannel = "demesne_authz_changelog"

// FunctionSQL renders the append trigger function: it appends the event to the changelog
// (the durable, ordered feed / zookie source) AND pg_notify's it on ChangelogChannel (the
// low-latency push for a live consumer). A missed notify is non-fatal — the durable feed +
// the consumer's own periodic re-check backstop it.
func (c ChangelogTrigger) FunctionSQL() string {
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO %[2]s (rel, resource_id, principal_kind, principal_id, op)
      VALUES (%[3]s, NEW.%[4]s, NEW.%[5]s, NEW.%[6]s, 'grant');
    PERFORM pg_notify('%[8]s', json_build_object('rel', %[3]s, 'resource_id', NEW.%[4]s, 'principal_kind', NEW.%[5]s, 'principal_id', NEW.%[6]s, 'op', 'grant')::text);
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    INSERT INTO %[2]s (rel, resource_id, principal_kind, principal_id, op)
      VALUES (%[7]s, OLD.%[4]s, OLD.%[5]s, OLD.%[6]s, 'revoke');
    PERFORM pg_notify('%[8]s', json_build_object('rel', %[7]s, 'resource_id', OLD.%[4]s, 'principal_kind', OLD.%[5]s, 'principal_id', OLD.%[6]s, 'op', 'revoke')::text);
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;`, c.fnName(), c.Changelog, c.relExpr("NEW"), c.RecordCol, c.KindCol, c.PrincipalCol, c.relExpr("OLD"), ChangelogChannel)
}

// TriggerSQL binds the append (row-level, so each grant/revoke is a distinct event).
func (c ChangelogTrigger) TriggerSQL() string {
	name := c.Table + "_changelog"
	var b strings.Builder
	fmt.Fprintf(&b, "DROP TRIGGER IF EXISTS %s ON %s.%s;\n", name, c.tableSchema(), c.Table)
	fmt.Fprintf(&b, "CREATE TRIGGER %s AFTER INSERT OR DELETE ON %s.%s FOR EACH ROW EXECUTE FUNCTION %s();\n", name, c.tableSchema(), c.Table, c.fnName())
	return b.String()
}

// EmitChangelogTriggers returns one append trigger per DISTINCT grant store that has a
// `tracked` grant relation (deduped by table — a shared store gets a single trigger that
// captures every type via its discriminator), sorted by table. Empty when nothing is
// tracked, keeping a non-tracking spec (Foir, until it opts in) byte-identical.
func (s *Spec) EmitChangelogTriggers() []ChangelogTrigger {
	seen := map[string]bool{}
	var out []ChangelogTrigger
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGrant)
			if !ok || !g.Tracked || seen[g.Table] {
				continue
			}
			seen[g.Table] = true
			out = append(out, ChangelogTrigger{
				Schema: s.definerSchema(), TableSchema: s.tableSchema(),
				Changelog: s.changelogTable(), Table: g.Table,
				RecordCol: g.RecordCol, KindCol: g.KindCol, PrincipalCol: g.PrincipalCol,
				DiscrimCol: g.DiscrimCol,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

// ChangelogSQL renders the full changelog layer (the shared table + every append trigger),
// prefixed with a banner. Returns "" when no store is tracked.
func (s *Spec) ChangelogSQL() string {
	trigs := s.EmitChangelogTriggers()
	if len(trigs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("-- ===== Authz changelog (via grant ... tracked) =====\n")
	b.WriteString("-- An ordered (seq = zookie) feed of grant/revoke events on the tracked stores —\n")
	b.WriteString("-- the source a consumer Watches to react to access changes (WS5 realtime\n")
	b.WriteString("-- force-drop). It never feeds the RLS floor (the WS4 fail-closed asymmetry).\n\n")
	b.WriteString(s.ChangelogTableSQL())
	b.WriteString("\n")
	for _, c := range trigs {
		b.WriteString(c.FunctionSQL())
		b.WriteString("\n\n")
		b.WriteString(c.TriggerSQL())
		b.WriteString("\n")
	}
	return b.String()
}
