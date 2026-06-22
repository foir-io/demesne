package demesne

import (
	"strings"
	"testing"
)

const matGroupSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access)
  relation team:    customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = grantee:read + team @rls maps select
}`

func TestEmitMaterializedFlats_GroupRelation(t *testing.T) {
	s, err := Parse(matGroupSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	flats := s.EmitMaterializedFlats()
	if len(flats) != 1 {
		t.Fatalf("want 1 materialized flat, got %d", len(flats))
	}
	f := flats[0]
	if f.Flat != "docs_team_flat" {
		t.Errorf("flat name = %q, want docs_team_flat", f.Flat)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS auth.docs_team_flat (resource_id text NOT NULL, principal_kind text NOT NULL, principal_id text NOT NULL)",
		"CREATE INDEX IF NOT EXISTS docs_team_flat_res_idx ON auth.docs_team_flat (resource_id)",
		"CREATE INDEX IF NOT EXISTS docs_team_flat_prin_idx ON auth.docs_team_flat (principal_id)",
	} {
		if !strings.Contains(f.TableSQL(), want) {
			t.Errorf("TableSQL missing %q:\n%s", want, f.TableSQL())
		}
	}
	for _, want := range []string{

		"SECURITY DEFINER",
		"DELETE FROM auth.docs_team_flat",
		"SELECT o.id, 'customer', c.mem",
		"FROM public.docs o JOIN public.tc c ON c.grp = o.team_id",
	} {
		if !strings.Contains(f.FunctionSQL(), want) {
			t.Errorf("FunctionSQL missing %q:\n%s", want, f.FunctionSQL())
		}
	}
	for _, want := range []string{
		"AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.docs",
		"AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.tc",
		"EXECUTE FUNCTION auth.docs_team_flat_rebuild()",
	} {
		if !strings.Contains(f.TriggerSQL(), want) {
			t.Errorf("TriggerSQL missing %q:\n%s", want, f.TriggerSQL())
		}
	}

	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION auth.docs_team_flat_reconcile()",
		"RETURNS integer", "SECURITY DEFINER",
		"LOCK TABLE auth.docs_team_flat IN SHARE ROW EXCLUSIVE MODE",
		"RAISE WARNING", "self-healing",
	} {
		if !strings.Contains(f.ReconcileSQL(), want) {
			t.Errorf("ReconcileSQL missing %q:\n%s", want, f.ReconcileSQL())
		}
	}

	flatSQL := s.FlatsSQL()
	for _, want := range []string{"_reconcile()", "LOCK TABLE auth.docs_team_flat IN SHARE ROW EXCLUSIVE MODE", "OR TRUNCATE"} {
		if !strings.Contains(flatSQL, want) {
			t.Errorf("FlatsSQL missing %q", want)
		}
	}
}

func TestMaterializedFlat_RLSFlipAndMemberDefiner(t *testing.T) {
	s, err := Parse(matGroupSpec)
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
	var using string
	for _, p := range rls.Policies {
		if p.Table == "docs" && p.Cmd == "SELECT" {
			using = p.Using
		}
	}
	if using == "" {
		t.Fatal("no docs/select policy")
	}

	if !strings.Contains(using, "auth.docs_team_flat_member(docs.id,") {
		t.Errorf("docs/select USING does not call the flat member definer:\n%s", using)
	}
	if strings.Contains(using, "auth.tc_member(") {
		t.Errorf("materialized floor must not walk the closure (auth.tc_member):\n%s", using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var member *GenFn
	for i := range defs {
		if defs[i].Name == "docs_team_flat_member" {
			member = &defs[i]
		}
	}
	if member == nil {
		t.Fatal("EmitDefiners did not emit docs_team_flat_member")
	}
	sql := member.CreateSQL()
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION auth.docs_team_flat_member(p_resource text, p_principal text)",
		"RETURNS boolean", "SECURITY DEFINER",
		"SELECT EXISTS (SELECT 1 FROM auth.docs_team_flat WHERE resource_id = p_resource AND principal_id = p_principal)",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("member definer missing %q:\n%s", want, sql)
		}
	}

	flatSQL := s.FlatsSQL()
	if !strings.Contains(flatSQL, "CREATE TABLE IF NOT EXISTS auth.docs_team_flat") {
		t.Errorf("FlatsSQL missing the flat table:\n%s", flatSQL)
	}
	if strings.Contains(flatSQL, "docs_team_flat_member") {
		t.Errorf("FlatsSQL must not emit the member definer (DefinersSQL owns it):\n%s", flatSQL)
	}
	if i, j := strings.Index(flatSQL, "CREATE TABLE"), strings.Index(flatSQL, "CREATE TRIGGER"); i < 0 || j < 0 || i > j {
		t.Errorf("FlatsSQL must create the table before the trigger:\n%s", flatSQL)
	}
}

func TestMaterializedFlat_NonMaterializedStillWalks(t *testing.T) {
	spec := strings.Replace(matGroupSpec, "on team_id materialized", "on team_id", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	for _, p := range rls.Policies {
		if p.Table == "docs" && p.Cmd == "SELECT" {
			if !strings.Contains(p.Using, "auth.tc_member(team_id,") {
				t.Errorf("non-materialized floor should walk the closure:\n%s", p.Using)
			}
			if strings.Contains(p.Using, "flat_member") {
				t.Errorf("non-materialized floor must not reference a flat:\n%s", p.Using)
			}
		}
	}
	if s.FlatsSQL() != "" {
		t.Errorf("non-materialized spec must emit no flat SQL")
	}
}

const matSingleTermSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = team @rls maps select
}`

func TestMaterialized_ListFastPathEmit(t *testing.T) {
	s, err := Parse(matSingleTermSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	defs, _ := s.EmitDefiners()
	var res *GenFn
	for i := range defs {
		if defs[i].Name == "docs_team_flat_resources" {
			res = &defs[i]
		}
	}
	if res == nil {
		t.Fatal("EmitDefiners did not emit docs_team_flat_resources")
	}
	sql := res.CreateSQL()
	for _, want := range []string{
		"RETURNS SETOF text", "SECURITY DEFINER",
		"FROM public.docs o JOIN public.tc c ON c.grp = o.team_id",
		"WHERE c.mem = (current_setting(", "->> 'customer_id')",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("resources definer missing %q:\n%s", want, sql)
		}
	}

	flatSQL := s.FlatsSQL()
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS docs_team_id_l1_idx ON public.docs (team_id)",
		"CREATE INDEX IF NOT EXISTS tc_mem_l2_idx ON public.tc (mem)",
	} {
		if !strings.Contains(flatSQL, want) {
			t.Errorf("FlatsSQL missing index %q", want)
		}
	}

	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("emit app surface: %v", err)
	}
	doc, _ := surf.Object("doc")
	if doc.FlatListFn != "auth.docs_team_flat_resources" {
		t.Errorf("single-term materialized object should be fast-path eligible, FlatListFn=%q", doc.FlatListFn)
	}
	if fast := doc.ListResourcesFastSQL(); !strings.Contains(fast, "IN (SELECT auth.docs_team_flat_resources())") || !strings.Contains(fast, "LIMIT $2") {
		t.Errorf("ListResourcesFastSQL not the drive-from-flat keyset query:\n%s", fast)
	}

	su, _ := Parse(matGroupSpec)
	if err := Validate(su); err != nil {
		t.Fatalf("validate union: %v", err)
	}
	usurf, _ := su.EmitAppSurface()
	udoc, _ := usurf.Object("doc")
	if udoc.FlatListFn != "" {
		t.Errorf("union materialized SELECT must NOT be fast-path eligible, got %q", udoc.FlatListFn)
	}
	if udoc.ListResourcesFastSQL() != "" {
		t.Error("ineligible object must return empty ListResourcesFastSQL (caller uses the RLS SELECT)")
	}
}

func TestMaterialized_MultiKindRejected(t *testing.T) {
	multi := strings.Replace(matGroupSpec,
		"relation team:    customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized",
		"relation team:    customer | admin via group tc(grp, mem) edge te(mem, grp) on team_id materialized", 1)
	s, err := Parse(multi)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "must be single-kind") {
		t.Fatalf("multi-kind materialized via-group must be rejected, got: %v", err)
	}

	ok := strings.Replace(multi, " on team_id materialized", " on team_id", 1)
	so, err := Parse(ok)
	if err != nil {
		t.Fatalf("parse non-materialized: %v", err)
	}
	if err := Validate(so); err != nil {
		t.Fatalf("non-materialized multi-kind via-group should validate, got: %v", err)
	}
}

func TestEmitMaterializedFlats_NoneWhenNotMaterialized(t *testing.T) {
	spec := strings.Replace(matGroupSpec, "on team_id materialized", "on team_id", 1)
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if flats := s.EmitMaterializedFlats(); len(flats) != 0 {
		t.Errorf("non-materialized group must emit no flat, got %d", len(flats))
	}
}
