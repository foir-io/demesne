package demesne

import (
	"strings"
	"testing"
)

const hardeningSpec = `
topology { level tenant level project parent tenant }

vocabulary staff {
  permission docs:read
  permission docs:write
  permission docs:manage
  preset viewer  @ project = docs:read
  preset editor  @ project = viewer + docs:write
  preset steward @ project = editor + docs:manage
  preset admin   @ project = *
  rank admin > steward > editor > viewer
}

rolestore staff {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions perms
}

subject staffer { anchor tenant reach descendants identifies sub roles configurable staff binds admin }

object doc {
  table docs
  scoped tenant > project
  relation reader:  staffer via role
  relation curator: staffer via role(rank >= steward)
  permission view = reader  @rls maps select
  permission edit = curator @rls maps update
  permission publish = @holds(docs:manage) @rls maps delete
}
`

func hardeningDefiners(t *testing.T, src string) []GenFn {
	t.Helper()
	s, err := Parse(src)
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
	return defs
}

func assertNoDegenerateSQL(t *testing.T, defs []GenFn) {
	t.Helper()
	for _, d := range defs {
		for _, bad := range []string{"ra. ", "AND  AND", "IN ()", "= ''", "ANY(r.)"} {
			if strings.Contains(d.Body, bad) {
				t.Errorf("definer %s emits degenerate SQL %q:\n%s", d.Name, bad, d.Body)
			}
		}
	}
}

func TestRoleStore_OmittedKindEmitsValidSQL(t *testing.T) {
	src := strings.Replace(hardeningSpec, `  kind        grantee_kind = "staff"`+"\n", "", 1)
	defs := hardeningDefiners(t, src)
	assertNoDegenerateSQL(t, defs)
	for _, d := range defs {
		if strings.Contains(d.Body, "grantee_kind") {
			t.Errorf("definer %s references the kind column though none is declared:\n%s", d.Name, d.Body)
		}
	}
}

func TestRoleStore_OmittedRevokedEmitsValidSQL(t *testing.T) {
	src := strings.Replace(hardeningSpec, "  revoked     revoked_at\n", "", 1)
	defs := hardeningDefiners(t, src)
	assertNoDegenerateSQL(t, defs)
	for _, d := range defs {
		if strings.Contains(d.Body, "revoked_at") {
			t.Errorf("definer %s references the revoked column though none is declared:\n%s", d.Name, d.Body)
		}
	}
}

func TestRoleStore_HoldsDefinerSurvivesOmittedOptionalColumns(t *testing.T) {
	src := strings.Replace(hardeningSpec, `  kind        grantee_kind = "staff"`+"\n", "", 1)
	src = strings.Replace(src, "  revoked     revoked_at\n", "", 1)
	defs := hardeningDefiners(t, src)
	var holds *GenFn
	for i := range defs {
		if strings.HasSuffix(defs[i].Name, "_has_perm") {
			holds = &defs[i]
		}
	}
	if holds == nil {
		t.Fatal("no @holds definer emitted")
	}
	assertNoDegenerateSQL(t, []GenFn{*holds})
	if !strings.Contains(holds.Body, "p_perm = ANY(r.perms)") {
		t.Errorf("@holds definer lost its permissions test:\n%s", holds.Body)
	}
}

func TestRoleStore_AssignmentsSQLSkipsOmittedColumns(t *testing.T) {
	src := strings.Replace(hardeningSpec, `  kind        grantee_kind = "staff"`+"\n", "", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r, err := s.HoldsResolver("staff")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	sql := r.AssignmentsSQL()
	for _, bad := range []string{"ra. ", "= ''", "AND  AND"} {
		if strings.Contains(sql, bad) {
			t.Errorf("AssignmentsSQL emits degenerate SQL %q:\n%s", bad, sql)
		}
	}
	if !strings.Contains(sql, "ra.grantee_id = $1") {
		t.Errorf("AssignmentsSQL lost its subject predicate:\n%s", sql)
	}
}

func TestViaRole_RankAtVirtualAnchorRejected(t *testing.T) {
	src := `
topology { level archive virtual }

vocabulary staff {
  permission items:read
  permission items:manage
  preset viewer  @ archive = items:read
  preset steward @ archive = *
  rank steward > viewer
}

rolestore staff {
  assignments memberships
  kind        member_kind = "contributor"
  subject     contributor_id
  rolejoin    group_id groups id slug
  revoked     revoked_at
}

subject staff { anchor archive reach descendants identifies sub roles configurable staff binds admin }

object item {
  table items
  level  archive
  scoped archive
  relation curator: staff via role(rank >= steward)
  permission edit = curator @rls maps update
}
`
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil {
		t.Fatal("expected validate to reject a rank filter at a virtual anchor")
	}
	for _, want := range []string{"never consulted", "non-virtual level carrying a scope column"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection must state the real cause and the fix, missing %q in: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "cannot carry a rank filter") {
		t.Errorf("the threshold does compile correctly; the message must not claim otherwise: %v", err)
	}
}

func TestViaRole_RankWithoutRankOrderingRejected(t *testing.T) {
	src := strings.Replace(hardeningSpec, "  rank admin > steward > editor > viewer\n", "", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil {
		t.Fatal("expected validate to reject `rank >=` with no rank ordering declared")
	}
	if !strings.Contains(err.Error(), "would admit every preset") {
		t.Errorf("rejection must name the widening, got: %v", err)
	}
}

func TestViaRole_EmptyPresetSetRejected(t *testing.T) {
	src := strings.Replace(hardeningSpec, "@ project", "@ tenant", 4)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil {
		t.Fatal("expected validate to reject a via-role gate with no preset at the object's level")
	}
	if !strings.Contains(err.Error(), "empty key set") {
		t.Errorf("rejection must name the empty key set, got: %v", err)
	}
}

func TestAtOrAbove_UnknownThresholdFailsClosed(t *testing.T) {
	got := atOrAbove([]string{"admin", "viewer"}, "steward", map[string]int{"admin": 0, "viewer": 1})
	if len(got) != 0 {
		t.Errorf("an unresolvable rank threshold must fail closed, got %v", got)
	}
}

func TestViaRole_RankFilterStillNarrowsWhenValid(t *testing.T) {
	defs := hardeningDefiners(t, hardeningSpec)
	var ranked *GenFn
	for i := range defs {
		if defs[i].Name == "is_steward" {
			ranked = &defs[i]
		}
	}
	if ranked == nil {
		t.Fatal("no is_steward definer emitted")
	}
	if !strings.Contains(ranked.Body, "IN ('admin', 'steward')") {
		t.Errorf("rank >= steward must admit exactly admin and steward:\n%s", ranked.Body)
	}
	assertNoDegenerateSQL(t, defs)
}
