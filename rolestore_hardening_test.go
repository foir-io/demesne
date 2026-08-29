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
  relation curator: staffer via role
  permission view = reader @rls maps select
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

func rolejoinRelation(t *testing.T, src, relation string) *Spec {
	t.Helper()
	s, err := Parse(strings.Replace(src, "rolejoin    role_id roles id key",
		"rolejoin    role_id "+relation+" id key", 1))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

func TestRoleStore_RolejoinRelationIsEmittedVerbatim(t *testing.T) {
	const relation = "roles_active"
	s := rolejoinRelation(t, hardeningSpec, relation)

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	joined := 0
	for _, d := range defs {
		if !strings.Contains(d.Body, " r ON r.id = ra.role_id") {
			continue
		}
		joined++
		if !strings.Contains(d.Body, "JOIN "+relation+" r ON r.id = ra.role_id") {
			t.Errorf("definer %s does not join the declared relation %q as a bare name:\n%s", d.Name, relation, d.Body)
		}
		for _, decorated := range []string{`"` + relation + `"`, "public." + relation} {
			if strings.Contains(d.Body, decorated) {
				t.Errorf("definer %s decorates the relation as %s; a quoted or schema-qualified name stops a view being substitutable:\n%s", d.Name, decorated, d.Body)
			}
		}
	}
	if joined == 0 {
		t.Fatal("no definer joins the rolestore, so this test asserts nothing about the relation")
	}
}

func TestRoleStore_RolejoinRelationReachesEveryRead(t *testing.T) {
	const relation = "roles_active"
	s := rolejoinRelation(t, hardeningSpec, relation)

	r, err := s.HoldsResolver("staff")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	surface, err := s.RoleAssignmentSurface("staff")
	if err != nil {
		t.Fatalf("RoleAssignmentSurface: %v", err)
	}
	for name, sql := range map[string]string{
		"AssignmentsSQL":      r.AssignmentsSQL(),
		"ListForPrincipalSQL": surface.ListForPrincipalSQL(),
	} {
		if !strings.Contains(sql, relation) {
			t.Errorf("%s does not read the declared relation %q:\n%s", name, relation, sql)
		}
		if strings.Contains(sql, " roles ") {
			t.Errorf("%s still reads `roles` though the spec names %q:\n%s", name, relation, sql)
		}
	}
}

func TestRoleStore_RolejoinRelationBindsWithoutBeingATable(t *testing.T) {
	const relation = "roles_active"
	s := rolejoinRelation(t, hardeningSpec, relation)

	sc := NewSchema()
	sc.AddColumn("docs", "id", "text", false)
	sc.AddColumn("docs", "tenant_id", "text", false)
	sc.AddColumn("docs", "project_id", "text", false)
	sc.AddColumn("role_grants", "grantee_id", "text", false)
	sc.AddColumn("role_grants", "grantee_kind", "text", false)
	sc.AddColumn("role_grants", "role_id", "text", false)
	sc.AddColumn("role_grants", "revoked_at", "timestamp with time zone", true)
	sc.AddColumn("role_grants", "tenant_id", "text", true)
	sc.AddColumn("role_grants", "project_id", "text", true)
	sc.AddColumn(relation, "id", "text", false)
	sc.AddColumn(relation, "key", "text", false)
	sc.AddColumn(relation, "perms", "ARRAY", false)

	if err := s.ValidateAgainst(sc); err != nil {
		t.Fatalf("a spec whose rolejoin names a view does not bind: %v\n"+
			"information_schema reports a view's columns the same as a table's, so the "+
			"validator must not require one", err)
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
