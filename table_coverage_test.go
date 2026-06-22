package demesne

import (
	"reflect"
	"testing"
)

const coverageSpec = `
topology { level platform virtual  level tenant parent platform  level project parent tenant }
vocabulary admin { permission c:r  preset r @ project = c:r }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
grant impersonation at tenant via edge impersonation_grants(grantee_id, tenant_id) active revoked_at
subject operator { anchor platform reach via grant impersonation identifies sub roles none }
subject member   { anchor tenant   reach descendants identifies sub roles configurable admin binds admin }
object doc {
  table  docs
  scoped tenant > project
  relation m:        member via role
  relation infolder: member via closure folder_closure(ancestor_id, descendant_id) base folders(id, parent_id) on folder_id
  permission view = m + infolder @rls maps select
}
`

func TestTableCoverage(t *testing.T) {
	s := mustSpec(t, coverageSpec)

	dbTables := []string{
		"docs",
		"role_assignments",
		"roles",
		"impersonation_grants",
		"folder_closure",
		"folders",
		"audit_log",
		"secrets",
	}
	cov := s.TableCoverage(dbTables)

	if !reflect.DeepEqual(cov.Governed, []string{"docs"}) {
		t.Errorf("Governed = %v, want [docs]", cov.Governed)
	}
	if !reflect.DeepEqual(cov.Referenced, []string{"folder_closure", "folders", "impersonation_grants", "role_assignments", "roles"}) {
		t.Errorf("Referenced = %v", cov.Referenced)
	}

	if !reflect.DeepEqual(cov.Ungoverned, []string{"audit_log", "secrets"}) {
		t.Errorf("Ungoverned = %v, want [audit_log secrets]", cov.Ungoverned)
	}
}

func TestConnectionRole(t *testing.T) {
	if got := mustSpec(t, coverageSpec).ConnectionRole(); got != "authenticated" {
		t.Errorf("default ConnectionRole = %q, want authenticated", got)
	}
	declared := mustSpec(t, "claims via \"req\" json role app_user\n"+coverageSpec)
	if got := declared.ConnectionRole(); got != "app_user" {
		t.Errorf("declared ConnectionRole = %q, want app_user", got)
	}
}
