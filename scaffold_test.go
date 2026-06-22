package demesne

import (
	"strings"
	"testing"
)

func schemaForScaffold() *Schema {
	sc := NewSchema()
	sc.AddColumn("tenants", "id", "text", false)
	sc.AddColumn("projects", "id", "text", false)
	sc.AddColumn("projects", "tenant_id", "text", false)
	sc.AddForeignKey("projects", "tenant_id", "tenants", "id")
	for _, leaf := range []string{"records", "files", "models"} {
		sc.AddColumn(leaf, "id", "text", false)
		sc.AddColumn(leaf, "tenant_id", "text", false)
		sc.AddColumn(leaf, "project_id", "text", false)
		sc.AddForeignKey(leaf, "tenant_id", "tenants", "id")
		sc.AddForeignKey(leaf, "project_id", "projects", "id")
	}
	return sc
}

func TestScaffold_InfersTopologyAndScopedObjects(t *testing.T) {
	sc := schemaForScaffold()
	src, err := sc.Scaffold(ScaffoldOptions{})
	if err != nil {
		t.Fatalf("scaffold: %v", err)
	}

	for _, want := range []string{
		"level tenant\n",
		"level project parent tenant\n",
		"object records {",
		"scoped tenant > project",
		"permission view   = @scoped @rls maps select",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("scaffold output missing %q:\n%s", want, src)
		}
	}

	if strings.Contains(src, "object tenants {") || strings.Contains(src, "object projects {") {
		t.Errorf("level tables should not be emitted as scoped objects:\n%s", src)
	}

	s, err := Parse(src)
	if err != nil {
		t.Fatalf("scaffolded spec does not parse: %v\n%s", err, src)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("scaffolded spec does not validate: %v\n%s", err, src)
	}

	if err := s.ValidateAgainst(sc); err != nil {
		t.Fatalf("scaffolded spec does not bind to its own schema: %v", err)
	}
}

func TestScaffold_NoContainersIsAnError(t *testing.T) {
	sc := NewSchema()
	sc.AddColumn("widgets", "id", "text", false)
	if _, err := sc.Scaffold(ScaffoldOptions{}); err == nil || !strings.Contains(err.Error(), "no tenancy container") {
		t.Errorf("scaffold with no FKs should report no container, got: %v", err)
	}
}
