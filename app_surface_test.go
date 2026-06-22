package demesne

import (
	"strings"
	"testing"
)

const editPointCheckSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via owner_id where owner_kind = "customer"
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view = owner + grantee:read  @rls maps select
  permission edit = owner + grantee:write @rls maps update
}`

func TestAppSurface_EditPointCheck(t *testing.T) {
	s, err := Parse(editPointCheckSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	o, _ := surf.Object("doc")

	edit := o.CheckEditSQL()
	if !strings.HasPrefix(edit, "SELECT EXISTS (SELECT 1 FROM docs WHERE id = $1 AND (") {
		t.Errorf("edit point-check should inline the update predicate, got: %s", edit)
	}
	if edit == o.CheckSQL() {
		t.Error("edit point-check must differ from the read point-check (it inlines the UPDATE predicate)")
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("EmitRLS: %v", err)
	}
	var updUsing string
	for _, p := range rls.Policies {
		if p.Table == "docs" && p.Cmd == "UPDATE" {
			updUsing = p.Using
		}
	}
	if updUsing == "" {
		t.Fatal("no UPDATE policy emitted for docs")
	}
	if !strings.Contains(edit, updUsing) {
		t.Errorf("edit point-check must inline the UPDATE policy USING:\n  check: %s\n  using: %s", edit, updUsing)
	}

	s2, err := Parse(strings.Replace(editPointCheckSpec,
		"  permission edit = owner + grantee:write @rls maps update\n", "", 1))
	if err != nil {
		t.Fatalf("parse read-only: %v", err)
	}
	if err := Validate(s2); err != nil {
		t.Fatalf("validate read-only: %v", err)
	}
	surf2, _ := s2.EmitAppSurface()
	o2, _ := surf2.Object("doc")
	if o2.CheckEditSQL() != "" {
		t.Errorf("an object with no update permission must project no edit check, got: %s", o2.CheckEditSQL())
	}
}

func TestEmitAppSurface_ProjectionAndDefaults(t *testing.T) {
	s := &Spec{Objects: []*Object{
		{Name: "record", Table: "records", PK: "id"},
		{Name: "note", Table: "notes", PK: ""},
	}}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	if len(surf.Objects) != 2 {
		t.Fatalf("want 2 object surfaces, got %d", len(surf.Objects))
	}
	note, ok := surf.Object("note")
	if !ok {
		t.Fatal("note surface missing")
	}
	if note.PK != "id" {
		t.Errorf("note PK should default to the `id` convention, got %q", note.PK)
	}
	if _, ok := surf.Object("nope"); ok {
		t.Error("Object should return false for an unknown name")
	}
}

func TestEmitAppSurface_NoObjects(t *testing.T) {
	if _, err := (&Spec{}).EmitAppSurface(); err == nil {
		t.Fatal("EmitAppSurface should error when the spec declares no objects")
	}
}

func TestAppSurface_CheckEqualsPointCheck(t *testing.T) {
	s := &Spec{Objects: []*Object{{Name: "record", Table: "records", PK: "id"}}}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	o, _ := surf.Object("record")
	pc, err := s.PointCheckSQL("record")
	if err != nil {
		t.Fatalf("PointCheckSQL: %v", err)
	}
	if o.CheckSQL() != pc {
		t.Errorf("CheckSQL must equal PointCheckSQL (equal-by-delegation):\n  surface: %s\n  spec:    %s", o.CheckSQL(), pc)
	}
}

func TestAppSurface_ReadBuilders(t *testing.T) {
	o := AppObjectSurface{Object: "record", Table: "records", PK: "id"}

	if got, want := o.CheckSQL(), "SELECT EXISTS (SELECT 1 FROM records WHERE id = $1)"; got != want {
		t.Errorf("CheckSQL\n  got:  %s\n  want: %s", got, want)
	}
	if got, want := o.CheckManySQL(), "SELECT id FROM records WHERE id = ANY($1)"; got != want {
		t.Errorf("CheckManySQL\n  got:  %s\n  want: %s", got, want)
	}
	if got, want := o.ListResourcesSQL(),
		"SELECT id FROM records WHERE ($1::text IS NULL OR id::text > $1::text) ORDER BY id::text LIMIT $2"; got != want {
		t.Errorf("ListResourcesSQL\n  got:  %s\n  want: %s", got, want)
	}
}

func TestAppSurface_CustomPK(t *testing.T) {
	o := AppObjectSurface{Object: "doc", Table: "docs", PK: "doc_id"}
	if got, want := o.ListResourcesSQL(),
		"SELECT doc_id FROM docs WHERE ($1::text IS NULL OR doc_id::text > $1::text) ORDER BY doc_id::text LIMIT $2"; got != want {
		t.Errorf("custom PK not threaded:\n  got:  %s\n  want: %s", got, want)
	}
}
