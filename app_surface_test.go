package demesne

import (
	"testing"
)

func TestEmitAppSurface_ProjectionAndDefaults(t *testing.T) {
	s := &Spec{Objects: []*Object{
		{Name: "record", Table: "records", PK: "id"},
		{Name: "note", Table: "notes", PK: ""}, // PK "" → the `id` convention
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

// CheckSQL must be byte-identical to PointCheckSQL — the surface's point-check is the
// SAME query the engine already delegates to RLS, so the app-level answer cannot drift
// from the enforced predicate (equal-by-delegation).
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

// A non-`id` PK must thread through every builder (de-Foirs the id assumption).
func TestAppSurface_CustomPK(t *testing.T) {
	o := AppObjectSurface{Object: "doc", Table: "docs", PK: "doc_id"}
	if got, want := o.ListResourcesSQL(),
		"SELECT doc_id FROM docs WHERE ($1::text IS NULL OR doc_id::text > $1::text) ORDER BY doc_id::text LIMIT $2"; got != want {
		t.Errorf("custom PK not threaded:\n  got:  %s\n  want: %s", got, want)
	}
}
