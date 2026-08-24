package pgx

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestPgxScansNullTextIntoPointer(t *testing.T) {
	m := pgtype.NewMap()
	var s *string
	plan := m.PlanScan(pgtype.TextOID, pgtype.TextFormatCode, &s)
	if plan == nil {
		t.Fatal("pgx has no scan plan for **string")
	}
	if err := plan.Scan(nil, &s); err != nil {
		t.Fatalf("scan NULL: %v", err)
	}
	if s != nil {
		t.Fatalf("NULL scanned to %q, want nil", *s)
	}
	if err := plan.Scan([]byte("t1"), &s); err != nil {
		t.Fatalf("scan value: %v", err)
	}
	if s == nil || *s != "t1" {
		t.Fatalf("value scanned to %v, want t1", s)
	}
}
