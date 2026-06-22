package pgx

import (
	"testing"

	demesne "github.com/eidestudio/demesne"
)

// Compile-time + smoke guard: FromPgx yields a demesne.Querier, and pgxRows satisfies
// demesne.Rows (the Close()-error wrap over pgx.Rows). No database needed — the real
// enforcement round-trip lives in the consumer (cmd/demesne) where pgx is wired to a DB.
func TestFromPgx_Interfaces(t *testing.T) {
	var _ demesne.Querier = FromPgx(nil)
	var _ demesne.Rows = pgxRows{}
}
