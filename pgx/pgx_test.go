package pgx

import (
	"testing"

	demesne "github.com/foir-io/demesne"
)

func TestFromPgx_Interfaces(t *testing.T) {
	var _ demesne.Querier = FromPgx(nil)
	var _ demesne.Rows = pgxRows{}
}
