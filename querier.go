package demesne

import (
	"context"
	"database/sql"
)

// The Querier surface (EID-371) — the minimal database interface the generated framework
// (EmitFramework) runs its Can / list / Holds builders against. It lives in the engine (not
// regenerated per package) for two reasons the foir adoption surfaced: the generated code
// references demesne.Querier DIRECTLY, so there is no per-package interface to collide with
// an adopter's own `Querier` type; and a single shared driver adapter serves every generated
// package. database/sql satisfies it via FromSQL; pgx via the
// github.com/eidestudio/demesne/pgx subpackage's FromPgx.
//
// Everything runs under the caller's session — the claims + RLS role already set on the
// connection/tx — so the database decides (equal by delegation).

// Row is the single-row result a point-check scans.
type Row interface {
	Scan(dest ...any) error
}

// Rows is the multi-row result a list/batch builder iterates.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// Querier is the database surface the generated builders execute against.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) Row
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

// SQLDB is the database/sql subset (a *sql.DB / *sql.Tx) FromSQL adapts to Querier.
type SQLDB interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type sqlQuerier struct{ db SQLDB }

func (q sqlQuerier) QueryRowContext(ctx context.Context, query string, args ...any) Row {
	return q.db.QueryRowContext(ctx, query, args...)
}

func (q sqlQuerier) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	return q.db.QueryContext(ctx, query, args...)
}

// FromSQL adapts a database/sql *DB or *Tx to Querier.
func FromSQL(db SQLDB) Querier { return sqlQuerier{db} }
