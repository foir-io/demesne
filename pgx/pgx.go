// Package pgx adapts a pgx connection / pool / transaction to demesne.Querier, so the
// generated framework (demesne emit … framework) runs against pgx — the dominant Go
// Postgres driver — without each adopter hand-writing the identical adapter (EID-371 §3,
// from the foir stress test). The engine stays stdlib-pure; only this separate module
// links pgx.
package pgx

import (
	"context"

	demesne "github.com/eidestudio/demesne"
	"github.com/jackc/pgx/v5"
)

// PgxQuerier is the pgx surface FromPgx adapts — satisfied by *pgxpool.Pool, *pgx.Conn,
// and pgx.Tx (all expose ctx-first Query / QueryRow).
type PgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// FromPgx adapts a pgx pool / conn / tx to demesne.Querier. It bridges the two mismatches
// the foir adoption hit: pgx uses ctx-first Query/QueryRow (no `…Context` suffix), and
// pgx.Rows.Close() returns nothing while demesne.Rows needs Close() error (the close error
// surfaces via Err()).
func FromPgx(q PgxQuerier) demesne.Querier { return adapter{q} }

type adapter struct{ q PgxQuerier }

func (a adapter) QueryRowContext(ctx context.Context, query string, args ...any) demesne.Row {
	return a.q.QueryRow(ctx, query, args...) // pgx.Row already satisfies demesne.Row{Scan}
}

func (a adapter) QueryContext(ctx context.Context, query string, args ...any) (demesne.Rows, error) {
	rows, err := a.q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}

// pgxRows gives pgx.Rows a Close() that returns an error (pgx.Rows.Close() returns nothing).
type pgxRows struct{ pgx.Rows }

func (r pgxRows) Close() error {
	r.Rows.Close()
	return r.Rows.Err()
}
