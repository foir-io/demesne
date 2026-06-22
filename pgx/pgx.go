package pgx

import (
	"context"

	demesne "github.com/eidestudio/demesne"
	"github.com/jackc/pgx/v5"
)

type PgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func FromPgx(q PgxQuerier) demesne.Querier { return adapter{q} }

type adapter struct{ q PgxQuerier }

func (a adapter) QueryRowContext(ctx context.Context, query string, args ...any) demesne.Row {
	return a.q.QueryRow(ctx, query, args...)
}

func (a adapter) QueryContext(ctx context.Context, query string, args ...any) (demesne.Rows, error) {
	rows, err := a.q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}

type pgxRows struct{ pgx.Rows }

func (r pgxRows) Close() error {
	r.Rows.Close()
	return r.Rows.Err()
}
