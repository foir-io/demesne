package demesne

import (
	"context"
	"database/sql"
)

// Row is one row a query returns.
type Row interface {
	Scan(dest ...any) error
}

// Rows is the rows a query returns.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// Querier is what generated checks run their SQL through. FromSQL adapts a *sql.DB, *sql.Tx or *sql.Conn. The checks
// pass a list of ids as a []string, so the driver must encode one as a Postgres text[], as pgx does.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) Row
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

// SQLDB is the part of *sql.DB, *sql.Tx and *sql.Conn that FromSQL needs.
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

// FromSQL adapts db to a Querier.
func FromSQL(db SQLDB) Querier {
	return sqlQuerier{db}
}
