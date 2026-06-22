package demesne

import (
	"context"
	"database/sql"
)

type Row interface {
	Scan(dest ...any) error
}

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) Row
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

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

func FromSQL(db SQLDB) Querier { return sqlQuerier{db} }
