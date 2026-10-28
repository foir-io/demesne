package demesne

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type fakeRows struct {
	rows   [][]any
	at     int
	closed bool
}

func (r *fakeRows) Next() bool {
	r.at++
	return r.at <= len(r.rows)
}

func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.at-1]
	if len(dest) != len(row) {
		return fmt.Errorf("scan into %d of %d columns", len(dest), len(row))
	}
	for i, d := range dest {
		switch d := d.(type) {
		case **string:
			if row[i] != nil {
				s := row[i].(string)
				*d = &s
			}
		case *string:
			*d = row[i].(string)
		case *TextArray:
			if err := d.Scan(row[i]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected destination %T", d)
		}
	}
	return nil
}

func (r *fakeRows) Close() error {
	r.closed = true
	return nil
}

func (r *fakeRows) Err() error { return nil }

type fakeQuerier struct {
	rows  *fakeRows
	query string
	args  []any
}

func (q *fakeQuerier) QueryRowContext(context.Context, string, ...any) Row { return nil }

func (q *fakeQuerier) QueryContext(_ context.Context, query string, args ...any) (Rows, error) {
	q.query, q.args = query, args
	if q.rows == nil {
		return nil, errors.New("down")
	}
	return q.rows, nil
}

func TestQueryAssignmentsReadsScopeKeyAndPermissionsInOrder(t *testing.T) {
	q := &fakeQuerier{rows: &fakeRows{rows: [][]any{
		{"t1", nil, "owner", "{docs:read,docs:write}"},
		{nil, nil, "viewer", nil},
	}}}
	got, err := QueryAssignments(context.Background(), q, "SELECT", "u1", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []RoleAssignment{
		{Scope: []string{"t1", ""}, RoleKey: "owner", Permissions: []string{"docs:read", "docs:write"}},
		{Scope: []string{"", ""}, RoleKey: "viewer", Permissions: []string{}},
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(q.args, []any{"u1"}) || !q.rows.closed {
		t.Fatalf("got %+v with %v, closed %v", got, q.args, q.rows.closed)
	}
	q = &fakeQuerier{rows: &fakeRows{rows: [][]any{{"t1", "owner"}}}}
	if got, err := QueryAssignments(context.Background(), q, "SELECT", "u1", 1, false); err != nil || got[0].RoleKey != "owner" || got[0].Scope[0] != "t1" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestQueryIDsReturnsEveryRowAndAnEmptyListForNone(t *testing.T) {
	q := &fakeQuerier{rows: &fakeRows{rows: [][]any{{"a"}, {"b"}}}}
	got, err := QueryIDs(context.Background(), q, "SELECT", []string{"a", "b", "c"})
	if err != nil || !reflect.DeepEqual(got, []string{"a", "b"}) || !q.rows.closed {
		t.Fatalf("got %v, %v", got, err)
	}
	q = &fakeQuerier{rows: &fakeRows{}}
	if got, err := QueryIDs(context.Background(), q, "SELECT"); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %#v, %v", got, err)
	}
	if _, err := QueryIDs(context.Background(), &fakeQuerier{}, "SELECT"); err == nil {
		t.Fatal("a failed query read as none")
	}
}
