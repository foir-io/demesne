package demesne_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/foir-io/demesne"
	"github.com/foir-io/demesne/examples/authz"
)

type nullScopeRows struct {
	rows [][]any
	i    int
}

func (r *nullScopeRows) Next() bool   { r.i++; return r.i <= len(r.rows) }
func (r *nullScopeRows) Close() error { return nil }
func (r *nullScopeRows) Err() error   { return nil }

func (r *nullScopeRows) Scan(dest ...any) error {
	row := r.rows[r.i-1]
	if len(dest) != len(row) {
		return fmt.Errorf("scan: %d dest for %d columns", len(dest), len(row))
	}
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			if row[i] == nil {
				return fmt.Errorf("sql: Scan error on column index %d: converting NULL to string is unsupported", i)
			}
			*p = row[i].(string)
		case **string:
			if row[i] == nil {
				*p = nil
				continue
			}
			v := row[i].(string)
			*p = &v
		default:
			return fmt.Errorf("scan: unsupported dest %T", d)
		}
	}
	return nil
}

type nullScopeQuerier struct{ rows [][]any }

func (q nullScopeQuerier) QueryRowContext(context.Context, string, ...any) demesne.Row {
	return nil
}

func (q nullScopeQuerier) QueryContext(context.Context, string, ...any) (demesne.Rows, error) {
	return &nullScopeRows{rows: q.rows}, nil
}

func TestHolds_NullScopeColumnIsAWildcard(t *testing.T) {
	q := nullScopeQuerier{rows: [][]any{{nil, nil, "tenant_owner"}}}

	held, err := authz.Holds(context.Background(), q, "u1", []string{"t1", "w1"})
	if err != nil {
		t.Fatalf("Holds: %v", err)
	}
	for _, perm := range []string{"docs:read", "docs:write", "docs:publish"} {
		if !held.Holds(perm) {
			t.Errorf("a globally scoped assignment does not confer %q; got %v", perm, held.Permissions())
		}
	}

	roles, err := authz.HoldsRoles(context.Background(), q, "u1", []string{"t1", "w1"})
	if err != nil {
		t.Fatalf("HoldsRoles: %v", err)
	}
	if !roles.Holds("tenant_owner") {
		t.Errorf("a globally scoped assignment does not confer its role; got %v", roles.Roles())
	}
}

func TestHolds_PartialNullScopeStillPinsTheLevelsItNames(t *testing.T) {
	q := nullScopeQuerier{rows: [][]any{{"t1", nil, "ws_editor"}}}

	held, err := authz.Holds(context.Background(), q, "u1", []string{"t1", "w9"})
	if err != nil {
		t.Fatalf("Holds: %v", err)
	}
	if !held.Holds("docs:write") {
		t.Errorf("a tenant-scoped assignment does not reach a workspace in that tenant; got %v", held.Permissions())
	}

	held, err = authz.Holds(context.Background(), q, "u1", []string{"t2", "w9"})
	if err != nil {
		t.Fatalf("Holds: %v", err)
	}
	if held.Holds("docs:write") {
		t.Errorf("a tenant-scoped assignment reached another tenant; got %v", held.Permissions())
	}
}

func TestEmitFramework_ScopeScanIsNullSafe(t *testing.T) {
	for _, spec := range []string{"example.demesne", "planes.demesne", "manage.demesne"} {
		t.Run(spec, func(t *testing.T) {
			src, err := os.ReadFile("examples/" + spec)
			if err != nil {
				t.Fatal(err)
			}
			s, err := demesne.Parse(string(src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			out, err := s.EmitFramework("authz")
			if err != nil {
				t.Fatalf("EmitFramework: %v", err)
			}
			if strings.Contains(out, "&a.Scope[") {
				t.Error("the generated fetch scans a scope column straight into a string, which cannot hold a SQL NULL")
			}
			if !strings.Contains(out, "if s0 != nil {") {
				t.Error("the generated fetch does not guard a NULL scope column")
			}

			ts, err := s.EmitFrameworkTS()
			if err != nil {
				t.Fatalf("EmitFrameworkTS: %v", err)
			}
			if strings.Contains(ts, "scopeCols.map((c) => String(row[c]))") {
				t.Error("the TypeScript fetch stringifies a NULL scope column into the literal \"null\"")
			}
		})
	}
}
