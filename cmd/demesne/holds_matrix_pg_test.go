package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"testing"

	demesne "github.com/foir-io/demesne"
	"github.com/jackc/pgx/v5"
)

type oracleCase struct {
	Kind   string          `json:"kind"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type oracleEntry struct {
	Cases []oracleCase `json:"cases"`
}

type resolveInput struct {
	Assignments []struct {
		Scope       []string `json:"scope"`
		RoleKey     string   `json:"roleKey"`
		Permissions []string `json:"permissions"`
	} `json:"assignments"`
	Scope []string `json:"scope"`
}

func loadResolveMatrix(t *testing.T, spec string) []oracleCase {
	t.Helper()
	path := filepath.Join("..", "..", "ts", "packages", "runtime", "test", "generated", "oracle.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var manifest map[string]oracleEntry
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse oracle manifest: %v", err)
	}
	entry, ok := manifest[spec]
	if !ok {
		t.Fatalf("oracle manifest has no %q entry", spec)
	}
	var out []oracleCase
	for _, c := range entry.Cases {
		if c.Kind == "holds.resolve" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatalf("oracle manifest %q carries no holds.resolve cases", spec)
	}
	return out
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const holdsMatrixSchema = `
create schema if not exists auth;
drop table if exists public.role_assignments;
drop table if exists public.roles;
create table public.roles (
  id text primary key, key text not null, permissions text[] not null default '{}');
create table public.role_assignments (
  id bigserial primary key, principal_kind text not null, user_id text not null,
  role_id text not null references public.roles(id),
  tenant_id text, project_id text, revoked_at timestamptz);
`

func TestHoldsMatrix_SQLAgreesWithTheOracle(t *testing.T) {
	url := os.Getenv("DEMESNE_PG_URL")
	if url == "" {
		t.Skip("set $DEMESNE_PG_URL to run the three-surface holds matrix against a live Postgres")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	src, err := os.ReadFile(filepath.Join("..", "..", "examples", "manage.demesne"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s, err := demesne.Parse(string(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := demesne.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("EmitDefiners: %v", err)
	}
	hr, err := s.HoldsResolver("")
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	vocab := hr.Vocabulary().Permissions

	if _, err := conn.Exec(ctx, holdsMatrixSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, `drop table if exists public.role_assignments, public.roles cascade;`)
	}()
	for _, d := range defs {
		if _, err := conn.Exec(ctx, d.CreateSQL()); err != nil {
			t.Fatalf("create %s: %v", d.Name, err)
		}
	}

	cases := loadResolveMatrix(t, "manage")
	checked := 0
	for i, c := range cases {
		var in resolveInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatalf("case %d input: %v", i, err)
		}
		var want []string
		if err := json.Unmarshal(c.Expect, &want); err != nil {
			t.Fatalf("case %d expect: %v", i, err)
		}
		wantSet := map[string]bool{}
		for _, p := range want {
			wantSet[p] = true
		}
		probe := append([]string(nil), vocab...)
		inVocab := map[string]bool{}
		for _, p := range vocab {
			inVocab[p] = true
		}
		for _, p := range want {
			if !inVocab[p] {
				probe = append(probe, p)
			}
		}

		if _, err := conn.Exec(ctx, `truncate public.role_assignments; delete from public.roles;`); err != nil {
			t.Fatalf("case %d reset: %v", i, err)
		}
		for j, a := range in.Assignments {
			roleID := fmt.Sprintf("r%d", j)
			if _, err := conn.Exec(ctx,
				`insert into public.roles (id, key, permissions) values ($1, $2, $3)`,
				roleID, "k"+roleID, a.Permissions); err != nil {
				t.Fatalf("case %d role: %v", i, err)
			}
			if _, err := conn.Exec(ctx,
				`insert into public.role_assignments (principal_kind, user_id, role_id, tenant_id, project_id)
				 values ('user', 'u1', $1, $2, $3)`,
				roleID, nullable(a.Scope[0]), nullable(a.Scope[1])); err != nil {
				t.Fatalf("case %d assignment: %v", i, err)
			}
		}

		rows, err := conn.Query(ctx,
			`select p, auth.member_has_perm('u1', $1, $2, p) from unnest($3::text[]) p`,
			nullable(in.Scope[0]), nullable(in.Scope[1]), probe)
		if err != nil {
			t.Fatalf("case %d query: %v", i, err)
		}
		got := map[string]bool{}
		for rows.Next() {
			var perm string
			var ok *bool
			if err := rows.Scan(&perm, &ok); err != nil {
				t.Fatalf("case %d scan: %v", i, err)
			}
			got[perm] = ok != nil && *ok
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("case %d rows: %v", i, err)
		}

		for _, p := range probe {
			checked++
			if got[p] != wantSet[p] {
				t.Errorf("SQL surface disagrees with the Go/TS oracle:\n  assignments %v\n  query scope %v\n  permission %q: SQL=%v oracle=%v",
					in.Assignments, in.Scope, p, got[p], wantSet[p])
			}
		}
	}
	t.Logf("three-surface matrix: %d cases, %d (scope x permission) cells checked against the SQL definer", len(cases), checked)
}
