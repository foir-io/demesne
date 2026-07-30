package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Scope    []string `json:"scope"`
	Resolver string   `json:"resolver"`

	expect []string
}

func loadResolveMatrix(t *testing.T, spec, resolver string) []resolveInput {
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
	var out []resolveInput
	for i, c := range entry.Cases {
		if c.Kind != "holds.resolve" {
			continue
		}
		var in resolveInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatalf("case %d input: %v", i, err)
		}
		if in.Resolver != resolver {
			continue
		}
		if err := json.Unmarshal(c.Expect, &in.expect); err != nil {
			t.Fatalf("case %d expect: %v", i, err)
		}
		out = append(out, in)
	}
	if len(out) == 0 {
		t.Fatalf("oracle manifest %q carries no holds.resolve cases for resolver %q", spec, resolver)
	}
	return out
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func placeholders(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("$%d", i+1)
	}
	return out
}

func matrixSchema(hr *demesne.HoldsResolver) string {
	roleCols := []string{hr.RolesID + " text primary key", hr.KeyCol + " text not null"}
	if hr.PermsCol != "" {
		roleCols = append(roleCols, hr.PermsCol+" text[] not null default '{}'")
	}
	asgCols := []string{
		"id bigserial primary key",
		hr.SubjectCol + " text not null",
		fmt.Sprintf("%s text not null references public.%s(%s)", hr.RoleCol, hr.RolesTable, hr.RolesID),
	}
	if hr.KindCol != "" {
		asgCols = append(asgCols, hr.KindCol+" text not null")
	}
	for _, c := range hr.ScopeCols {
		asgCols = append(asgCols, c+" text")
	}
	if hr.RevokedCol != "" {
		asgCols = append(asgCols, hr.RevokedCol+" timestamptz")
	}
	return fmt.Sprintf(`create schema if not exists auth;
drop table if exists public.%s;
drop table if exists public.%s;
create table public.%s (%s);
create table public.%s (%s);`,
		hr.Assignments, hr.RolesTable,
		hr.RolesTable, strings.Join(roleCols, ", "),
		hr.Assignments, strings.Join(asgCols, ", "))
}

func insertAssignment(ctx context.Context, conn *pgx.Conn, hr *demesne.HoldsResolver, roleID string, scope []string) error {
	cols := []string{hr.SubjectCol, hr.RoleCol}
	vals := []any{"u1", roleID}
	if hr.KindCol != "" {
		cols = append(cols, hr.KindCol)
		vals = append(vals, hr.KindVal)
	}
	for i, c := range hr.ScopeCols {
		cols = append(cols, c)
		if i < len(scope) {
			vals = append(vals, nullable(scope[i]))
		} else {
			vals = append(vals, nil)
		}
	}
	sql := fmt.Sprintf("insert into public.%s (%s) values (%s)",
		hr.Assignments, strings.Join(cols, ", "), strings.Join(placeholders(len(vals)), ", "))
	_, err := conn.Exec(ctx, sql, vals...)
	return err
}

type matrixTarget struct {
	name      string
	spec      string
	oracleKey string
	rolestore string
	resolver  string
	definer   string
}

func TestHoldsMatrix_SQLAgreesWithTheOracle(t *testing.T) {
	url := os.Getenv("DEMESNE_PG_URL")
	if url == "" {
		t.Skip("set $DEMESNE_PG_URL to run the three-surface holds matrix against a live Postgres")
	}
	targets := []matrixTarget{
		{"manage", "manage.demesne", "manage", "", "", "member_has_perm"},
		{"planes/admin", "planes.demesne", "planes", "admin", "", "operator_has_perm"},
		{"planes/platform", "planes.demesne", "planes", "platform", "platform", "platform_has_perm"},
	}
	for _, tgt := range targets {
		t.Run(tgt.name, func(t *testing.T) { runHoldsMatrix(t, url, tgt) })
	}
}

func runHoldsMatrix(t *testing.T, url string, tgt matrixTarget) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	src, err := os.ReadFile(filepath.Join("..", "..", "examples", tgt.spec))
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
	hr, err := s.HoldsResolver(tgt.rolestore)
	if err != nil {
		t.Fatalf("HoldsResolver: %v", err)
	}
	vocab := hr.Vocabulary().Permissions
	scopeArgs := len(hr.SelectedScopeCols())

	found := false
	for _, d := range defs {
		if d.Name != tgt.definer {
			continue
		}
		found = true
		if got := strings.Count(d.Sig, ",") + 1; got != scopeArgs+2 {
			t.Fatalf("%s takes %d arguments, want %d (subject + %d scope + perm): %q", d.Name, got, scopeArgs+2, scopeArgs, d.Sig)
		}
	}
	if !found {
		t.Fatalf("spec emits no definer %q", tgt.definer)
	}

	if _, err := conn.Exec(ctx, matrixSchema(hr)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, fmt.Sprintf(`drop table if exists public.%s, public.%s cascade;`, hr.Assignments, hr.RolesTable))
	}()
	for _, d := range defs {
		if _, err := conn.Exec(ctx, d.CreateSQL()); err != nil {
			t.Fatalf("create %s: %v", d.Name, err)
		}
	}

	query := fmt.Sprintf("select p, auth.%s(%s, p) from unnest($%d::text[]) p",
		tgt.definer, strings.Join(placeholders(scopeArgs+1), ", "), scopeArgs+2)

	cases := loadResolveMatrix(t, tgt.oracleKey, tgt.resolver)
	checked := 0
	for i, in := range cases {
		wantSet := map[string]bool{}
		for _, p := range in.expect {
			wantSet[p] = true
		}
		probe := append([]string(nil), vocab...)
		inVocab := map[string]bool{}
		for _, p := range vocab {
			inVocab[p] = true
		}
		for _, p := range in.expect {
			if !inVocab[p] {
				probe = append(probe, p)
			}
		}

		if _, err := conn.Exec(ctx, fmt.Sprintf(`truncate public.%s; delete from public.%s;`, hr.Assignments, hr.RolesTable)); err != nil {
			t.Fatalf("case %d reset: %v", i, err)
		}
		insert := fmt.Sprintf("insert into public.%s (%s, %s, %s) values ($1, $2, $3)",
			hr.RolesTable, hr.RolesID, hr.KeyCol, hr.PermsCol)
		for j, a := range in.Assignments {
			roleID := fmt.Sprintf("r%d", j)
			if _, err := conn.Exec(ctx, insert, roleID, "k"+roleID, a.Permissions); err != nil {
				t.Fatalf("case %d role: %v", i, err)
			}
			if err := insertAssignment(ctx, conn, hr, roleID, a.Scope); err != nil {
				t.Fatalf("case %d assignment: %v", i, err)
			}
		}

		args := []any{"u1"}
		for k := 0; k < scopeArgs; k++ {
			if k < len(in.Scope) {
				args = append(args, nullable(in.Scope[k]))
			} else {
				args = append(args, nil)
			}
		}
		args = append(args, probe)

		rows, err := conn.Query(ctx, query, args...)
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
	t.Logf("three-surface matrix: %d cases, %d (scope x permission) cells checked against auth.%s", len(cases), checked, tgt.definer)
}
