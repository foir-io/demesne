package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	demesne "github.com/eidestudio/demesne"
	demesnepgx "github.com/eidestudio/demesne/pgx"
	authz "github.com/eidestudio/demesne/examples/supabaseauthz"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The generated FRAMEWORK, round-tripped against a real Supabase project (EID-289 + EID-339).
// It proves the typed Go primitives enforce equal-by-delegation on Supabase's own
// role + GUC conventions: the app installs the claims itself via the generated
// SessionSetupSQL + Claims.Mint (the direct path; the access-token hook is the Supabase
// JWT-mint path, proven separately by the TS round-trip), then the generated
// authz.Note.CanView / ListResources / CheckMany run AS the non-BYPASSRLS authenticated
// role — the live RLS predicate decides.
//
// Set $SUPABASE_DB_URL to a session-pooler (IPv4) connection string to run it; skipped
// otherwise. It creates public.notes/note_acl + a `demesne` schema and drops them after.

func TestSupabaseFramework_RoundTrip(t *testing.T) {
	url := os.Getenv("SUPABASE_DB_URL")
	if url == "" {
		t.Skip("set $SUPABASE_DB_URL (session-pooler/IPv4) to run the Supabase framework round-trip")
	}
	if !strings.Contains(url, "sslmode=") {
		if strings.Contains(url, "?") {
			url += "&sslmode=require"
		} else {
			url += "?sslmode=require"
		}
	}
	ctx := context.Background()

	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Build the DDL from the spec via the engine (definers in `demesne`, RLS over public.notes).
	src, err := os.ReadFile(filepath.Join("..", "..", "examples", "supabase.demesne"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s, err := demesne.Parse(string(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("EmitDefiners: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("EmitRLS: %v", err)
	}

	const schema = `
create schema if not exists demesne;
drop table if exists public.note_acl;
drop table if exists public.notes;
create table public.notes (
  note_pk text primary key, org_ref text not null, ws_ref text not null,
  owner_ref text, visibility text not null default 'private');
create table public.note_acl (
  org_ref text not null, ws_ref text not null, note_ref text not null,
  grantee_kind text not null, grantee_ref text not null, perm text not null,
  created_at timestamptz not null default now(),
  primary key (note_ref, grantee_kind, grantee_ref, perm));
grant usage on schema demesne to authenticated;
grant select, insert, update, delete on public.notes to authenticated;
grant select, insert, update, delete on public.note_acl to authenticated;
`
	// A defer (registered AFTER `defer db.Close()`) runs BEFORE the pool closes — LIFO —
	// so the drop executes on a live connection. (t.Cleanup would fire after db.Close.)
	defer func() {
		_, _ = db.ExecContext(ctx, `drop table if exists public.note_acl, public.notes cascade; drop schema if exists demesne cascade;`)
	}()

	// Apply (as the connection role; postgres is BYPASSRLS on Supabase, so DDL + seed work).
	for _, stmt := range []string{
		schema,
		demesne.DefinersSQL(defs),
		rls.EnablementSQL(),
		rls.PolicySQL("authenticated"),
		`grant execute on all functions in schema demesne to authenticated;`,
		`insert into public.notes (note_pk, org_ref, ws_ref, owner_ref, visibility) values
		 ('n1','o1','w1','m1','private'),('n2','o1','w1','m2','open'),
		 ('n3','o1','w1','m2','private'),('n4','o2','w9','m1','private');`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply DDL/seed: %v\n--- stmt ---\n%s", err, stmt)
		}
	}

	// session runs fn under a member's session (the generated WithRLS envelope) on one tx.
	session := func(member, org, ws string, fn func(q demesne.Querier)) {
		blob, err := authz.Claims{Org: org, Ws: ws, MemberRef: member}.Mint()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		setup := authz.SessionSetupSQL(true)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Commit() }()
		if _, err := tx.ExecContext(ctx, setup[0]); err != nil { // SET LOCAL ROLE authenticated
			t.Fatalf("set role: %v", err)
		}
		if _, err := tx.ExecContext(ctx, setup[1], blob); err != nil { // install claims
			t.Fatalf("set claims: %v", err)
		}
		fn(demesne.FromSQL(tx))
	}

	canView := func(member, org, ws, id string) authz.Decision {
		var d authz.Decision
		session(member, org, ws, func(q demesne.Querier) {
			got, err := authz.Note.CanView(ctx, q, id)
			if err != nil {
				t.Fatalf("CanView(%s): %v", id, err)
			}
			d = got
		})
		return d
	}
	visible := func(member, org, ws string) []string {
		var out []string
		session(member, org, ws, func(q demesne.Querier) {
			ids, err := authz.Note.ListResources(ctx, q, nil, 100)
			if err != nil {
				t.Fatalf("ListResources: %v", err)
			}
			out = ids
		})
		sort.Strings(out)
		return out
	}

	// CanView: the generated typed check enforces under live RLS.
	if d := canView("m1", "o1", "w1", "n1"); d != authz.Allow {
		t.Errorf("m1 CanView(n1) = %v, want allow (owner)", d)
	}
	if d := canView("m1", "o1", "w1", "n2"); d != authz.Allow {
		t.Errorf("m1 CanView(n2) = %v, want allow (open)", d)
	}
	if d := canView("m1", "o1", "w1", "n3"); d != authz.Deny {
		t.Errorf("m1 CanView(n3) = %v, want deny (m2 private)", d)
	}
	if d := canView("m1", "o1", "w1", "n4"); d != authz.Deny {
		t.Errorf("m1 CanView(n4) = %v, want deny (cross-org, even though m1 owns it)", d)
	}

	// ListResources returns exactly the visible set.
	if got := visible("m1", "o1", "w1"); !eqSlice(got, []string{"n1", "n2"}) {
		t.Errorf("m1 ListResources = %v, want [n1 n2]", got)
	}
	if got := visible("m2", "o1", "w1"); !eqSlice(got, []string{"n2", "n3"}) {
		t.Errorf("m2 ListResources = %v, want [n2 n3]", got)
	}

	// CheckMany returns the visible subset of a batch.
	session("m1", "o1", "w1", func(q demesne.Querier) {
		got, err := authz.Note.CheckMany(ctx, q, []string{"n1", "n2", "n3", "n4"})
		if err != nil {
			t.Fatalf("CheckMany: %v", err)
		}
		sort.Strings(got)
		if !eqSlice(got, []string{"n1", "n2"}) {
			t.Errorf("m1 CheckMany = %v, want [n1 n2]", got)
		}
	})

	// pgx-native pass: the SAME generated surface, driven through the demesne/pgx adapter
	// (FromPgx) over a pgxpool tx — the dominant-driver path and the #1 adoption friction
	// the foir stress test flagged (EID-371 §3). Exercises the Close()-error wrap on real
	// pgx.Rows (ListResources) and pgx.Row scanning (CanView).
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()
	pgxSession := func(member, org, ws string, fn func(q demesne.Querier)) {
		blob, err := authz.Claims{Org: org, Ws: ws, MemberRef: member}.Mint()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		setup := authz.SessionSetupSQL(true)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("pgx begin: %v", err)
		}
		defer func() { _ = tx.Commit(ctx) }()
		if _, err := tx.Exec(ctx, setup[0]); err != nil {
			t.Fatalf("pgx set role: %v", err)
		}
		if _, err := tx.Exec(ctx, setup[1], blob); err != nil {
			t.Fatalf("pgx set claims: %v", err)
		}
		fn(demesnepgx.FromPgx(tx))
	}
	pgxSession("m1", "o1", "w1", func(q demesne.Querier) {
		if d, err := authz.Note.CanView(ctx, q, "n1"); err != nil || d != authz.Allow {
			t.Errorf("pgx m1 CanView(n1) = %v, %v; want allow", d, err)
		}
		if d, err := authz.Note.CanView(ctx, q, "n3"); err != nil || d != authz.Deny {
			t.Errorf("pgx m1 CanView(n3) = %v, %v; want deny", d, err)
		}
		ids, err := authz.Note.ListResources(ctx, q, nil, 100)
		if err != nil {
			t.Fatalf("pgx ListResources: %v", err)
		}
		sort.Strings(ids)
		if !eqSlice(ids, []string{"n1", "n2"}) {
			t.Errorf("pgx m1 ListResources = %v, want [n1 n2]", ids)
		}
	})
}

func eqSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
