package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	demesne "github.com/foir-io/demesne"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	reachRows   = "demesne_reach_rows"
	reachAuth   = "demesne_reach_auth"
	reachCaller = "demesne_reach_caller"
)

type reachTree struct {
	name                    string
	root, child, other, far string
}

func TestReachPatterns_Postgres(t *testing.T) {
	url := os.Getenv("DEMESNE_PG_URL")
	if url == "" {
		t.Skip("set $DEMESNE_PG_URL to run the reach patterns against a live Postgres")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "examples", "reach.demesne"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := demesne.Parse("tables schema \"" + reachRows + "\"\ndefiners schema \"" + reachAuth + "\"\n" + string(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := demesne.Validate(spec); err != nil {
		t.Fatal(err)
	}
	for _, tree := range []reachTree{
		{name: "ids opposite to depth", root: "z_root", child: "a_child", other: "m_other", far: "b_far"},
		{name: "ids with depth", root: "a_root", child: "z_child", other: "m_other", far: "y_far"},
	} {
		t.Run(tree.name, func(t *testing.T) { runReachPatterns(t, url, spec, tree) })
	}
}

type reachDB struct {
	t   *testing.T
	ctx context.Context
	tx  pgx.Tx
}

func (d reachDB) exec(sql string, args ...any) {
	d.t.Helper()
	if _, err := d.tx.Exec(d.ctx, sql, args...); err != nil {
		d.t.Fatalf("%v\n%s", err, sql)
	}
}

func (d reachDB) as(claims map[string]string, fn func() error) error {
	d.t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		d.t.Fatal(err)
	}
	d.exec("SAVEPOINT reach_case")
	d.exec("SELECT set_config('request.jwt.claims', $1, true)", string(raw))
	d.exec("SET LOCAL ROLE " + reachCaller)
	err = fn()
	d.exec("ROLLBACK TO SAVEPOINT reach_case")
	return err
}

func (d reachDB) visible(claims map[string]string, table string) []string {
	d.t.Helper()
	var ids []string
	if err := d.as(claims, func() error {
		rows, err := d.tx.Query(d.ctx, "SELECT id FROM "+reachRows+"."+table)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		d.t.Fatalf("select %s as %v: %v", table, claims, err)
	}
	sort.Strings(ids)
	return ids
}

func (d reachDB) updated(claims map[string]string, table, id string) int64 {
	d.t.Helper()
	var n int64
	if err := d.as(claims, func() error {
		tag, err := d.tx.Exec(d.ctx, "UPDATE "+reachRows+"."+table+" SET id = id WHERE id = $1", id)
		n = tag.RowsAffected()
		return err
	}); err != nil {
		d.t.Fatalf("update %s %s as %v: %v", table, id, claims, err)
	}
	return n
}

func (d reachDB) truth(claims map[string]string, sql string, args ...any) bool {
	d.t.Helper()
	var got *bool
	if err := d.as(claims, func() error { return d.tx.QueryRow(d.ctx, sql, args...).Scan(&got) }); err != nil {
		d.t.Fatalf("%s as %v: %v", sql, claims, err)
	}
	return got != nil && *got
}

func (d reachDB) insertRefused(claims map[string]string, sql string, args ...any) bool {
	d.t.Helper()
	err := d.as(claims, func() error {
		_, err := d.tx.Exec(d.ctx, sql, args...)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42501" {
		return true
	}
	if err != nil {
		d.t.Fatalf("%s as %v: %v", sql, claims, err)
	}
	return false
}

func wantIDs(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

func runReachPatterns(t *testing.T, url string, spec *demesne.Spec, tree reachTree) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	d := reachDB{t: t, ctx: ctx, tx: tx}
	installReachSchema(d, spec)
	seedReachRows(d, tree)

	t.Run("scope ladder decides from the session", func(t *testing.T) { checkLadder(reachDB{t, ctx, tx}, tree) })
	t.Run("selections", func(t *testing.T) { checkSelections(reachDB{t, ctx, tx}, tree) })
	t.Run("edge direction per object", func(t *testing.T) { checkDirection(reachDB{t, ctx, tx}, tree) })
	t.Run("claim lifts reads only", func(t *testing.T) { checkClaimLift(reachDB{t, ctx, tx}, tree) })
	t.Run("borrow compiles for its op", func(t *testing.T) { checkBorrow(reachDB{t, ctx, tx}, tree) })
	t.Run("admit arm and export", func(t *testing.T) { checkAdmit(reachDB{t, ctx, tx}, tree) })
}

func installReachSchema(d reachDB, spec *demesne.Spec) {
	d.t.Helper()
	d.exec("CREATE SCHEMA " + reachRows + "; CREATE SCHEMA " + reachAuth + "; CREATE ROLE " + reachCaller + " NOLOGIN")
	for _, table := range []string{
		"approvals(holder_id text, estate_id text, space_id text, folder_id text, ended_at timestamptz, expires_at timestamptz)",
		"paths(ancestor_id text, descendant_id text)",
		"assets(id text, estate_id text, space_id text, folder_id text)",
		"blueprints(id text, estate_id text, space_id text, folder_id text)",
		"ledgers(id text, estate_id text)",
		"allowances(id text, estate_id text, space_id text)",
		"spaces(id text, estate_id text)",
		"catalogs(id text, estate_id text, space_id text, folder_id text)",
		"entries(id text, estate_id text, space_id text, catalog_id text)",
		"folders(id text, estate_id text, space_id text, parent_id text)",
	} {
		d.exec("CREATE TABLE " + reachRows + "." + table)
	}
	defs, err := spec.EmitDefiners()
	if err != nil {
		d.t.Fatal(err)
	}
	d.exec("SET LOCAL check_function_bodies = off")
	for _, def := range defs {
		d.exec(def.CreateSQL())
	}
	rls, err := spec.EmitRLS()
	if err != nil || len(rls.Unsupported) > 0 {
		d.t.Fatalf("emit rls: %v %v", err, rls.Unsupported)
	}
	d.exec(rls.EnablementSQL())
	d.exec(rls.PolicySQL(reachCaller))
	d.exec("GRANT USAGE ON SCHEMA " + reachRows + ", " + reachAuth + " TO " + reachCaller)
	d.exec("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + reachRows + " TO " + reachCaller)
	d.exec("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA " + reachAuth + " TO " + reachCaller)
}

func seedReachRows(d reachDB, tr reachTree) {
	d.t.Helper()
	q := func(sql string, args ...any) { d.exec(sql, args...) }
	for _, f := range [][3]any{{tr.root, "s1", nil}, {tr.child, "s1", tr.root}, {tr.other, "s1", nil}, {tr.far, "s2", nil}} {
		q("INSERT INTO "+reachRows+".folders VALUES ($1, 'e1', $2, $3)", f[0], f[1], f[2])
		q("INSERT INTO "+reachRows+".paths VALUES ($1, $1)", f[0])
	}
	q("INSERT INTO "+reachRows+".paths VALUES ($1, $2)", tr.root, tr.child)
	for _, g := range [][4]any{{"h_estate", nil, nil, nil}, {"h_space", "s1", nil, nil}, {"h_folder", "s1", tr.root, nil}, {"h_ended", nil, nil, "yes"}} {
		ended := "NULL"
		if g[3] != nil {
			ended = "now() - interval '1 minute'"
		}
		q("INSERT INTO "+reachRows+".approvals VALUES ($1, 'e1', $2, $3, "+ended+", now() + interval '1 day')", g[0], g[1], g[2])
	}
	for _, table := range []string{"assets", "blueprints"} {
		for _, r := range [][3]any{{tr.root, "s1", tr.root}, {tr.child, "s1", tr.child}, {tr.other, "s1", tr.other}, {"shared", "s1", nil}, {tr.far, "s2", tr.far}} {
			q("INSERT INTO "+reachRows+"."+table+" VALUES ($1, 'e1', $2, $3)", r[0], r[1], r[2])
		}
	}
	q("INSERT INTO " + reachRows + ".ledgers VALUES ('l1', 'e1')")
	q("INSERT INTO " + reachRows + ".allowances VALUES ('al_s1', 'e1', 's1'), ('al_s2', 'e1', 's2')")
	q("INSERT INTO " + reachRows + ".spaces VALUES ('s1', 'e1'), ('s2', 'e1')")
	q("INSERT INTO "+reachRows+".catalogs VALUES ($1, 'e1', 's1', $1), ($2, 'e1', 's1', $2)", tr.root, tr.child)
	q("INSERT INTO "+reachRows+".entries VALUES ($1, 'e1', 's1', $1), ($2, 'e1', 's1', $2)", tr.root, tr.child)
}

func checkLadder(d reachDB, tr reachTree) {
	t := d.t
	wantIDs(t, "estate-wide helper without a folder claim", d.visible(map[string]string{"sub": "h_estate", "space_id": "s1"}, "assets"), "shared")
	wantIDs(t, "estate-wide helper standing in the root", d.visible(map[string]string{"sub": "h_estate", "space_id": "s1", "folder_id": tr.root}, "assets"), tr.root, tr.child, "shared")
	wantIDs(t, "space-pinned helper in its space", d.visible(map[string]string{"sub": "h_space", "space_id": "s1", "folder_id": tr.root}, "assets"), tr.root, tr.child, "shared")
	wantIDs(t, "space-pinned helper in another space", d.visible(map[string]string{"sub": "h_space", "space_id": "s2", "folder_id": tr.far}, "assets"))
	wantIDs(t, "folder-pinned helper in its folder", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1", "folder_id": tr.root}, "assets"), tr.root, tr.child, "shared")
	wantIDs(t, "folder-pinned helper beside its folder", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1", "folder_id": tr.other}, "assets"))
	wantIDs(t, "folder-pinned helper standing in the space", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1"}, "assets"), "shared")
	wantIDs(t, "ended approval", d.visible(map[string]string{"sub": "h_ended", "space_id": "s1", "folder_id": tr.root}, "assets"))

	probe := "SELECT " + reachAuth + ".approvals_reach($1, 'e1')"
	for _, c := range []struct {
		name   string
		claims map[string]string
		holder string
		want   bool
	}{
		{"space rung refuses a missing space claim", map[string]string{"folder_id": tr.root}, "h_space", false},
		{"space rung admits its space", map[string]string{"space_id": "s1"}, "h_space", true},
		{"folder rung admits a missing folder claim", map[string]string{"space_id": "s1"}, "h_folder", true},
		{"folder rung refuses a sibling folder", map[string]string{"space_id": "s1", "folder_id": tr.other}, "h_folder", false},
		{"unpinned approval needs no claims", map[string]string{}, "h_estate", true},
	} {
		if got := d.truth(c.claims, probe, c.holder); got != c.want {
			t.Errorf("%s: approvals_reach(%s) = %v, want %v", c.name, c.holder, got, c.want)
		}
	}
	d.exec("SAVEPOINT empty_claims")
	d.exec("SELECT set_config('request.jwt.claims', '', true)")
	var ok bool
	if err := d.tx.QueryRow(d.ctx, probe, "h_estate").Scan(&ok); err != nil || !ok {
		t.Errorf("a direct call with an empty claims setting must answer rather than raise: %v %v", ok, err)
	}
	d.exec("ROLLBACK TO SAVEPOINT empty_claims")

	for _, c := range []struct {
		sql  string
		args []any
		want bool
	}{
		{"SELECT " + reachAuth + ".approvals_reach_in_space($1, 'e1', $2)", []any{"h_space", ""}, true},
		{"SELECT " + reachAuth + ".approvals_reach_in_space($1, 'e1', $2)", []any{"h_space", "s2"}, false},
		{"SELECT " + reachAuth + ".approvals_reach_in_space($1, 'e1', $2)", []any{"h_space", "s1"}, true},
		{"SELECT " + reachAuth + ".approvals_reach_in_folder($1, 'e1', $2, $3)", []any{"h_folder", "s1", ""}, true},
		{"SELECT " + reachAuth + ".approvals_reach_in_folder($1, 'e1', $2, $3)", []any{"h_folder", "s1", tr.other}, false},
		{"SELECT " + reachAuth + ".approvals_reach_in_folder($1, 'e1', $2, $3)", []any{"h_folder", "s1", tr.root}, true},
		{"SELECT " + reachAuth + ".approvals_reach_in_space($1, 'e1', $2)", []any{"h_folder", "s2"}, false},
	} {
		if got := d.truth(map[string]string{}, c.sql, c.args...); got != c.want {
			t.Errorf("%s %v = %v, want %v", c.sql, c.args, got, c.want)
		}
	}
}

func checkSelections(d reachDB, tr reachTree) {
	t := d.t
	wantIDs(t, "unscoped: estate-wide helper", d.visible(map[string]string{"sub": "h_estate"}, "ledgers"), "l1")
	wantIDs(t, "unscoped: space-pinned helper", d.visible(map[string]string{"sub": "h_space", "space_id": "s1"}, "ledgers"))
	wantIDs(t, "unscoped: folder-pinned helper", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1", "folder_id": tr.root}, "ledgers"))
	wantIDs(t, "bound: estate-wide helper", d.visible(map[string]string{"sub": "h_estate"}, "spaces"), "s1", "s2")
	wantIDs(t, "bound: space-pinned helper in its space", d.visible(map[string]string{"sub": "h_space", "space_id": "s1"}, "spaces"), "s1")
	wantIDs(t, "bound: space-pinned helper claiming another space", d.visible(map[string]string{"sub": "h_space", "space_id": "s2"}, "spaces"))
	wantIDs(t, "bound: folder-pinned helper", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1", "folder_id": tr.root}, "spaces"), "s1")
	checkBoundColumn(d, tr)
	if n := d.updated(map[string]string{"sub": "h_space", "space_id": "s1"}, "spaces", "s1"); n != 0 {
		t.Errorf("a space-pinned helper updated its own space row (%d rows); update takes the unscoped reach", n)
	}
	if n := d.updated(map[string]string{"sub": "h_estate", "space_id": "s1"}, "spaces", "s1"); n != 1 {
		t.Errorf("an estate-wide helper could not update the space row (%d rows)", n)
	}
}

func checkDirection(d reachDB, tr reachTree) {
	t := d.t
	at := func(folder string) map[string]string {
		return map[string]string{"estate_id": "e1", "space_id": "s1", "folder_id": folder}
	}
	wantIDs(t, "rows reach down from the root", d.visible(at(tr.root), "assets"), tr.root, tr.child, "shared")
	wantIDs(t, "rows do not reach up from the child", d.visible(at(tr.child), "assets"), tr.child, "shared")
	wantIDs(t, "definitions inherit up to the child", d.visible(at(tr.child), "blueprints"), tr.root, tr.child, "shared")
	wantIDs(t, "definitions do not reach down from the root", d.visible(at(tr.root), "blueprints"), tr.root, "shared")
	wantIDs(t, "a sibling inherits nothing", d.visible(at(tr.other), "blueprints"), tr.other, "shared")
	if n := d.updated(at(tr.child), "blueprints", tr.root); n != 0 {
		t.Errorf("the child updated an inherited definition (%d rows)", n)
	}
	if n := d.updated(at(tr.root), "assets", tr.child); n != 0 {
		t.Errorf("the root updated a descendant row through a read-only reach (%d rows)", n)
	}
}

func checkClaimLift(d reachDB, tr reachTree) {
	t := d.t
	lifted := map[string]string{"estate_id": "e1", "space_id": "s1", "folder_id": tr.other, "view_mode": "all"}
	wantIDs(t, "lifted read", d.visible(lifted, "assets"), tr.root, tr.child, tr.other, "shared")
	wantIDs(t, "other claim value", d.visible(map[string]string{"estate_id": "e1", "space_id": "s1", "folder_id": tr.other, "view_mode": "some"}, "assets"), tr.other, "shared")
	wantIDs(t, "the lift stays inside the space", d.visible(map[string]string{"estate_id": "e1", "space_id": "s2", "view_mode": "all"}, "assets"), tr.far)
	if n := d.updated(lifted, "assets", tr.root); n != 0 {
		t.Errorf("the lifted claim updated a row outside its folder (%d rows)", n)
	}
	if n := d.updated(lifted, "assets", tr.other); n != 1 {
		t.Errorf("the lifted claim could not update its own folder's row (%d rows)", n)
	}
}

func checkBorrow(d reachDB, tr reachTree) {
	t := d.t
	staff := func(folder string) map[string]string {
		return map[string]string{"estate_id": "e1", "space_id": "s1", "folder_id": folder, "kind": "staff"}
	}
	wantIDs(t, "read borrow inherits up", d.visible(staff(tr.child), "entries"), tr.root, tr.child)
	wantIDs(t, "read borrow does not reach down", d.visible(staff(tr.root), "entries"), tr.root)
	if n := d.updated(staff(tr.child), "entries", tr.root); n != 0 {
		t.Errorf("write borrow admitted an inherited catalog (%d rows)", n)
	}
	if n := d.updated(staff(tr.child), "entries", tr.child); n != 1 {
		t.Errorf("write borrow refused the caller's own catalog (%d rows)", n)
	}
	robot := staff(tr.child)
	robot["kind"] = "robot"
	wantIDs(t, "borrowed authority still applies", d.visible(robot, "entries"))
}

func checkAdmit(d reachDB, tr reachTree) {
	t := d.t
	robot := func(folder string) map[string]string {
		c := map[string]string{"estate_id": "e1", "space_id": "s1", "kind": "robot"}
		if folder != "" {
			c["folder_id"] = folder
		}
		return c
	}
	staff := map[string]string{"estate_id": "e1", "space_id": "s1", "kind": "staff"}
	wantIDs(t, "robot confined to the root", d.visible(robot(tr.root), "folders"), tr.root, tr.child)
	wantIDs(t, "robot confined to the child", d.visible(robot(tr.child), "folders"), tr.child)
	wantIDs(t, "unconfined robot", d.visible(robot(""), "folders"), tr.root, tr.child, tr.other)
	wantIDs(t, "staff through the permission", d.visible(staff, "folders"), tr.root, tr.child, tr.other)
	wantIDs(t, "robot in another space", d.visible(map[string]string{"estate_id": "e1", "space_id": "s2", "kind": "robot", "folder_id": tr.root}, "folders"))

	insert := "INSERT INTO " + reachRows + ".folders VALUES ('fresh', 'e1', 's1', $1)"
	if d.insertRefused(robot(tr.root), insert, tr.root) {
		t.Error("a robot confined to the root could not create a folder beneath it")
	}
	if !d.insertRefused(robot(tr.root), insert, tr.other) {
		t.Error("a robot confined to the root created a folder under a sibling")
	}
	if !d.insertRefused(robot(tr.root), insert, nil) {
		t.Error("a confined robot created a top-level folder")
	}
	if d.insertRefused(robot(""), insert, nil) {
		t.Error("an unconfined robot could not create a top-level folder")
	}

	for _, claims := range []map[string]string{robot(tr.root), robot(tr.child), robot(""), staff, {"estate_id": "e1", "space_id": "s1", "kind": "visitor"}} {
		for _, id := range []string{tr.root, tr.child, tr.other, tr.far} {
			space := "s1"
			if id == tr.far {
				space = "s2"
			}
			exported := d.truth(claims, "SELECT "+reachAuth+".folder_write_allowed($1, 'e1', $2)", id, space)
			policy := d.updated(claims, "folders", id) == 1
			if exported != policy {
				t.Errorf("folder_write_allowed(%s) = %v but the update policy admitted it = %v, as %v", id, exported, policy, claims)
			}
		}
	}
	if !d.truth(robot(tr.root), "SELECT "+reachAuth+".folder_write_allowed($1, 'e1', 's1')", tr.child) {
		t.Error("export: a confined robot may write its descendant")
	}
	if d.truth(robot(tr.root), "SELECT "+reachAuth+".folder_write_allowed($1, 'e1', 's1')", tr.other) {
		t.Error("export: a confined robot may not write a sibling")
	}
}

func checkBoundColumn(d reachDB, tr reachTree) {
	t := d.t
	wantIDs(t, "bound column: space-pinned helper reads its own space's row", d.visible(map[string]string{"sub": "h_space", "space_id": "s1"}, "allowances"), "al_s1")
	wantIDs(t, "bound column: space-pinned helper claiming another space", d.visible(map[string]string{"sub": "h_space", "space_id": "s2"}, "allowances"))
	wantIDs(t, "bound column: folder-pinned helper", d.visible(map[string]string{"sub": "h_folder", "space_id": "s1", "folder_id": tr.root}, "allowances"), "al_s1")
	wantIDs(t, "bound column: estate-wide helper", d.visible(map[string]string{"sub": "h_estate", "space_id": "s1"}, "allowances"), "al_s1", "al_s2")
	for _, id := range []string{"al_s1", "al_s2"} {
		if n := d.updated(map[string]string{"sub": "h_space", "space_id": "s1"}, "allowances", id); n != 0 {
			t.Errorf("a space-pinned helper updated allowance %s (%d rows); writes take the unscoped reach", id, n)
		}
		if n := d.updated(map[string]string{"sub": "h_estate", "space_id": "s1"}, "allowances", id); n != 1 {
			t.Errorf("an estate-wide helper could not update allowance %s (%d rows)", id, n)
		}
	}
	insert := "INSERT INTO " + reachRows + ".allowances VALUES ('al_new', 'e1', 's1')"
	if !d.insertRefused(map[string]string{"sub": "h_space", "space_id": "s1"}, insert) {
		t.Error("a space-pinned helper inserted an allowance")
	}
	if d.insertRefused(map[string]string{"sub": "h_estate", "space_id": "s1"}, insert) {
		t.Error("an estate-wide helper could not insert an allowance")
	}
}
