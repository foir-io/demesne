use demesne_model::SpecExt;
use demesne_runtime::{AppObjectSurface, Decision, compose_can, mint_claims_values_with_extra};
use postgres::{Client, Error, GenericClient, Transaction};
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::time::Duration;

struct T {
    name: String,
    errors: RefCell<Vec<String>>,
}

impl T {
    fn new(name: String) -> T {
        T { name, errors: RefCell::new(Vec::new()) }
    }

    fn errorf(&self, msg: impl Into<String>) {
        self.errors.borrow_mut().push(format!("{}: {}", self.name, msg.into()));
    }

    fn guarded(&self, f: impl FnOnce(&T)) {
        if let Err(p) = panic::catch_unwind(AssertUnwindSafe(|| f(self))) {
            self.errorf(format!("fatal: {}", panic_text(&*p)));
        }
    }

    fn top(name: &str, f: impl FnOnce(&T)) {
        let t = T::new(name.to_string());
        t.guarded(f);
        let errors = t.errors.take();
        assert!(errors.is_empty(), "{} failure(s):\n{}", errors.len(), errors.join("\n"));
    }
}

fn panic_text(p: &(dyn Any + Send)) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(std::string::ToString::to_string)).unwrap_or_default()
}

fn require_env(var: &str, why: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("set ${var} {why}"),
    }
}

struct Cleanup<'a> {
    url: &'a str,
    sql: &'static str,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut c) = demesne_postgres::connect(self.url) {
            let _ = c.batch_execute(self.sql);
        }
    }
}

struct Framework {
    claims_contract: Vec<String>,
    setup: Vec<String>,
    note: NoteAccess,
}

struct NoteAccess {
    can_view: String,
    list_resources: String,
    check_many: String,
}

impl Framework {
    fn new(spec: &demesne_syntax::Spec) -> Framework {
        let claims_contract = spec.claims_contract().unwrap_or_else(|e| panic!("claims contract: {e}")).clone();
        let surf = demesne_emit_sql::Sql::new(spec).emit_app_surface().unwrap_or_else(|e| panic!("EmitAppSurface: {e}"));
        let note = surf.object("note").unwrap_or_else(|| panic!("the app surface carries no note object"));
        Framework { claims_contract, setup: spec.session().session_setup_sql(true), note: NoteAccess::new(note) }
    }

    fn mint(&self, member_ref: &str, org: &str, ws: &str) -> Result<String, demesne_runtime::Error> {
        let mut values = BTreeMap::new();
        for (k, v) in [("member_ref", member_ref), ("org", org), ("ws", ws)] {
            if !v.is_empty() {
                values.insert(k.to_string(), v.to_string());
            }
        }
        mint_claims_values_with_extra(&self.claims_contract, &values, None)
    }
}

impl NoteAccess {
    fn new(o: &AppObjectSurface) -> NoteAccess {
        let list_resources = if o.flat_list_fn.is_empty() { o.list_resources_sql() } else { o.list_resources_fast_sql() };
        NoteAccess { can_view: o.check_sql(), list_resources, check_many: o.check_many_sql() }
    }

    fn can_view(&self, q: &mut impl GenericClient, id: &str) -> Result<Decision, Error> {
        let ok: bool = q.query_one(self.can_view.as_str(), &[&id])?.try_get(0)?;
        Ok(compose_can(true, ok, Decision::NotGoverned))
    }

    fn list_resources(&self, q: &mut impl GenericClient, after: Option<&str>, limit: i64) -> Result<Vec<String>, Error> {
        q.query(self.list_resources.as_str(), &[&after, &limit])?.iter().map(|r| r.try_get(0)).collect()
    }

    fn check_many(&self, q: &mut impl GenericClient, ids: &[&str]) -> Result<Vec<String>, Error> {
        q.query(self.check_many.as_str(), &[&ids])?.iter().map(|r| r.try_get(0)).collect()
    }
}

const SCHEMA: &str = "
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
";

fn session<R>(fw: &Framework, db: &mut Client, member: &str, org: &str, ws: &str, f: impl FnOnce(&mut Transaction<'_>) -> R) -> R {
    let blob = fw.mint(member, org, ws).unwrap_or_else(|e| panic!("mint: {e}"));
    let mut tx = db.transaction().unwrap_or_else(|e| panic!("begin: {e}"));
    if let Err(e) = tx.batch_execute(&fw.setup[0]) {
        panic!("set role: {e}");
    }
    if let Err(e) = tx.execute(fw.setup[1].as_str(), &[&blob]) {
        panic!("set claims: {e}");
    }
    let out = f(&mut tx);
    let _ = tx.commit();
    out
}

fn pgx_session<R>(fw: &Framework, pool: &mut Client, member: &str, org: &str, ws: &str, f: impl FnOnce(&mut Client) -> R) -> R {
    let blob = fw.mint(member, org, ws).unwrap_or_else(|e| panic!("mint: {e}"));
    if let Err(e) = pool.batch_execute("BEGIN") {
        panic!("pgx begin: {e}");
    }
    if let Err(e) = pool.batch_execute(&fw.setup[0]) {
        panic!("pgx set role: {e}");
    }
    if let Err(e) = pool.execute(fw.setup[1].as_str(), &[&blob]) {
        panic!("pgx set claims: {e}");
    }
    let out = f(pool);
    let _ = pool.batch_execute("COMMIT");
    out
}

#[test]
#[ignore = "needs SUPABASE_DB_URL; run with -- --ignored"]
fn supabase_framework_round_trip() {
    let mut url = require_env("SUPABASE_DB_URL", "(session-pooler/IPv4) to run the Supabase framework round-trip");
    if !url.contains("sslmode=") {
        url.push_str(if url.contains('?') { "&sslmode=require" } else { "?sslmode=require" });
    }
    T::top("supabase_framework_round_trip", |t| round_trip(t, &url));
}

fn round_trip(t: &T, url: &str) {
    let mut db = demesne_postgres::connect(url).unwrap_or_else(|e| panic!("open: {e}"));
    if let Err(e) = db.is_valid(Duration::from_secs(30)) {
        panic!("ping: {e}");
    }

    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/supabase.demesne")).unwrap_or_else(|e| panic!("read spec: {e}"));
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("parse: {e}"));
    let fw = Framework::new(&s);

    let _cleanup = Cleanup { url, sql: "drop table if exists public.note_acl, public.notes cascade; drop schema if exists demesne cascade;" };
    install(&mut db, &s);

    let mut can_view = |member: &str, org: &str, ws: &str, id: &str| -> Decision {
        session(&fw, &mut db, member, org, ws, |q| fw.note.can_view(q, id).unwrap_or_else(|e| panic!("CanView({id}): {e}")))
    };
    let d = can_view("m1", "o1", "w1", "n1");
    if d != Decision::Allow {
        t.errorf(format!("m1 CanView(n1) = {d}, want allow (owner)"));
    }
    let d = can_view("m1", "o1", "w1", "n2");
    if d != Decision::Allow {
        t.errorf(format!("m1 CanView(n2) = {d}, want allow (open)"));
    }
    let d = can_view("m1", "o1", "w1", "n3");
    if d != Decision::Deny {
        t.errorf(format!("m1 CanView(n3) = {d}, want deny (m2 private)"));
    }
    let d = can_view("m1", "o1", "w1", "n4");
    if d != Decision::Deny {
        t.errorf(format!("m1 CanView(n4) = {d}, want deny (cross-org, even though m1 owns it)"));
    }

    let mut visible = |member: &str, org: &str, ws: &str| -> Vec<String> {
        let mut out = session(&fw, &mut db, member, org, ws, |q| fw.note.list_resources(q, None, 100).unwrap_or_else(|e| panic!("ListResources: {e}")));
        out.sort();
        out
    };
    let got = visible("m1", "o1", "w1");
    if got != ["n1", "n2"] {
        t.errorf(format!("m1 ListResources = {got:?}, want [n1 n2]"));
    }
    let got = visible("m2", "o1", "w1");
    if got != ["n2", "n3"] {
        t.errorf(format!("m2 ListResources = {got:?}, want [n2 n3]"));
    }

    session(&fw, &mut db, "m1", "o1", "w1", |q| {
        let mut got = fw.note.check_many(q, &["n1", "n2", "n3", "n4"]).unwrap_or_else(|e| panic!("CheckMany: {e}"));
        got.sort();
        if got != ["n1", "n2"] {
            t.errorf(format!("m1 CheckMany = {got:?}, want [n1 n2]"));
        }
    });

    check_pgx_session(t, &fw, url);
}

fn install(db: &mut Client, s: &demesne_syntax::Spec) {
    let sql = demesne_emit_sql::Sql::new(s);
    let defs = sql.emit_definers().unwrap_or_else(|e| panic!("EmitDefiners: {e}"));
    let rls = sql.emit_rls().unwrap_or_else(|e| panic!("EmitRLS: {e}"));
    for stmt in [
        SCHEMA.to_string(),
        demesne_emit_sql::definers_sql(&defs),
        rls.enablement_sql(),
        rls.policy_sql("authenticated"),
        "grant execute on all functions in schema demesne to authenticated;".to_string(),
        "insert into public.notes (note_pk, org_ref, ws_ref, owner_ref, visibility) values
		 ('n1','o1','w1','m1','private'),('n2','o1','w1','m2','open'),
		 ('n3','o1','w1','m2','private'),('n4','o2','w9','m1','private');"
            .to_string(),
    ] {
        if let Err(e) = db.batch_execute(&stmt) {
            panic!("apply DDL/seed: {e}\n--- stmt ---\n{stmt}");
        }
    }
}

fn check_pgx_session(t: &T, fw: &Framework, url: &str) {
    let mut pool = demesne_postgres::connect(url).unwrap_or_else(|e| panic!("pgxpool: {e}"));
    pgx_session(fw, &mut pool, "m1", "o1", "w1", |q| {
        match fw.note.can_view(q, "n1") {
            Ok(Decision::Allow) => {}
            other => t.errorf(format!("pgx m1 CanView(n1) = {other:?}; want allow")),
        }
        match fw.note.can_view(q, "n3") {
            Ok(Decision::Deny) => {}
            other => t.errorf(format!("pgx m1 CanView(n3) = {other:?}; want deny")),
        }
        let mut ids = fw.note.list_resources(q, None, 100).unwrap_or_else(|e| panic!("pgx ListResources: {e}"));
        ids.sort();
        if ids != ["n1", "n2"] {
            t.errorf(format!("pgx m1 ListResources = {ids:?}, want [n1 n2]"));
        }
    });
}
