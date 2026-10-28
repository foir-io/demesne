use demesne_gocompat::json::{self, Value};
use demesne_model::SurfaceExt;
use demesne_runtime::HoldsResolver;
use postgres::types::ToSql;
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};

type Arg<'a> = &'a (dyn ToSql + Sync);

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

    #[expect(clippy::print_stderr, reason = "the harness logs its cell counts as Go's t.Logf does, so the two runs can be compared")]
    fn logf(&self, msg: impl Into<String>) {
        eprintln!("{}: {}", self.name, msg.into());
    }

    fn guarded(&self, f: impl FnOnce(&T)) {
        if let Err(p) = panic::catch_unwind(AssertUnwindSafe(|| f(self))) {
            self.errorf(format!("fatal: {}", panic_text(&*p)));
        }
    }

    fn run(&self, name: &str, f: impl FnOnce(&T)) {
        let sub = T::new(format!("{}/{}", self.name, name));
        sub.guarded(f);
        self.errors.borrow_mut().extend(sub.errors.take());
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
    sql: String,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut c) = demesne_postgres::connect(self.url) {
            let _ = c.batch_execute(&self.sql);
        }
    }
}

struct Assignment {
    scope: Option<Vec<String>>,
    role_key: String,
    permissions: Option<Vec<String>>,
}

fn show(assignments: &[Assignment]) -> String {
    let parts: Vec<String> = assignments.iter().map(|a| format!("{{{:?} {:?} {:?}}}", a.scope, a.role_key, a.permissions)).collect();
    format!("[{}]", parts.join(" "))
}

struct ResolveInput {
    assignments: Vec<Assignment>,
    scope: Option<Vec<String>>,
    expect: Option<Vec<String>>,
}

fn strings(v: Option<&Value>, what: &str) -> Option<Vec<String>> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::Array(xs)) => Some(xs.iter().map(|x| x.as_str().map_or_else(|| panic!("{what}: element {x:?} is not a string"), String::from)).collect()),
        Some(other) => panic!("{what}: {other:?} is not an array of strings"),
    }
}

fn text(v: Option<&Value>, what: &str) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::Str(s)) => s.clone(),
        Some(other) => panic!("{what}: {other:?} is not a string"),
    }
}

fn load_resolve_matrix(spec: &str, resolver: &str) -> Vec<ResolveInput> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ts/packages/runtime/test/generated/oracle.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let manifest = json::parse(&raw).unwrap_or_else(|e| panic!("parse oracle manifest: {e}"));
    let Some(entry) = manifest.get(spec) else {
        panic!("oracle manifest has no {spec:?} entry");
    };
    let cases = match entry.get("cases") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(cs)) => cs.as_slice(),
        Some(other) => panic!("parse oracle manifest: cases {other:?} is not an array"),
    };
    let mut out = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        if text(c.get("kind"), &format!("case {i} kind")) != "holds.resolve" {
            continue;
        }
        let input = c.get("input").unwrap_or(&Value::Null);
        if text(input.get("resolver"), &format!("case {i} input")) != resolver {
            continue;
        }
        let assignments = match input.get("assignments") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(xs)) => xs
                .iter()
                .map(|a| Assignment {
                    scope: strings(a.get("scope"), &format!("case {i} input")),
                    role_key: text(a.get("roleKey"), &format!("case {i} input")),
                    permissions: strings(a.get("permissions"), &format!("case {i} input")),
                })
                .collect(),
            Some(other) => panic!("case {i} input: assignments {other:?} is not an array"),
        };
        out.push(ResolveInput {
            assignments,
            scope: strings(input.get("scope"), &format!("case {i} input")),
            expect: strings(c.get("expect"), &format!("case {i} expect")),
        });
    }
    assert!(!out.is_empty(), "oracle manifest {spec:?} carries no holds.resolve cases for resolver {resolver:?}");
    out
}

fn nullable(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}

fn placeholders(n: usize) -> Vec<String> {
    (1..=n).map(|i| format!("${i}")).collect()
}

fn matrix_schema(hr: &HoldsResolver) -> String {
    let mut role_cols = vec![format!("{} text primary key", hr.roles_id), format!("{} text not null", hr.key_col)];
    if !hr.perms_col.is_empty() {
        role_cols.push(format!("{} text[] not null default '{{}}'", hr.perms_col));
    }
    let mut asg_cols = vec![
        "id bigserial primary key".to_string(),
        format!("{} text not null", hr.subject_col),
        format!("{} text not null references public.{}({})", hr.role_col, hr.roles_table, hr.roles_id),
    ];
    if !hr.kind_col.is_empty() {
        asg_cols.push(format!("{} text not null", hr.kind_col));
    }
    for c in hr.scope_cols.iter() {
        asg_cols.push(format!("{c} text"));
    }
    if !hr.revoked_col.is_empty() {
        asg_cols.push(format!("{} timestamptz", hr.revoked_col));
    }
    format!(
        "create schema if not exists auth;\ndrop table if exists public.{};\ndrop table if exists public.{};\ncreate table public.{} ({});\ncreate table public.{} ({});",
        hr.assignments,
        hr.roles_table,
        hr.roles_table,
        role_cols.join(", "),
        hr.assignments,
        asg_cols.join(", ")
    )
}

fn insert_assignment(conn: &mut postgres::Client, hr: &HoldsResolver, role_id: &str, scope: &[String]) -> Result<u64, postgres::Error> {
    let mut cols = vec![hr.subject_col.to_string(), hr.role_col.to_string()];
    let mut vals: Vec<Option<String>> = vec![Some("u1".into()), Some(role_id.into())];
    if !hr.kind_col.is_empty() {
        cols.push(hr.kind_col.to_string());
        vals.push(Some(hr.kind_val.to_string()));
    }
    for (i, c) in hr.scope_cols.iter().enumerate() {
        cols.push(c.to_string());
        vals.push(scope.get(i).and_then(|s| nullable(s)));
    }
    let sql = format!("insert into public.{} ({}) values ({})", hr.assignments, cols.join(", "), placeholders(vals.len()).join(", "));
    let params: Vec<Arg> = vals.iter().map(|v| v as Arg).collect();
    conn.execute(&sql, &params)
}

struct MatrixTarget {
    name: &'static str,
    spec: &'static str,
    oracle_key: &'static str,
    rolestore: &'static str,
    resolver: &'static str,
    definer: &'static str,
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn holds_matrix_sql_agrees_with_the_oracle() {
    let url = require_env("DEMESNE_PG_URL", "to run the three-surface holds matrix against a live Postgres");
    let targets = [
        MatrixTarget { name: "manage", spec: "manage.demesne", oracle_key: "manage", rolestore: "", resolver: "", definer: "member_has_perm" },
        MatrixTarget { name: "planes/admin", spec: "planes.demesne", oracle_key: "planes", rolestore: "admin", resolver: "", definer: "operator_has_perm" },
        MatrixTarget {
            name: "planes/platform",
            spec: "planes.demesne",
            oracle_key: "planes",
            rolestore: "platform",
            resolver: "platform",
            definer: "platform_has_perm",
        },
    ];
    T::top("holds_matrix_sql_agrees_with_the_oracle", |t| {
        for tgt in &targets {
            t.run(tgt.name, |t| run_holds_matrix(t, &url, tgt));
        }
    });
}

fn run_holds_matrix(t: &T, url: &str, tgt: &MatrixTarget) {
    let mut conn = demesne_postgres::connect(url).unwrap_or_else(|e| panic!("connect: {e}"));

    let path = format!("{}/../../examples/{}", env!("CARGO_MANIFEST_DIR"), tgt.spec);
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read spec: {e}"));
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("parse: {e}"));
    if let Err(e) = demesne_emit_sql::validate(&s) {
        panic!("validate: {e}");
    }
    let defs = demesne_emit_sql::Sql::new(&s).emit_definers().unwrap_or_else(|e| panic!("EmitDefiners: {e}"));
    let hr = s.holds_resolver(tgt.rolestore).unwrap_or_else(|e| panic!("HoldsResolver: {e}"));
    let vocab: Vec<String> = hr.vocabulary().permissions.iter().map(std::string::ToString::to_string).collect();
    let scope_args = hr.selected_scope_cols().len();

    let mut found = false;
    for d in &defs {
        if d.name != tgt.definer {
            continue;
        }
        found = true;
        let got = d.sig.matches(',').count() + 1;
        assert!(got == scope_args + 2, "{} takes {got} arguments, want {} (subject + {scope_args} scope + perm): {:?}", d.name, scope_args + 2, d.sig);
    }
    assert!(found, "spec emits no definer {:?}", tgt.definer);

    if let Err(e) = conn.batch_execute(&matrix_schema(&hr)) {
        panic!("schema: {e}");
    }
    let _cleanup = Cleanup { url, sql: format!("drop table if exists public.{}, public.{} cascade;", hr.assignments, hr.roles_table) };
    for d in &defs {
        if let Err(e) = conn.batch_execute(&d.create_sql()) {
            panic!("create {}: {e}", d.name);
        }
    }

    let query = format!("select p, auth.{}({}, p) from unnest(${}::text[]) p", tgt.definer, placeholders(scope_args + 1).join(", "), scope_args + 2);

    let cases = load_resolve_matrix(tgt.oracle_key, tgt.resolver);
    let mut checked = 0;
    for (i, input) in cases.iter().enumerate() {
        let want_set: BTreeSet<&str> = input.expect.iter().flatten().map(String::as_str).collect();
        let mut probe = vocab.clone();
        let in_vocab: BTreeSet<&str> = vocab.iter().map(String::as_str).collect();
        for p in input.expect.iter().flatten() {
            if !in_vocab.contains(p.as_str()) {
                probe.push(p.clone());
            }
        }

        if let Err(e) = conn.batch_execute(&format!("truncate public.{}; delete from public.{};", hr.assignments, hr.roles_table)) {
            panic!("case {i} reset: {e}");
        }
        let insert = format!("insert into public.{} ({}, {}, {}) values ($1, $2, $3)", hr.roles_table, hr.roles_id, hr.key_col, hr.perms_col);
        for (j, a) in input.assignments.iter().enumerate() {
            let role_id = format!("r{j}");
            if let Err(e) = conn.execute(&insert, &[&role_id, &format!("k{role_id}"), &a.permissions]) {
                panic!("case {i} role: {e}");
            }
            if let Err(e) = insert_assignment(&mut conn, &hr, &role_id, a.scope.as_deref().unwrap_or_default()) {
                panic!("case {i} assignment: {e}");
            }
        }

        let scope = input.scope.as_deref().unwrap_or_default();
        let scope_vals: Vec<Option<String>> = (0..scope_args).map(|k| scope.get(k).and_then(|s| nullable(s))).collect();
        let mut params: Vec<Arg> = vec![&"u1"];
        params.extend(scope_vals.iter().map(|v| v as Arg));
        params.push(&probe);

        let rows = conn.query(&query, &params).unwrap_or_else(|e| panic!("case {i} query: {e}"));
        let mut got: BTreeMap<String, bool> = BTreeMap::new();
        for row in &rows {
            let perm: String = row.try_get(0).unwrap_or_else(|e| panic!("case {i} scan: {e}"));
            let ok: Option<bool> = row.try_get(1).unwrap_or_else(|e| panic!("case {i} scan: {e}"));
            got.insert(perm, ok == Some(true));
        }

        for p in &probe {
            checked += 1;
            let (sql, oracle) = (got.get(p).copied().unwrap_or(false), want_set.contains(p.as_str()));
            if sql != oracle {
                t.errorf(format!(
                    "SQL surface disagrees with the Go/TS oracle:\n  assignments {}\n  query scope {:?}\n  permission {p:?}: SQL={sql} oracle={oracle}",
                    show(&input.assignments),
                    input.scope
                ));
            }
        }
    }
    t.logf(format!("three-surface matrix: {} cases, {checked} (scope x permission) cells checked against auth.{}", cases.len(), tgt.definer));
}
