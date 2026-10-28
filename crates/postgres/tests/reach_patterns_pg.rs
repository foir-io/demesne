use demesne_gocompat::json::{Value, marshal};
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{Error, Transaction};
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};

const REACH_ROWS: &str = "demesne_reach_rows";
const REACH_AUTH: &str = "demesne_reach_auth";
const REACH_CALLER: &str = "demesne_reach_caller";
const NULL: Option<&str> = None;

type Claims = BTreeMap<String, String>;
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

fn claims(pairs: &[(&str, &str)]) -> Claims {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn args<'a>(xs: &'a [&'a str]) -> Vec<Arg<'a>> {
    xs.iter().map(|x| x as Arg).collect()
}

#[derive(Clone, Copy)]
struct ReachTree {
    name: &'static str,
    root: &'static str,
    child: &'static str,
    other: &'static str,
    far: &'static str,
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn reach_patterns_postgres() {
    let url = require_env("DEMESNE_PG_URL", "to run the reach patterns against a live Postgres");
    T::top("reach_patterns_postgres", |t| {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/reach.demesne")).unwrap_or_else(|e| panic!("{e}"));
        let spec = demesne_syntax::parse(&format!("tables schema \"{REACH_ROWS}\"\ndefiners schema \"{REACH_AUTH}\"\n{src}")).unwrap_or_else(|e| panic!("{e}"));
        if let Err(e) = demesne_emit_sql::validate(&spec) {
            panic!("{e}");
        }
        for tree in [
            ReachTree { name: "ids opposite to depth", root: "z_root", child: "a_child", other: "m_other", far: "b_far" },
            ReachTree { name: "ids with depth", root: "a_root", child: "z_child", other: "m_other", far: "y_far" },
        ] {
            t.run(tree.name, |t| run_reach_patterns(t, &url, &spec, tree));
        }
    });
}

struct Db<'a, 'c> {
    t: &'a T,
    tx: &'a mut Transaction<'c>,
}

fn exec_on(tx: &mut Transaction<'_>, sql: &str, params: &[Arg]) -> Result<(), Error> {
    if params.is_empty() { tx.batch_execute(sql) } else { tx.execute(sql, params).map(|_| ()) }
}

impl<'c> Db<'_, 'c> {
    fn exec(&mut self, sql: &str, params: &[Arg]) {
        if let Err(e) = exec_on(self.tx, sql, params) {
            panic!("{e}\n{sql}");
        }
    }

    fn as_claims<R>(&mut self, claims: &Claims, f: impl FnOnce(&mut Transaction<'c>) -> Result<R, Error>) -> Result<R, Error> {
        let raw = marshal(&Value::Map(claims.iter().map(|(k, v)| (k.clone(), Value::str(v))).collect()));
        self.exec("SAVEPOINT reach_case", &[]);
        self.exec("SELECT set_config('request.jwt.claims', $1, true)", &[&raw]);
        self.exec(&format!("SET LOCAL ROLE {REACH_CALLER}"), &[]);
        let out = f(self.tx);
        self.exec("ROLLBACK TO SAVEPOINT reach_case", &[]);
        out
    }

    fn visible(&mut self, claims: &Claims, table: &str) -> Vec<String> {
        let sql = format!("SELECT id FROM {REACH_ROWS}.{table}");
        let got = self.as_claims(claims, |tx| tx.query(&sql, &[])?.iter().map(|r| r.try_get::<_, String>(0)).collect::<Result<Vec<_>, _>>());
        let mut ids = got.unwrap_or_else(|e| panic!("select {table} as {claims:?}: {e}"));
        ids.sort();
        ids
    }

    fn updated(&mut self, claims: &Claims, table: &str, id: &str) -> u64 {
        let sql = format!("UPDATE {REACH_ROWS}.{table} SET id = id WHERE id = $1");
        self.as_claims(claims, |tx| tx.execute(&sql, &[&id])).unwrap_or_else(|e| panic!("update {table} {id} as {claims:?}: {e}"))
    }

    fn truth(&mut self, claims: &Claims, sql: &str, params: &[Arg]) -> bool {
        let got = self.as_claims(claims, |tx| tx.query_one(sql, params)?.try_get::<_, Option<bool>>(0)).unwrap_or_else(|e| panic!("{sql} as {claims:?}: {e}"));
        got == Some(true)
    }

    fn insert_refused(&mut self, claims: &Claims, sql: &str, params: &[Arg]) -> bool {
        match self.as_claims(claims, |tx| exec_on(tx, sql, params)) {
            Err(e) if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) => true,
            Err(e) => panic!("{sql} as {claims:?}: {e}"),
            Ok(()) => false,
        }
    }
}

fn want_ids(t: &T, what: &str, got: &[String], want: &[&str]) {
    let mut want: Vec<&str> = want.to_vec();
    want.sort_unstable();
    if got.join(",") != want.join(",") {
        t.errorf(format!("{what}: got {got:?}, want {want:?}"));
    }
}

fn run_reach_patterns(t: &T, url: &str, spec: &demesne_syntax::Spec, tree: ReachTree) {
    let mut conn = demesne_postgres::connect(url).unwrap_or_else(|e| panic!("{e}"));
    let mut tx = conn.transaction().unwrap_or_else(|e| panic!("{e}"));
    install_reach_schema(&mut Db { t, tx: &mut tx }, spec);
    seed_reach_rows(&mut Db { t, tx: &mut tx }, &tree);

    t.run("scope ladder decides from the session", |t| check_ladder(&mut Db { t, tx: &mut tx }, &tree));
    t.run("selections", |t| check_selections(&mut Db { t, tx: &mut tx }, &tree));
    t.run("edge direction per object", |t| check_direction(&mut Db { t, tx: &mut tx }, &tree));
    t.run("claim lifts reads only", |t| check_claim_lift(&mut Db { t, tx: &mut tx }, &tree));
    t.run("borrow compiles for its op", |t| check_borrow(&mut Db { t, tx: &mut tx }, &tree));
    t.run("admit arm and export", |t| check_admit(&mut Db { t, tx: &mut tx }, &tree));
    let _ = tx.rollback();
}

fn install_reach_schema(d: &mut Db, spec: &demesne_syntax::Spec) {
    d.exec(&format!("CREATE SCHEMA {REACH_ROWS}; CREATE SCHEMA {REACH_AUTH}; CREATE ROLE {REACH_CALLER} NOLOGIN"), &[]);
    for table in [
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
    ] {
        d.exec(&format!("CREATE TABLE {REACH_ROWS}.{table}"), &[]);
    }
    let sql = demesne_emit_sql::Sql::new(spec);
    let defs = sql.emit_definers().unwrap_or_else(|e| panic!("{e}"));
    d.exec("SET LOCAL check_function_bodies = off", &[]);
    for def in &defs {
        d.exec(&def.create_sql(), &[]);
    }
    let rls = match sql.emit_rls() {
        Ok(r) if r.unsupported.is_empty() => r,
        Ok(r) => panic!("emit rls: <nil> {:?}", r.unsupported),
        Err(e) => panic!("emit rls: {e} []"),
    };
    d.exec(&rls.enablement_sql(), &[]);
    d.exec(&rls.policy_sql(REACH_CALLER), &[]);
    d.exec(&format!("GRANT USAGE ON SCHEMA {REACH_ROWS}, {REACH_AUTH} TO {REACH_CALLER}"), &[]);
    d.exec(&format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {REACH_ROWS} TO {REACH_CALLER}"), &[]);
    d.exec(&format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {REACH_AUTH} TO {REACH_CALLER}"), &[]);
}

fn seed_reach_rows(d: &mut Db, tr: &ReachTree) {
    for (id, space, parent) in [(tr.root, "s1", NULL), (tr.child, "s1", Some(tr.root)), (tr.other, "s1", NULL), (tr.far, "s2", NULL)] {
        d.exec(&format!("INSERT INTO {REACH_ROWS}.folders VALUES ($1, 'e1', $2, $3)"), &[&id, &space, &parent]);
        d.exec(&format!("INSERT INTO {REACH_ROWS}.paths VALUES ($1, $1)"), &[&id]);
    }
    d.exec(&format!("INSERT INTO {REACH_ROWS}.paths VALUES ($1, $2)"), &[&tr.root, &tr.child]);
    for (holder, space, folder, ended) in
        [("h_estate", NULL, NULL, false), ("h_space", Some("s1"), NULL, false), ("h_folder", Some("s1"), Some(tr.root), false), ("h_ended", NULL, NULL, true)]
    {
        let ended = if ended { "now() - interval '1 minute'" } else { "NULL" };
        d.exec(&format!("INSERT INTO {REACH_ROWS}.approvals VALUES ($1, 'e1', $2, $3, {ended}, now() + interval '1 day')"), &[&holder, &space, &folder]);
    }
    for table in ["assets", "blueprints"] {
        for (id, space, folder) in [
            (tr.root, "s1", Some(tr.root)),
            (tr.child, "s1", Some(tr.child)),
            (tr.other, "s1", Some(tr.other)),
            ("shared", "s1", NULL),
            (tr.far, "s2", Some(tr.far)),
        ] {
            d.exec(&format!("INSERT INTO {REACH_ROWS}.{table} VALUES ($1, 'e1', $2, $3)"), &[&id, &space, &folder]);
        }
    }
    d.exec(&format!("INSERT INTO {REACH_ROWS}.ledgers VALUES ('l1', 'e1')"), &[]);
    d.exec(&format!("INSERT INTO {REACH_ROWS}.allowances VALUES ('al_s1', 'e1', 's1'), ('al_s2', 'e1', 's2')"), &[]);
    d.exec(&format!("INSERT INTO {REACH_ROWS}.spaces VALUES ('s1', 'e1'), ('s2', 'e1')"), &[]);
    d.exec(&format!("INSERT INTO {REACH_ROWS}.catalogs VALUES ($1, 'e1', 's1', $1), ($2, 'e1', 's1', $2)"), &[&tr.root, &tr.child]);
    d.exec(&format!("INSERT INTO {REACH_ROWS}.entries VALUES ($1, 'e1', 's1', $1), ($2, 'e1', 's1', $2)"), &[&tr.root, &tr.child]);
}

fn check_ladder(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let v = d.visible(&claims(&[("sub", "h_estate"), ("space_id", "s1")]), "assets");
    want_ids(t, "estate-wide helper without a folder claim", &v, &["shared"]);
    let v = d.visible(&claims(&[("sub", "h_estate"), ("space_id", "s1"), ("folder_id", tr.root)]), "assets");
    want_ids(t, "estate-wide helper standing in the root", &v, &[tr.root, tr.child, "shared"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s1"), ("folder_id", tr.root)]), "assets");
    want_ids(t, "space-pinned helper in its space", &v, &[tr.root, tr.child, "shared"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s2"), ("folder_id", tr.far)]), "assets");
    want_ids(t, "space-pinned helper in another space", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1"), ("folder_id", tr.root)]), "assets");
    want_ids(t, "folder-pinned helper in its folder", &v, &[tr.root, tr.child, "shared"]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1"), ("folder_id", tr.other)]), "assets");
    want_ids(t, "folder-pinned helper beside its folder", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1")]), "assets");
    want_ids(t, "folder-pinned helper standing in the space", &v, &["shared"]);
    let v = d.visible(&claims(&[("sub", "h_ended"), ("space_id", "s1"), ("folder_id", tr.root)]), "assets");
    want_ids(t, "ended approval", &v, &[]);

    let probe = format!("SELECT {REACH_AUTH}.approvals_reach($1, 'e1')");
    for (name, c, holder, want) in [
        ("space rung refuses a missing space claim", claims(&[("folder_id", tr.root)]), "h_space", false),
        ("space rung admits its space", claims(&[("space_id", "s1")]), "h_space", true),
        ("folder rung admits a missing folder claim", claims(&[("space_id", "s1")]), "h_folder", true),
        ("folder rung refuses a sibling folder", claims(&[("space_id", "s1"), ("folder_id", tr.other)]), "h_folder", false),
        ("unpinned approval needs no claims", claims(&[]), "h_estate", true),
    ] {
        let got = d.truth(&c, &probe, &[&holder]);
        if got != want {
            t.errorf(format!("{name}: approvals_reach({holder}) = {got}, want {want}"));
        }
    }
    d.exec("SAVEPOINT empty_claims", &[]);
    d.exec("SELECT set_config('request.jwt.claims', '', true)", &[]);
    match d.tx.query_one(&probe, &[&"h_estate"]).and_then(|r| r.try_get::<_, bool>(0)) {
        Ok(true) => {}
        Ok(false) => t.errorf("a direct call with an empty claims setting must answer rather than raise: false <nil>"),
        Err(e) => t.errorf(format!("a direct call with an empty claims setting must answer rather than raise: false {e}")),
    }
    d.exec("ROLLBACK TO SAVEPOINT empty_claims", &[]);

    let in_space = format!("SELECT {REACH_AUTH}.approvals_reach_in_space($1, 'e1', $2)");
    let in_folder = format!("SELECT {REACH_AUTH}.approvals_reach_in_folder($1, 'e1', $2, $3)");
    for (sql, a, want) in [
        (&in_space, vec!["h_space", ""], true),
        (&in_space, vec!["h_space", "s2"], false),
        (&in_space, vec!["h_space", "s1"], true),
        (&in_folder, vec!["h_folder", "s1", ""], true),
        (&in_folder, vec!["h_folder", "s1", tr.other], false),
        (&in_folder, vec!["h_folder", "s1", tr.root], true),
        (&in_space, vec!["h_folder", "s2"], false),
    ] {
        let got = d.truth(&claims(&[]), sql, &args(&a));
        if got != want {
            t.errorf(format!("{sql} {a:?} = {got}, want {want}"));
        }
    }
}

fn check_selections(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let v = d.visible(&claims(&[("sub", "h_estate")]), "ledgers");
    want_ids(t, "unscoped: estate-wide helper", &v, &["l1"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s1")]), "ledgers");
    want_ids(t, "unscoped: space-pinned helper", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1"), ("folder_id", tr.root)]), "ledgers");
    want_ids(t, "unscoped: folder-pinned helper", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_estate")]), "spaces");
    want_ids(t, "bound: estate-wide helper", &v, &["s1", "s2"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s1")]), "spaces");
    want_ids(t, "bound: space-pinned helper in its space", &v, &["s1"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s2")]), "spaces");
    want_ids(t, "bound: space-pinned helper claiming another space", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1"), ("folder_id", tr.root)]), "spaces");
    want_ids(t, "bound: folder-pinned helper", &v, &["s1"]);
    check_bound_column(d, tr);
    let n = d.updated(&claims(&[("sub", "h_space"), ("space_id", "s1")]), "spaces", "s1");
    if n != 0 {
        t.errorf(format!("a space-pinned helper updated its own space row ({n} rows); update takes the unscoped reach"));
    }
    let n = d.updated(&claims(&[("sub", "h_estate"), ("space_id", "s1")]), "spaces", "s1");
    if n != 1 {
        t.errorf(format!("an estate-wide helper could not update the space row ({n} rows)"));
    }
}

fn check_direction(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let at = |folder: &str| claims(&[("estate_id", "e1"), ("space_id", "s1"), ("folder_id", folder)]);
    let v = d.visible(&at(tr.root), "assets");
    want_ids(t, "rows reach down from the root", &v, &[tr.root, tr.child, "shared"]);
    let v = d.visible(&at(tr.child), "assets");
    want_ids(t, "rows do not reach up from the child", &v, &[tr.child, "shared"]);
    let v = d.visible(&at(tr.child), "blueprints");
    want_ids(t, "definitions inherit up to the child", &v, &[tr.root, tr.child, "shared"]);
    let v = d.visible(&at(tr.root), "blueprints");
    want_ids(t, "definitions do not reach down from the root", &v, &[tr.root, "shared"]);
    let v = d.visible(&at(tr.other), "blueprints");
    want_ids(t, "a sibling inherits nothing", &v, &[tr.other, "shared"]);
    let n = d.updated(&at(tr.child), "blueprints", tr.root);
    if n != 0 {
        t.errorf(format!("the child updated an inherited definition ({n} rows)"));
    }
    let n = d.updated(&at(tr.root), "assets", tr.child);
    if n != 0 {
        t.errorf(format!("the root updated a descendant row through a read-only reach ({n} rows)"));
    }
}

fn check_claim_lift(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let lifted = claims(&[("estate_id", "e1"), ("space_id", "s1"), ("folder_id", tr.other), ("view_mode", "all")]);
    let v = d.visible(&lifted, "assets");
    want_ids(t, "lifted read", &v, &[tr.root, tr.child, tr.other, "shared"]);
    let v = d.visible(&claims(&[("estate_id", "e1"), ("space_id", "s1"), ("folder_id", tr.other), ("view_mode", "some")]), "assets");
    want_ids(t, "other claim value", &v, &[tr.other, "shared"]);
    let v = d.visible(&claims(&[("estate_id", "e1"), ("space_id", "s2"), ("view_mode", "all")]), "assets");
    want_ids(t, "the lift stays inside the space", &v, &[tr.far]);
    let n = d.updated(&lifted, "assets", tr.root);
    if n != 0 {
        t.errorf(format!("the lifted claim updated a row outside its folder ({n} rows)"));
    }
    let n = d.updated(&lifted, "assets", tr.other);
    if n != 1 {
        t.errorf(format!("the lifted claim could not update its own folder's row ({n} rows)"));
    }
}

fn check_borrow(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let staff = |folder: &str| claims(&[("estate_id", "e1"), ("space_id", "s1"), ("folder_id", folder), ("kind", "staff")]);
    let v = d.visible(&staff(tr.child), "entries");
    want_ids(t, "read borrow inherits up", &v, &[tr.root, tr.child]);
    let v = d.visible(&staff(tr.root), "entries");
    want_ids(t, "read borrow does not reach down", &v, &[tr.root]);
    let n = d.updated(&staff(tr.child), "entries", tr.root);
    if n != 0 {
        t.errorf(format!("write borrow admitted an inherited catalog ({n} rows)"));
    }
    let n = d.updated(&staff(tr.child), "entries", tr.child);
    if n != 1 {
        t.errorf(format!("write borrow refused the caller's own catalog ({n} rows)"));
    }
    let mut robot = staff(tr.child);
    robot.insert("kind".into(), "robot".into());
    let v = d.visible(&robot, "entries");
    want_ids(t, "borrowed authority still applies", &v, &[]);
}

fn check_admit(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let robot = |folder: &str| {
        let mut c = claims(&[("estate_id", "e1"), ("space_id", "s1"), ("kind", "robot")]);
        if !folder.is_empty() {
            c.insert("folder_id".into(), folder.into());
        }
        c
    };
    let staff = claims(&[("estate_id", "e1"), ("space_id", "s1"), ("kind", "staff")]);
    let v = d.visible(&robot(tr.root), "folders");
    want_ids(t, "robot confined to the root", &v, &[tr.root, tr.child]);
    let v = d.visible(&robot(tr.child), "folders");
    want_ids(t, "robot confined to the child", &v, &[tr.child]);
    let v = d.visible(&robot(""), "folders");
    want_ids(t, "unconfined robot", &v, &[tr.root, tr.child, tr.other]);
    let v = d.visible(&staff, "folders");
    want_ids(t, "staff through the permission", &v, &[tr.root, tr.child, tr.other]);
    let v = d.visible(&claims(&[("estate_id", "e1"), ("space_id", "s2"), ("kind", "robot"), ("folder_id", tr.root)]), "folders");
    want_ids(t, "robot in another space", &v, &[]);

    let insert = format!("INSERT INTO {REACH_ROWS}.folders VALUES ('fresh', 'e1', 's1', $1)");
    if d.insert_refused(&robot(tr.root), &insert, &[&tr.root]) {
        t.errorf("a robot confined to the root could not create a folder beneath it");
    }
    if !d.insert_refused(&robot(tr.root), &insert, &[&tr.other]) {
        t.errorf("a robot confined to the root created a folder under a sibling");
    }
    if !d.insert_refused(&robot(tr.root), &insert, &[&NULL]) {
        t.errorf("a confined robot created a top-level folder");
    }
    if d.insert_refused(&robot(""), &insert, &[&NULL]) {
        t.errorf("an unconfined robot could not create a top-level folder");
    }

    let allowed = format!("SELECT {REACH_AUTH}.folder_write_allowed($1, 'e1', $2)");
    for c in [robot(tr.root), robot(tr.child), robot(""), staff.clone(), claims(&[("estate_id", "e1"), ("space_id", "s1"), ("kind", "visitor")])] {
        for id in [tr.root, tr.child, tr.other, tr.far] {
            let space = if id == tr.far { "s2" } else { "s1" };
            let exported = d.truth(&c, &allowed, &[&id, &space]);
            let policy = d.updated(&c, "folders", id) == 1;
            if exported != policy {
                t.errorf(format!("folder_write_allowed({id}) = {exported} but the update policy admitted it = {policy}, as {c:?}"));
            }
        }
    }
    let allowed_s1 = format!("SELECT {REACH_AUTH}.folder_write_allowed($1, 'e1', 's1')");
    if !d.truth(&robot(tr.root), &allowed_s1, &[&tr.child]) {
        t.errorf("export: a confined robot may write its descendant");
    }
    if d.truth(&robot(tr.root), &allowed_s1, &[&tr.other]) {
        t.errorf("export: a confined robot may not write a sibling");
    }
}

fn check_bound_column(d: &mut Db, tr: &ReachTree) {
    let t = d.t;
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s1")]), "allowances");
    want_ids(t, "bound column: space-pinned helper reads its own space's row", &v, &["al_s1"]);
    let v = d.visible(&claims(&[("sub", "h_space"), ("space_id", "s2")]), "allowances");
    want_ids(t, "bound column: space-pinned helper claiming another space", &v, &[]);
    let v = d.visible(&claims(&[("sub", "h_folder"), ("space_id", "s1"), ("folder_id", tr.root)]), "allowances");
    want_ids(t, "bound column: folder-pinned helper", &v, &["al_s1"]);
    let v = d.visible(&claims(&[("sub", "h_estate"), ("space_id", "s1")]), "allowances");
    want_ids(t, "bound column: estate-wide helper", &v, &["al_s1", "al_s2"]);
    for id in ["al_s1", "al_s2"] {
        let n = d.updated(&claims(&[("sub", "h_space"), ("space_id", "s1")]), "allowances", id);
        if n != 0 {
            t.errorf(format!("a space-pinned helper updated allowance {id} ({n} rows); writes take the unscoped reach"));
        }
        let n = d.updated(&claims(&[("sub", "h_estate"), ("space_id", "s1")]), "allowances", id);
        if n != 1 {
            t.errorf(format!("an estate-wide helper could not update allowance {id} ({n} rows)"));
        }
    }
    let insert = format!("INSERT INTO {REACH_ROWS}.allowances VALUES ('al_new', 'e1', 's1')");
    if !d.insert_refused(&claims(&[("sub", "h_space"), ("space_id", "s1")]), &insert, &[]) {
        t.errorf("a space-pinned helper inserted an allowance");
    }
    if d.insert_refused(&claims(&[("sub", "h_estate"), ("space_id", "s1")]), &insert, &[]) {
        t.errorf("an estate-wide helper could not insert an allowance");
    }
}
