use postgres::{Client, NoTls};
use std::collections::BTreeSet;
use std::fmt::Write as _;

const HEAD: &str = r#"
definers schema "ad_auth"
tables schema "ad_rows"

topology {
  level org     virtual
  level tenant  parent org
  level project parent tenant
}

vocabulary staff {
  permission docs:read
  permission docs:write
  preset viewer @ project = docs:read
  preset writer @ project = viewer + docs:write
  preset owner  @ tenant  = *
  rank owner > writer > viewer
}

rolestore staff {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}

grant support at tenant
  via edge support_grants(grantee_id, tenant_id)
  active revoked_at

external predicate tier_allows(text, text)

subject staff    { anchor tenant; reach descendants; identifies sub; roles configurable staff; binds admin }
subject member   { anchor project; reach self; identifies member_id; roles none; binds owner }
subject operator { anchor org; reach via grant support; identifies op_id; roles none }
"#;

struct Obj {
    name: &'static str,
    wildcard: bool,
    view: &'static str,
    extra: &'static str,
}

const fn obj(name: &'static str, view: &'static str) -> Obj {
    Obj { name, wildcard: false, view, extra: "" }
}

const OBJECTS: [Obj; 19] = [
    obj("plain", "owner + grantee:read"),
    obj("byrole", "owner + editor + grantee:read"),
    obj("held", "owner + @holds(docs:read) + grantee:read"),
    obj("kindby", r#"(owner and @kind("auditor")) + grantee:read"#),
    obj("rowby", r#"(owner and @row(status, "open")) + grantee:read"#),
    obj("modeby", r#"(owner and mode visibility = "open") + grantee:read"#),
    obj("claimby", r#"owner + (grantee:read and @claim("tier", "gold"))"#),
    obj("sessby", "(owner and @session) + grantee:read"),
    obj("heldby", "(editor and @holds(docs:write)) + owner + grantee:read"),
    obj("kindalone", r#"owner + @kind("auditor") + grantee:read"#),
    obj("pub", "owner + @public + grantee:read"),
    obj("selfie", "owner + @self(author_id) + grantee:read"),
    Obj { name: "wild", wildcard: true, view: "owner + grantee:read", extra: "" },
    Obj { name: "withinn", wildcard: true, view: "owner + @within(project nullable) + grantee:read", extra: "" },
    Obj { name: "req", wildcard: false, view: "owner + grantee:read", extra: "require view = @self(author_id)" },
    obj("negrow", r#"(owner and not @row(status, "archived")) + grantee:read"#),
    obj("scopedby", "(@scoped and owner) + grantee:read"),
    Obj { name: "ext", wildcard: false, view: "owner + grantee:read", extra: "require view = @external(tier_allows, status, @tier)" },
    Obj {
        name: "admitted",
        wildcard: false,
        view: "owner + grantee:read",
        extra: "admit select = @kind(\"robot\") and @within(project)\n  admit select = @kind(\"courier\") and not owner",
    },
];

const SHARED: &str = "
CREATE TABLE role_grants (id text PRIMARY KEY, grantee_kind text, grantee_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);
CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
CREATE TABLE support_grants (grantee_id text, tenant_id text, revoked_at timestamptz);
INSERT INTO roles VALUES ('r_viewer', 'viewer', '{docs:read}'), ('r_writer', 'writer', '{docs:read,docs:write}'), ('r_owner', 'owner', '{docs:read,docs:write}');
INSERT INTO role_grants VALUES
  ('g1', 'staff', 's_viewer', 't1', 'p1', 'r_viewer', NULL),
  ('g2', 'staff', 's_owner',  't1', NULL, 'r_owner',  NULL),
  ('g3', 'staff', 's_p2',     't1', 'p2', 'r_viewer', NULL),
  ('g4', 'staff', 's_writer', 't1', 'p1', 'r_writer', NULL);
INSERT INTO support_grants VALUES ('op1', 't2', NULL);
";

const IDENTITIES: [(&str, &str); 3] = [("member_id", "member"), ("sub", "staff"), ("op_id", "operator")];

fn spec() -> String {
    let mut s = HEAD.to_string();
    for o in &OBJECTS {
        let wildcard = if o.wildcard { " wildcard" } else { "" };
        write!(
            s,
            "object {n} {{\n  table {n}s\n  scoped tenant > project{wildcard}\n  relation owner: member via owner_id\n  relation editor: staff via role\n  relation grantee: member via grant {n}_acl(doc_id, principal_kind, principal_id, access)\n  permission view = {v} @rls maps select\n  {e}\n}}\n",
            n = o.name,
            v = o.view,
            e = o.extra
        )
        .expect("fmt::Write for String never fails");
    }
    s
}

fn tables() -> String {
    let mut b = SHARED.to_string();
    for o in &OBJECTS {
        let n = o.name;
        write!(
            b,
            "CREATE TABLE {n}s (id text PRIMARY KEY, tenant_id text, project_id text, owner_id text, author_id text, status text, visibility text);
             INSERT INTO {n}s VALUES
               ('d1', 't1', 'p1', 'm1', 's_viewer', 'open', 'open'),
               ('d2', 't1', 'p2', 'm2', 's_owner', 'archived', 'private'),
               ('d3', 't2', 'p1', 'm1', 'op1', 'open', 'open'),
               ('d4', 't1', NULL, 'm2', NULL, NULL, NULL);
             CREATE TABLE {n}_acl (doc_id text, principal_kind text, principal_id text, access text);
             INSERT INTO {n}_acl VALUES ('d1', 'member', 'm2', 'read'), ('d2', 'member', 'm1', 'read'), ('d3', 'member', 'm2', 'read'), ('d4', 'member', 'm1', 'read');\n"
        )
        .expect("fmt::Write for String never fails");
    }
    b
}

fn require_env(var: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set ${var} to run the admits checks against a live Postgres"))
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let rls = sql.emit_rls().expect("the policies compile");
    db.batch_execute(
        "DROP SCHEMA IF EXISTS ad_rows CASCADE; DROP SCHEMA IF EXISTS ad_auth CASCADE;
         CREATE SCHEMA ad_rows; CREATE SCHEMA ad_auth;
         DO $$ BEGIN
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ad_caller') THEN CREATE ROLE ad_caller NOLOGIN; END IF;
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ad_stranger') THEN CREATE ROLE ad_stranger NOLOGIN; END IF;
         END $$;
         CREATE FUNCTION ad_auth.tier_allows(p_status text, p_tier text) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT p_status = 'open' AND p_tier = 'gold' $$;",
    )
    .expect("fresh schemas");
    db.batch_execute(&format!("SET search_path = ad_rows; {} RESET search_path;", tables())).expect("tables and rows");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql("ad_caller")] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(
        "GRANT USAGE ON SCHEMA ad_rows, ad_auth TO ad_caller, ad_stranger;
         GRANT SELECT ON ALL TABLES IN SCHEMA ad_rows TO ad_caller;
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ad_auth TO ad_caller;",
    )
    .expect("grants");
}

#[derive(Clone)]
struct Claims(Vec<(&'static str, &'static str)>);

impl Claims {
    fn json(&self) -> String {
        let fields: Vec<String> = self.0.iter().map(|(k, v)| format!("\"{k}\":\"{v}\"")).collect();
        format!("{{{}}}", fields.join(","))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    fn identities(&self) -> Vec<(&'static str, &str)> {
        IDENTITIES.iter().filter_map(|(claim, kind)| self.get(claim).map(|v| (*kind, v))).collect()
    }
}

fn grid() -> Vec<Claims> {
    let dims: [(&str, &[&str]); 7] = [
        ("member_id", &["m1", "m2"]),
        ("sub", &["s_viewer", "s_writer", "s_owner"]),
        ("op_id", &["op1"]),
        ("tenant_id", &["t1", "t2"]),
        ("project_id", &["p1", "p2"]),
        ("kind", &["auditor", "robot", "courier"]),
        ("tier", &["gold"]),
    ];
    let mut out = vec![Claims(Vec::new())];
    for (key, values) in dims {
        let mut next = Vec::new();
        for c in &out {
            next.push(c.clone());
            for v in values {
                let mut with = c.clone();
                with.0.push((key, v));
                next.push(with);
            }
        }
        out = next;
    }
    out
}

fn union(select: impl Fn(&str) -> String) -> String {
    OBJECTS.iter().map(|o| select(o.name)).collect::<Vec<_>>().join(" UNION ALL ")
}

fn visible(db: &mut Client, claims: &str) -> BTreeSet<(String, String)> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE ad_caller").expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let rows = tx.query(&union(|n| format!("SELECT '{n}', id FROM ad_rows.{n}s")), &[]).expect("the visible rows");
    tx.rollback().expect("rollback");
    rows.iter().map(|r| (r.get(0), r.get(1))).collect()
}

fn admitted(db: &mut Client, claims: &str) -> BTreeSet<(String, String)> {
    db.query(&union(|n| format!("SELECT '{n}', id FROM ad_rows.{n}s WHERE ad_auth.{n}s_admits(id, $1::text::jsonb)")), &[&claims])
        .expect("the admitted rows")
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

#[derive(Debug)]
struct Listed {
    kind: Option<String>,
    id: Option<String>,
    claims: Vec<(String, Option<String>)>,
}

fn listing(db: &mut Client, table: &str, id: &str) -> Vec<Listed> {
    let conditional: bool =
        db.query_one("SELECT to_regprocedure($1) IS NOT NULL", &[&format!("ad_auth.{table}s_accessors_conditional(text)")]).expect("the listing lookup").get(0);
    let q = if conditional {
        format!("SELECT principal_kind, principal_id, via_claim_keys, via_claim_values FROM ad_auth.{table}s_accessors_conditional($1)")
    } else {
        format!("SELECT principal_kind, principal_id, NULL::text[], NULL::text[] FROM ad_auth.{table}s_accessors($1)")
    };
    db.query(&q, &[&id])
        .unwrap_or_else(|e| panic!("{table} listing: {e}"))
        .iter()
        .map(|r| {
            let keys: Vec<String> = r.get::<_, Option<Vec<String>>>(2).unwrap_or_default();
            let values: Vec<Option<String>> = r.get::<_, Option<Vec<Option<String>>>>(3).unwrap_or_default();
            Listed { kind: r.get(0), id: r.get(1), claims: keys.into_iter().zip(values).collect() }
        })
        .collect()
}

fn lists(rows: &[Listed], kind: &str, id: &str) -> bool {
    rows.iter().any(|r| r.kind.as_deref() == Some(kind) && r.id.as_deref() == Some(id))
}

fn covers(rows: &[Listed], claims: &Claims) -> bool {
    rows.iter().any(|r| r.id.is_none() && r.claims.iter().all(|(k, v)| v.is_some() && claims.get(k) == v.as_deref()))
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn admits_is_exact_and_the_listing_never_names_fewer() {
    let mut db = Client::connect(&require_env("DEMESNE_PG_URL"), NoTls).expect("connect");
    install(&mut db);
    let mut failures = admits_failures(&mut db);
    failures.extend(listing_failures(&mut db));
    failures.extend(narrowing_failures(&mut db));
    failures.extend(privilege_failures(&mut db));
    assert!(failures.is_empty(), "{} failures, first 20:\n{}", failures.len(), failures.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}

fn admits_failures(db: &mut Client) -> Vec<String> {
    let grid = grid();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    let mut hidden = BTreeSet::new();
    for c in &grid {
        let json = c.json();
        let (shown, admits) = (visible(db, &json), admitted(db, &json));
        for row in shown.symmetric_difference(&admits) {
            failures.push(format!("{json}: {row:?} RLS shows it {}, admits says {}", shown.contains(row), admits.contains(row)));
        }
        seen.extend(shown.iter().map(|(t, _)| t.clone()));
        hidden.extend(
            OBJECTS
                .iter()
                .filter(|o| o.view.contains("@public") || (1..=4).any(|d| !shown.contains(&(o.name.to_string(), format!("d{d}")))))
                .map(|o| o.name.to_string()),
        );
    }
    for o in &OBJECTS {
        if !seen.contains(o.name) || !hidden.contains(o.name) {
            failures.push(format!("{}: the grid never {} a row, so it tests nothing", o.name, if seen.contains(o.name) { "hid" } else { "showed" }));
        }
    }
    if grid.len() < 900 {
        failures.push(format!("only {} claim sets", grid.len()));
    }
    failures
}

fn listing_failures(db: &mut Client) -> Vec<String> {
    let mut failures = Vec::new();
    let mut covered = 0;
    for c in grid() {
        let [(kind, id)] = c.identities()[..] else { continue };
        for (table, row) in visible(db, &c.json()) {
            let rows = listing(db, &table, &row);
            if lists(&rows, kind, id) || covers(&rows, &c) {
                covered += 1;
            } else {
                failures.push(format!("{table}/{row}: RLS admits {} but the listing names neither {kind} {id} nor a conditional row: {rows:?}", c.json()));
            }
        }
    }
    if covered < 1000 {
        failures.push(format!("only {covered} admitted callers were checked"));
    }
    failures
}

fn narrowing_failures(db: &mut Client) -> Vec<String> {
    let cases = [
        ("rowby", "d1", "member", "m1", true),
        ("rowby", "d2", "member", "m2", false),
        ("negrow", "d1", "member", "m1", true),
        ("negrow", "d2", "member", "m2", false),
        ("modeby", "d1", "member", "m1", true),
        ("modeby", "d2", "member", "m2", false),
        ("heldby", "d1", "staff", "s_writer", true),
        ("heldby", "d1", "staff", "s_viewer", false),
        ("heldby", "d1", "member", "m1", true),
    ];
    let mut failures = Vec::new();
    for (table, row, kind, id, want) in cases {
        let rows = listing(db, table, row);
        if lists(&rows, kind, id) != want {
            failures.push(format!("{table}/{row}: {kind} {id} listed {}, want {want}: {rows:?}", !want));
        }
    }
    failures
}

fn privilege_failures(db: &mut Client) -> Vec<String> {
    let mut failures = Vec::new();
    for o in &OBJECTS {
        let f = format!("ad_auth.{}s_admits(text, jsonb)", o.name);
        let public: bool = db.query_one("SELECT has_function_privilege('public', $1, 'EXECUTE')", &[&f]).expect("the privilege").get(0);
        if public {
            failures.push(format!("PUBLIC may execute {f}"));
        }
    }
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE ad_stranger").expect("the stranger role");
    match tx.query_one("SELECT ad_auth.plains_admits('d1', '{}')", &[]) {
        Err(e) if e.code() == Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE) => {}
        other => failures.push(format!("a role without a grant called plains_admits: {other:?}")),
    }
    tx.rollback().expect("rollback");

    let own = r#"{"member_id":"m1","tenant_id":"t1","project_id":"p1"}"#;
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE ad_caller").expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&own]).expect("the claims");
    let before: Vec<String> = tx.query("SELECT id FROM ad_rows.plains ORDER BY id", &[]).expect("rows").iter().map(|r| r.get(0)).collect();
    let other: bool =
        tx.query_one(r#"SELECT ad_auth.plains_admits('d2', '{"member_id":"m2","tenant_id":"t1","project_id":"p2"}')"#, &[]).expect("admits").get(0);
    let setting: String = tx.query_one("SELECT current_setting('request.jwt.claims', true)", &[]).expect("the setting").get(0);
    let after: Vec<String> = tx.query("SELECT id FROM ad_rows.plains ORDER BY id", &[]).expect("rows").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    if !other {
        failures.push("plains_admits refuses m2 in p2 the row m2 owns there".into());
    }
    if setting != own || before != after || before != ["d1"] {
        failures.push(format!("admits changed the caller's claims: {own} became {setting}, rows {before:?} became {after:?}"));
    }
    failures
}
