use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const SPEC: &str = r#"
definers schema "d36_auth"
tables schema "d36_rows"

topology {
  level org       virtual
  level tenant    parent org
  level workspace parent tenant
}

vocabulary staff {
  permission docs:read
  permission docs:write
  preset viewer @ workspace = docs:read
  preset owner  @ tenant    = *
  rank owner > viewer
}

rolestore staff {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id workspace_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}

subject staff  { anchor tenant; reach descendants; identifies sub; roles configurable staff; binds admin }
subject member { anchor workspace; reach self; identifies member_id; roles none; binds owner }

object held_doc {
  table  held_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant held_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @holds(docs:read) + grantee:read @rls maps select
}

object tree_doc {
  table  tree_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant tree_acl(doc_id, principal_kind, principal_id, access)
  permission view = (owner + @holds(docs:read) + grantee:read) and not @row(state, "archived") @rls maps select
}

object role_doc {
  table  role_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation editor:  staff via role
  relation grantee: member via grant role_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + editor + grantee:read @rls maps select
}

object kind_doc {
  table  kind_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant kind_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @kind("auditor") + grantee:read @rls maps select
}

object self_doc {
  table  self_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant self_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @self(author_id) + grantee:read @rls maps select
}

object within_doc {
  table  within_docs
  scoped tenant > workspace wildcard
  relation owner:   member via owner_id
  relation grantee: member via grant within_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @within(workspace nullable) + grantee:read @rls maps select
}

object member_doc {
  table  member_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant member_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @session + grantee:read @rls maps select
}

object public_doc {
  table  public_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation grantee: member via grant public_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @public + grantee:read @rls maps select
}

object session_doc {
  table  session_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation editor:  staff via role
  relation grantee: member via grant session_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + @session(editor) + grantee:read @rls maps select
}

object team {
  table  teams
  scoped tenant > workspace
  relation grantee: member via grant team_acl(team_id, principal_kind, principal_id, access)
  permission view = grantee:read @rls maps select
  admit select = @kind("service")
}

object team_doc {
  table  team_docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation in_team: team via object team->view on team_id
  relation grantee: member via grant team_doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + in_team + grantee:read @rls maps select
}
"#;

const TABLES: &str = "
CREATE TABLE role_grants (id text PRIMARY KEY, grantee_kind text, grantee_id text, tenant_id text, workspace_id text, role_id text, revoked_at timestamptz);
CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
CREATE TABLE held_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE role_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE tree_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text, state text);
CREATE TABLE tree_acl (doc_id text, principal_kind text, principal_id text, access text);
INSERT INTO tree_docs VALUES ('d1', 't1', 'w1', 'm1', 'active');
CREATE TABLE session_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE kind_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE self_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text, author_id text);
CREATE TABLE within_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE public_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE member_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE member_acl (doc_id text, principal_kind text, principal_id text, access text);
INSERT INTO member_docs VALUES ('d1', 't1', 'w1', 'm1');
CREATE TABLE kind_acl (doc_id text, principal_kind text, principal_id text, access text);
CREATE TABLE self_acl (doc_id text, principal_kind text, principal_id text, access text);
CREATE TABLE within_acl (doc_id text, principal_kind text, principal_id text, access text);
CREATE TABLE public_acl (doc_id text, principal_kind text, principal_id text, access text);
INSERT INTO kind_docs VALUES ('d1', 't1', 'w1', 'm1');
INSERT INTO self_docs VALUES ('d1', 't1', 'w1', 'm1', 'author_1');
INSERT INTO within_docs VALUES ('d1', 't1', 'w1', 'm1'), ('d2', 't1', NULL, 'm1');
INSERT INTO public_docs VALUES ('d1', 't1', 'w1', 'm1');
CREATE TABLE held_acl (doc_id text, principal_kind text, principal_id text, access text);
CREATE TABLE role_acl (doc_id text, principal_kind text, principal_id text, access text);
CREATE TABLE session_acl (doc_id text, principal_kind text, principal_id text, access text);
INSERT INTO roles VALUES ('r_viewer', 'viewer', '{docs:read}'), ('r_owner', 'owner', '{docs:read,docs:write}'), ('r_none', 'none', '{}');
INSERT INTO role_grants VALUES
  ('g1', 'staff', 'viewer_w1', 't1', 'w1', 'r_viewer', NULL),
  ('g2', 'staff', 'owner_t1',  't1', NULL, 'r_owner',  NULL),
  ('g3', 'staff', 'viewer_w2', 't1', 'w2', 'r_viewer', NULL),
  ('g4', 'staff', 'revoked',   't1', 'w1', 'r_viewer', now()),
  ('g5', 'staff', 'no_perms',  't1', 'w1', 'r_none',   NULL);
INSERT INTO held_docs VALUES ('d1', 't1', 'w1', 'm1');
INSERT INTO role_docs VALUES ('d1', 't1', 'w1', 'm1');
INSERT INTO session_docs VALUES ('d1', 't1', 'w1', 'm1');
CREATE TABLE teams (id text PRIMARY KEY, tenant_id text, workspace_id text);
CREATE TABLE team_acl (team_id text, principal_kind text, principal_id text, access text);
CREATE TABLE team_docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text, team_id text);
CREATE TABLE team_doc_acl (doc_id text, principal_kind text, principal_id text, access text);
INSERT INTO teams VALUES ('a', 't1', 'w1');
INSERT INTO team_acl VALUES ('a', 'member', 'm_team', 'read');
INSERT INTO team_docs VALUES ('d1', 't1', 'w1', 'm1', 'a');
INSERT INTO team_doc_acl VALUES ('d1', 'member', 'm_doc', 'read');
";

const STAFF: [&str; 5] = ["viewer_w1", "owner_t1", "viewer_w2", "revoked", "no_perms"];

fn require_env(var: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set ${var} to run the accessor listing against a live Postgres"))
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(SPEC).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let rls = sql.emit_rls().expect("the policies compile");
    db.batch_execute(
        "DROP SCHEMA IF EXISTS d36_rows CASCADE; DROP SCHEMA IF EXISTS d36_auth CASCADE;
         CREATE SCHEMA d36_rows; CREATE SCHEMA d36_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'd36_caller') THEN CREATE ROLE d36_caller NOLOGIN; END IF; END $$;",
    )
    .expect("fresh schemas");
    db.batch_execute(&format!("SET search_path = d36_rows; {TABLES} RESET search_path;")).expect("tables and rows");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql("d36_caller")] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(
        "GRANT USAGE ON SCHEMA d36_rows, d36_auth TO d36_caller;
         GRANT SELECT ON ALL TABLES IN SCHEMA d36_rows TO d36_caller;
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA d36_auth TO d36_caller;",
    )
    .expect("grants");
}

fn admitted_to(db: &mut Client, table: &str, id: &str, claims: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE d36_caller").expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let n: i64 = tx.query_one(&format!("SELECT count(*) FROM d36_rows.{table} WHERE id = $1"), &[&id]).expect("the select").get(0);
    tx.rollback().expect("rollback");
    n > 0
}

fn admitted(db: &mut Client, table: &str, claims: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE d36_caller").expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let n: i64 = tx.query_one(&format!("SELECT count(*) FROM d36_rows.{table} WHERE id = 'd1'"), &[]).expect("the select").get(0);
    tx.rollback().expect("rollback");
    n > 0
}

fn listed(db: &mut Client, table: &str) -> BTreeSet<(String, String)> {
    db.query(&format!("SELECT principal_kind, principal_id FROM d36_auth.{table}_accessors('d1') WHERE principal_id IS NOT NULL"), &[])
        .unwrap_or_else(|e| panic!("{table}_accessors: {e}"))
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

fn staff_claims(sub: &str) -> String {
    format!(r#"{{"sub":"{sub}","tenant_id":"t1","workspace_id":"w1"}}"#)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_accessor_listing_covers_every_caller_rls_admits() {
    let mut db = Client::connect(&require_env("DEMESNE_PG_URL"), NoTls).expect("connect");
    install(&mut db);
    let mut failures = staff_failures(&mut db);
    failures.extend(conditional_failures(&mut db));
    failures.extend(borrow_failures(&mut db));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn borrow_failures(db: &mut Client) -> Vec<String> {
    let member_claims = |id: &str| format!(r#"{{"member_id":"{id}","tenant_id":"t1","workspace_id":"w1"}}"#);
    let service = r#"{"kind":"service","tenant_id":"t1","workspace_id":"w1"}"#;
    let listed_members: BTreeSet<String> = listed(db, "team_docs").into_iter().filter(|(k, _)| k == "member").map(|(_, id)| id).collect();
    let admitted_members: BTreeSet<String> =
        ["m1", "m_team", "m_doc", "m_none"].into_iter().filter(|m| admitted(db, "team_docs", &member_claims(m))).map(String::from).collect();
    let mut failures = Vec::new();
    if listed_members != admitted_members {
        failures.push(format!("team_docs: RLS admits {admitted_members:?} but the listing names {listed_members:?}"));
    }
    if !admitted_members.contains("m_team") {
        failures.push("team_docs: the team's grantee reads nothing through the borrow, so the case tests nothing".into());
    }
    if !admitted_to(db, "teams", "a", service) {
        failures.push("teams: the select arm admits no service caller, so the case tests nothing".into());
    }
    if admitted(db, "team_docs", service) {
        failures.push("team_docs: the team's select arm reaches through the borrow, which the listing does not name".into());
    }
    failures
}

fn staff_failures(db: &mut Client) -> Vec<String> {
    let cases = [
        ("held_docs", &["viewer_w1", "owner_t1"][..]),
        ("tree_docs", &["viewer_w1", "owner_t1"][..]),
        ("role_docs", &["viewer_w1"][..]),
        ("session_docs", &["viewer_w1"][..]),
    ];
    let mut failures = Vec::new();
    for (table, want) in cases {
        let names = listed(db, table);
        let listed_staff: BTreeSet<&str> = names.iter().filter(|(k, _)| k == "staff").map(|(_, id)| id.as_str()).collect();
        let admitted_staff: BTreeSet<&str> = STAFF.iter().copied().filter(|s| admitted(db, table, &staff_claims(s))).collect();
        if listed_staff != admitted_staff {
            failures.push(format!("{table}: RLS admits {admitted_staff:?} but the listing names {listed_staff:?}"));
        }
        if listed_staff != want.iter().copied().collect::<BTreeSet<_>>() {
            failures.push(format!("{table}: the listing names {listed_staff:?}, want {want:?}"));
        }
        if !names.contains(&("member".to_string(), "m1".to_string())) {
            failures.push(format!("{table}: the owner m1 is missing from {names:?}"));
        }
    }
    failures
}

struct Row {
    source: String,
    keys: Option<Vec<String>>,
    values: Option<Vec<String>>,
}

fn conditional_rows(db: &mut Client, table: &str, id: &str) -> Vec<Row> {
    db.query(&format!("SELECT source, via_claim_keys, via_claim_values FROM d36_auth.{table}_accessors_conditional($1) WHERE principal_id IS NULL"), &[&id])
        .unwrap_or_else(|e| panic!("{table}_accessors_conditional: {e}"))
        .iter()
        .map(|r| Row { source: r.get(0), keys: r.get(1), values: r.get(2) })
        .collect()
}

fn covers(rows: &[Row], claims: &serde_like::Claims) -> bool {
    rows.iter().any(|r| match (r.source.as_str(), &r.keys, &r.values) {
        ("public" | "scope", _, _) => true,
        (_, Some(keys), Some(values)) => keys.len() == values.len() && keys.iter().zip(values).all(|(k, v)| claims.get(k) == Some(v.as_str())),
        _ => false,
    })
}

mod serde_like {
    pub(super) struct Claims(pub(super) Vec<(&'static str, &'static str)>);

    impl Claims {
        pub(super) fn get(&self, key: &str) -> Option<&str> {
            self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
        }

        pub(super) fn json(&self) -> String {
            let fields: Vec<String> = self.0.iter().map(|(k, v)| format!("\"{k}\":\"{v}\"")).collect();
            format!("{{{}}}", fields.join(","))
        }
    }
}

fn conditional_failures(db: &mut Client) -> Vec<String> {
    use serde_like::Claims;
    let callers = [
        Claims(vec![("sub", "x1"), ("kind", "auditor"), ("tenant_id", "t1"), ("workspace_id", "w1")]),
        Claims(vec![("sub", "x2"), ("kind", "guest"), ("tenant_id", "t1"), ("workspace_id", "w1")]),
        Claims(vec![("sub", "author_1"), ("tenant_id", "t1"), ("workspace_id", "w1")]),
        Claims(vec![("sub", "x3"), ("tenant_id", "t1"), ("workspace_id", "w9")]),
        Claims(vec![("sub", "x4"), ("tenant_id", "t1")]),
    ];
    let cases = [
        ("kind_docs", "d1", 1),
        ("self_docs", "d1", 1),
        ("within_docs", "d1", 1),
        ("within_docs", "d2", 1),
        ("member_docs", "d1", 1),
        ("public_docs", "d1", 1),
    ];
    let mut failures = Vec::new();
    for (table, id, want_admitted_at_least) in cases {
        let rows = conditional_rows(db, table, id);
        let mut admitted_count = 0;
        for c in &callers {
            let admitted = admitted_to(db, table, id, &c.json());
            admitted_count += usize::from(admitted);
            match (admitted, covers(&rows, c)) {
                (true, false) => failures.push(format!("{table}/{id}: RLS admits {} but no conditional row covers it", c.json())),
                (false, true) => failures.push(format!("{table}/{id}: a conditional row covers {}, which RLS refuses", c.json())),
                _ => {}
            }
        }
        if admitted_count < want_admitted_at_least {
            failures.push(format!("{table}/{id}: RLS admitted {admitted_count} callers, so the case tests nothing"));
        }
    }
    failures
}
