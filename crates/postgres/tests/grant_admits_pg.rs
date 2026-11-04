use postgres::{Client, NoTls};
use std::fmt::Write as _;

const HEAD: &str = r#"
definers schema "ga_auth"
tables schema "ga_rows"

topology {
  level org     virtual
  level tenant  parent org
  level project parent tenant
}

vocabulary staff {
  permission docs:read
  preset viewer @ project = docs:read
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

subject staff  { anchor tenant; reach descendants; identifies sub; roles configurable staff; binds admin }
subject member { anchor project; reach self; identifies member_id; roles none; binds owner }
"#;

const OBJECTS: [(&str, &str); 3] = [("wide", " read admits write, delete"), ("grouped", " read admits write, delete"), ("exact", "")];

fn spec() -> String {
    let mut s = HEAD.to_string();
    for (n, admits) in OBJECTS {
        let (edit, delete) =
            if admits.is_empty() { ("(grantee:write and grantee:read)", "(grantee:delete and grantee:read)") } else { ("grantee:write", "grantee:delete") };
        let group = if n == "grouped" { " group \"team\" closure team_members(team_id, member_id) edge team_edges(member_id, team_id)" } else { "" };
        write!(
            s,
            "object {n} {{\n  table {n}s\n  scoped tenant > project\n  relation owner: member via owner_id\n  relation grantee: member via grant {n}_acl(doc_id, principal_kind, principal_id, access){group}{admits}\n  permission view   = owner + grantee:read @rls maps select\n  permission edit   = owner + {edit} @rls maps update\n  permission delete = owner + {delete} @rls maps delete\n}}\n"
        )
        .expect("fmt::Write for String never fails");
    }
    s
}

fn tables() -> String {
    let mut b = String::from(
        "CREATE TABLE role_grants (id text PRIMARY KEY, grantee_kind text, grantee_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);
         CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
         CREATE TABLE team_members (team_id text, member_id text);
         CREATE TABLE team_edges (member_id text, team_id text);
         INSERT INTO team_members VALUES ('team_w', 'm_team_w'), ('team_d', 'm_team_d');\n",
    );
    for (n, _) in OBJECTS {
        let (w, d) = if n == "grouped" { (("team", "team_w"), ("team", "team_d")) } else { (("member", "m_write"), ("member", "m_delete")) };
        write!(
            b,
            "CREATE TABLE {n}s (id text PRIMARY KEY, tenant_id text, project_id text, owner_id text, status text);
             INSERT INTO {n}s VALUES ('d1', 't1', 'p1', 'm_owner', 'open');
             CREATE TABLE {n}_acl (doc_id text, principal_kind text, principal_id text, access text);
             INSERT INTO {n}_acl VALUES ('d1', '{}', '{}', 'write'), ('d1', '{}', '{}', 'delete'), ('d1', 'member', 'm_read', 'read');\n",
            w.0, w.1, d.0, d.1
        )
        .expect("fmt::Write for String never fails");
    }
    b
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let rls = sql.emit_rls().expect("the policies compile");
    db.batch_execute(
        "DROP SCHEMA IF EXISTS ga_rows CASCADE; DROP SCHEMA IF EXISTS ga_auth CASCADE;
         CREATE SCHEMA ga_rows; CREATE SCHEMA ga_auth;
         DO $$ BEGIN
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ga_caller') THEN CREATE ROLE ga_caller NOLOGIN; END IF;
         END $$;",
    )
    .expect("fresh schemas");
    db.batch_execute(&format!("SET search_path = ga_rows; {} RESET search_path;", tables())).expect("tables and rows");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql("ga_caller")] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(
        "GRANT USAGE ON SCHEMA ga_rows, ga_auth TO ga_caller;
         GRANT SELECT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ga_rows TO ga_caller;
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ga_auth TO ga_caller;",
    )
    .expect("grants");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Read,
    Update,
    Delete,
}

fn rows(db: &mut Client, table: &str, member: &str, verb: Verb) -> u64 {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("SET LOCAL ROLE ga_caller").expect("the caller role");
    let claims = format!(r#"{{"member_id":"{member}","tenant_id":"t1","project_id":"p1"}}"#);
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let n = match verb {
        Verb::Read => tx.query(&format!("SELECT id FROM ga_rows.{table}s WHERE id = 'd1'"), &[]).expect("the read").len() as u64,
        Verb::Update => tx.execute(&format!("UPDATE ga_rows.{table}s SET status = 'edited' WHERE id = 'd1'"), &[]).expect("the update"),
        Verb::Delete => tx.execute(&format!("DELETE FROM ga_rows.{table}s WHERE id = 'd1'"), &[]).expect("the delete"),
    };
    tx.rollback().expect("rollback");
    n
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn an_admitted_class_reads_and_still_does_only_what_it_was_granted() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect");
    install(&mut db);
    let cases: [(&str, &str, &str, [u64; 3]); 13] = [
        ("wide", "m_write", "a write grant reads, and writes", [1, 1, 0]),
        ("wide", "m_delete", "a delete grant reads, and deletes", [1, 0, 1]),
        ("wide", "m_read", "a read grant reads alone", [1, 0, 0]),
        ("wide", "m_none", "no grant admits nothing", [0, 0, 0]),
        ("wide", "m_owner", "the owner does everything", [1, 1, 1]),
        ("grouped", "m_team_w", "a team's write grant reads, and writes", [1, 1, 0]),
        ("grouped", "m_team_d", "a team's delete grant reads, and deletes", [1, 0, 1]),
        ("grouped", "m_read", "a read grant reads alone", [1, 0, 0]),
        ("grouped", "m_none", "no grant admits nothing", [0, 0, 0]),
        ("exact", "m_write", "without the clause a write grant doesn't read, so it writes nothing", [0, 0, 0]),
        ("exact", "m_delete", "without the clause a delete grant doesn't read, so it deletes nothing", [0, 0, 0]),
        ("exact", "m_read", "a read grant reads alone", [1, 0, 0]),
        ("exact", "m_owner", "the owner does everything", [1, 1, 1]),
    ];
    let mut failures = Vec::new();
    for (table, member, what, want) in cases {
        let got = [Verb::Read, Verb::Update, Verb::Delete].map(|v| rows(&mut db, table, member, v));
        if got != want {
            failures.push(format!("{table} {member}: {what}: read/update/delete gave {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
