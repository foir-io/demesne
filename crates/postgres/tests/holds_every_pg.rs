use postgres::error::SqlState;
use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_he_rows";
const AUTH: &str = "demesne_he_auth";
const CALLER: &str = "demesne_he_caller";

const SPEC: &str = "topology { level estate level space parent estate }\nvocabulary staff { permission invites:read permission invites:write implies invites:read }\nrolestore staff {\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n}\nsubject staff { anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }\nobject space {\n  table spaces\n  level space\n  scoped estate > space\n  permission view = @holds(invites:read) @rls maps select\n}\nobject invite {\n  table invites\n  scoped estate\n  permission view   = @holds(invites:read every space_ids at space)  @rls maps select\n  permission create = @holds(invites:write every space_ids at space) @rls maps insert\n  permission edit   = @holds(invites:write every space_ids at space) @rls maps update\n  permission delete = @holds(invites:write every space_ids at space) @rls maps delete\n}\n";

const SPACES: [(&str, &str); 4] = [("s1", "e1"), ("s2", "e1"), ("s3", "e1"), ("x1", "e2")];
const GRANTS: [(&str, &str, Option<&str>, &str); 7] = [
    ("u_estate", "e1", None, "writer"),
    ("u_s1", "e1", Some("s1"), "writer"),
    ("u_s12", "e1", Some("s1"), "writer"),
    ("u_s12", "e1", Some("s2"), "writer"),
    ("u_mixed", "e1", Some("s1"), "writer"),
    ("u_mixed", "e1", Some("s2"), "reader"),
    ("u_far", "e2", None, "writer"),
];
const ARRAYS: [(&str, Option<&[Option<&str>]>); 9] = [
    ("null", None),
    ("empty", Some(&[])),
    ("s1", Some(&[Some("s1")])),
    ("s1_s2", Some(&[Some("s1"), Some("s2")])),
    ("s1_s3", Some(&[Some("s1"), Some("s3")])),
    ("s1_missing", Some(&[Some("s1"), Some("s9")])),
    ("s1_foreign", Some(&[Some("s1"), Some("x1")])),
    ("s1_hole", Some(&[Some("s1"), None])),
    ("s1_twice", Some(&[Some("s1"), Some("s1")])),
];

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let rls = sql.emit_rls().expect("the policies compile");
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
         CREATE TABLE role_grants (grantee_id text, estate_id text, space_id text, role_id text);
         CREATE TABLE spaces (id text PRIMARY KEY, estate_id text);
         CREATE TABLE invites (id text PRIMARY KEY, estate_id text, space_ids text[]);
         INSERT INTO roles VALUES ('writer', 'writer', ARRAY['invites:write']), ('reader', 'reader', ARRAY['invites:read']);"
    ))
    .expect("fresh schemas and tables");
    for (id, estate) in SPACES {
        db.execute("INSERT INTO spaces VALUES ($1, $2)", &[&id, &estate]).expect("a space");
    }
    for (who, estate, space, role) in GRANTS {
        db.execute("INSERT INTO role_grants VALUES ($1, $2, $3, $4)", &[&who, &estate, &space, &role]).expect("a role grant");
    }
    for (id, ids) in ARRAYS {
        db.execute("INSERT INTO invites VALUES ($1, 'e1', $2)", &[&id, &ids.map(<[_]>::to_vec)]).expect("an invite");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};"
    ))
    .expect("grants");
}

fn holds(who: &str, estate: &str, space: &str, write: bool) -> bool {
    GRANTS.iter().any(|(g, e, s, role)| *g == who && *e == estate && s.is_none_or(|s| s == space) && (*role == "writer" || !write))
}

fn holds_at_every(who: &str, ids: Option<&[Option<&str>]>, write: bool) -> bool {
    let Some(ids) = ids else { return false };
    !ids.is_empty() && ids.iter().all(|id| id.is_some_and(|id| SPACES.contains(&(id, "e1")) && holds(who, "e1", id, write)))
}

fn attempts(db: &mut Client, who: &str, id: &str, ids: Option<&[Option<&str>]>) -> [bool; 4] {
    let run = |db: &mut Client, sql: &str, inserting: bool| -> bool {
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
        tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\"}}")]).expect("the claims");
        let done = if inserting {
            match tx.execute(sql, &[&format!("new_{id}"), &ids.map(<[_]>::to_vec)]) {
                Ok(n) => n == 1,
                Err(e) if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) => false,
                Err(e) => panic!("{sql}: {e}"),
            }
        } else {
            tx.query(sql, &[&id]).expect("the statement").len() == 1
        };
        tx.rollback().expect("rollback");
        done
    };
    [
        run(db, "SELECT id FROM invites WHERE id = $1", false),
        run(db, "INSERT INTO invites VALUES ($1, 'e1', $2)", true),
        run(db, "UPDATE invites SET id = id WHERE id = $1 RETURNING id", false),
        run(db, "DELETE FROM invites WHERE id = $1 RETURNING id", false),
    ]
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_permission_held_at_every_value_of_an_array_admits_and_one_missing_refuses() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the array checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut failures = Vec::new();
    let mut seen: [BTreeSet<bool>; 4] = Default::default();
    for who in ["u_estate", "u_s1", "u_s12", "u_mixed", "u_far", "u_nobody"] {
        for (id, ids) in ARRAYS {
            let (read, write) = (holds_at_every(who, ids, false), holds_at_every(who, ids, true));
            let want = [read, write, write, write];
            let got = attempts(&mut db, who, id, ids);
            for (i, answer) in got.iter().enumerate() {
                seen[i].insert(*answer);
            }
            if got != want {
                failures.push(format!("{who} on {id}: select/insert/update/delete gave {got:?}, want {want:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(seen.iter().all(|outcomes| outcomes.len() == 2), "every operation was both admitted and refused: {seen:?}");
    assert!(
        holds_at_every("u_mixed", ARRAYS[3].1, false) && !holds_at_every("u_mixed", ARRAYS[3].1, true),
        "the grid holds a caller who reads a pair and cannot write it"
    );
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
