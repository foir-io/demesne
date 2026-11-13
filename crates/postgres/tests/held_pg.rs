use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_held_rows";
const AUTH: &str = "demesne_held_auth";
const CALLER: &str = "demesne_held_caller";

const SPEC: &str = "topology { level estate level space parent estate }\nvocabulary staff { permission docs:read permission docs:write implies docs:read permission docs:audit }\nrolestore staff {\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n  held claim held_verbs\n}\nsubject staff { anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }\nobject doc {\n  table docs\n  scoped estate > space wildcard\n  permission view = @holds(docs:read) @rls maps select\n  permission edit = @holds(docs:write) @rls maps update\n}\nobject ledger {\n  table ledgers\n  scoped estate\n  permission view = @holds(docs:read) @rls maps select\n  permission edit = @holds(docs:write) @rls maps update\n}\n";

const DOCS: [(&str, &str, Option<&str>); 5] =
    [("e1_s1", "e1", Some("s1")), ("e1_s2", "e1", Some("s2")), ("e1_shared", "e1", None), ("e2_s9", "e2", Some("s9")), ("e2_shared", "e2", None)];
const LEDGERS: [(&str, &str); 2] = [("l_e1", "e1"), ("l_e2", "e2")];

#[derive(Debug, Clone, Copy)]
struct Session {
    estate: Option<&'static str>,
    space: Option<&'static str>,
    held: &'static str,
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
         CREATE TABLE role_grants (grantee_id text, estate_id text, space_id text, role_id text);
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text);
         CREATE TABLE ledgers (id text PRIMARY KEY, estate_id text);
         INSERT INTO roles VALUES ('writer', 'writer', ARRAY['docs:write']);
         INSERT INTO role_grants VALUES ('assigned', 'e1', 's2', 'writer');"
    ))
    .expect("fresh schemas and tables");
    for (id, estate, space) in DOCS {
        db.execute("INSERT INTO docs VALUES ($1, $2, $3)", &[&id, &estate, &space]).expect("a doc");
    }
    for (id, estate) in LEDGERS {
        db.execute("INSERT INTO ledgers VALUES ($1, $2)", &[&id, &estate]).expect("a ledger");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, UPDATE ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};"))
        .expect("grants");
}

fn rows(db: &mut Client, who: &str, s: Session, table: &str, update: bool) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let field = |k: &str, v: Option<&str>| v.map(|v| format!(",\"{k}\":\"{v}\"")).unwrap_or_default();
    let claims = format!("{{\"sub\":\"{who}\"{}{},\"held_verbs\":{}}}", field("estate_id", s.estate), field("space_id", s.space), s.held);
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let sql = if update { format!("UPDATE {table} SET id = id RETURNING id") } else { format!("SELECT id FROM {table}") };
    let ids = tx.query(&sql, &[]).expect("the statement").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

fn carries(held: &str, write: bool) -> bool {
    held.starts_with('[') && (held.contains("\"docs:write\"") || (!write && held.contains("\"docs:read\"")))
}

#[derive(Clone, Copy)]
enum Place {
    Estate,
    Space(Option<&'static str>),
}

fn stands_at(s: Session, estate: &str, place: Place) -> bool {
    let top = s.estate == Some(estate);
    match place {
        Place::Estate => top && s.space.is_none(),
        Place::Space(row) => top && s.space.is_none_or(|c| row == Some(c)),
    }
}

fn contained(s: Session, estate: &str, space: Option<&str>) -> bool {
    s.estate == Some(estate) && space.is_none_or(|row| s.space == Some(row))
}

fn wrong_answers(db: &mut Client, s: Session, update: bool, seen: &mut BTreeSet<bool>) -> Vec<String> {
    let verb = carries(s.held, update);
    let docs = DOCS.iter().filter(|(_, e, sp)| verb && contained(s, e, *sp) && stands_at(s, e, Place::Space(*sp))).map(|d| d.0.to_string()).collect();
    let ledgers = LEDGERS.iter().filter(|(_, e)| verb && contained(s, e, None) && stands_at(s, e, Place::Estate)).map(|l| l.0.to_string()).collect();
    let mut wrong = Vec::new();
    for (table, want) in [("docs", docs), ("ledgers", ledgers)] {
        let want: BTreeSet<String> = want;
        let got = rows(db, "key", s, table, update);
        seen.insert(got.is_empty());
        wrong.extend((got != want).then(|| format!("{s:?} {} {table}: got {got:?}, want {want:?}", if update { "updates" } else { "reads" })));
    }
    wrong
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_held_verb_reaches_what_an_assignment_at_the_sessions_place_reaches_and_no_further() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the held-verb checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let helds = ["[\"docs:write\"]", "[\"docs:read\"]", "[\"docs:audit\"]", "[]", "\"docs:write\"", "null", "{\"docs:write\":true}"];
    let places = [(Some("e1"), Some("s1")), (Some("e1"), None), (Some("e2"), Some("s9")), (None, Some("s1")), (None, None)];
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for held in helds {
        for (estate, space) in places {
            let s = Session { estate, space, held };
            for update in [false, true] {
                failures.extend(wrong_answers(&mut db, s, update, &mut seen));
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(seen.len(), 2, "the grid both admits and refuses");
    let at = |estate, space, held| Session { estate, space, held };
    let own = |ids: &[&str]| -> BTreeSet<String> { ids.iter().map(|i| (*i).to_string()).collect() };
    assert_eq!(
        rows(&mut db, "key", at(Some("e1"), Some("s1"), "[\"docs:write\"]"), "docs", true),
        own(&["e1_s1"]),
        "a session in a space never writes the row shared by every space"
    );
    assert_eq!(
        rows(&mut db, "key", at(Some("e1"), None, "[\"docs:write\"]"), "docs", false),
        own(&["e1_shared"]),
        "a session at the estate holds its verb on what its containment shows it"
    );
    assert_eq!(
        rows(&mut db, "key", at(Some("e1"), Some("s1"), "[\"docs:write\"]"), "ledgers", false),
        own(&[]),
        "an estate table is not held from inside a space"
    );
    assert_eq!(
        rows(&mut db, "key", at(Some("e1"), Some("s1"), "[\"docs:write\"]"), "docs", false),
        own(&["e1_s1"]),
        "a held write verb reads, by the vocabulary's implication"
    );
    assert_eq!(
        rows(&mut db, "assigned", at(Some("e1"), Some("s2"), "[]"), "docs", true),
        own(&["e1_s2"]),
        "an assignment still decides for a caller who carries no verb"
    );
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
