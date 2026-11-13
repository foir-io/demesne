use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_decl_rows";
const AUTH: &str = "demesne_decl_auth";
const CALLER: &str = "demesne_decl_caller";

const ANCHORS: &str = "(@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"grant\") and grantee:read) + (@slot(kind, \"borrow\") and borrow)";

fn spec() -> String {
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation edge_slot: member via edge doc_edges(principal_id, object_id) key rule_id slot slot\n  relation borrow: member via composition doc_reads(descendant_id, ancestor_id) slot first_field from param\n  permission view = owner + some r in rules_live prefix \"read.\" held rules_held (every s in rule_slots(rule_id) where role = \"require\" ({ANCHORS}) and none s in rule_slots(rule_id) where role = \"except\" ({ANCHORS})) @rls maps select\n}}\n"
    )
}

const SLOTS: [(&str, &str, &str, &str, &str); 9] = [
    ("read.one", "1", "edge", "", "require"),
    ("read.two", "1", "edge", "", "require"),
    ("read.two", "2", "edge", "", "require"),
    ("read.bar", "1", "edge", "", "require"),
    ("read.bar", "2", "edge", "", "except"),
    ("read.grant", "1", "grant", "", "require"),
    ("read.team", "1", "borrow", "team", "require"),
    ("read.both", "1", "edge", "", "require"),
    ("read.both", "2", "grant", "", "require"),
];
const DOCS: [(&str, &[&str]); 10] = [
    ("d_none", &[]),
    ("d_free", &["read.free"]),
    ("d_one", &["read.one"]),
    ("d_two", &["read.two"]),
    ("d_bar", &["read.bar"]),
    ("d_grant", &["read.grant"]),
    ("d_team", &["read.team"]),
    ("d_both", &["read.both"]),
    ("d_chain", &["read.team"]),
    ("d_wrong_field", &["read.team"]),
];
const EDGES: [(&str, &str, &str, &str); 9] = [
    ("bob", "d_one", "read.one", "1"),
    ("bob", "d_two", "read.two", "1"),
    ("bob", "d_two", "read.two", "2"),
    ("cat", "d_two", "read.two", "2"),
    ("bob", "d_bar", "read.bar", "1"),
    ("cat", "d_bar", "read.bar", "1"),
    ("cat", "d_bar", "read.bar", "2"),
    ("bob", "d_both", "read.both", "1"),
    ("cat", "d_both", "read.both", "1"),
];
const GRANTS: [(&str, &str); 3] = [("bob", "d_grant"), ("cat", "d_both"), ("dan", "d_both")];
const HOPS: [(&str, &str, &str); 4] =
    [("d_team", "d_one", "team"), ("d_team", "d_two", "project"), ("d_chain", "d_team", "team"), ("d_wrong_field", "d_one", "project")];
const ALL: [&str; 7] = ["read.free", "read.one", "read.two", "read.bar", "read.grant", "read.team", "read.both"];

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, rules_live text[]);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text, slot integer);
         CREATE TABLE doc_acl (doc_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE doc_reads (descendant_id text, ancestor_id text, first_field text);
         CREATE TABLE rule_slots (rule_id text, slot integer, kind text, param text, role text);"
    ))
    .expect("fresh schemas and tables");
    for (id, rules) in DOCS {
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', 'ann', $2)", &[&id, &rules.to_vec()]).expect("a doc");
    }
    for (rule, slot, kind, param, role) in SLOTS {
        db.execute("INSERT INTO rule_slots VALUES ($1, $2::text::integer, $3, $4, $5)", &[&rule, &slot, &kind, &param, &role]).expect("a declared slot");
    }
    for (who, doc, rule, slot) in EDGES {
        db.execute("INSERT INTO doc_edges VALUES ($1, $2, $3, $4::text::integer)", &[&who, &doc, &rule, &slot]).expect("an edge");
    }
    for (who, doc) in GRANTS {
        db.execute("INSERT INTO doc_acl VALUES ($2, 'member', $1, 'read')", &[&who, &doc]).expect("a grant");
    }
    for (from, to, field) in HOPS {
        db.execute("INSERT INTO doc_reads VALUES ($1, $2, $3)", &[&from, &to, &field]).expect("a hop");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON {ROWS}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};"))
        .expect("grants");
}

type Slot = (&'static str, &'static str, &'static str, &'static str, &'static str);

#[derive(Clone, Copy)]
struct Caller<'a> {
    who: &'a str,
    held: &'a [&'a str],
}

fn slot_matches(c: Caller, doc: &str, (rule, slot, kind, param, _): &Slot, hop: bool) -> bool {
    match *kind {
        "edge" => EDGES.contains(&(c.who, doc, rule, slot)),
        "grant" => GRANTS.contains(&(c.who, doc)),
        "borrow" => hop && HOPS.iter().any(|(from, to, field)| *from == doc && field == param && reads(c, to, false)),
        _ => false,
    }
}

fn reads(c: Caller, doc: &str, hop: bool) -> bool {
    if c.who == "ann" {
        return true;
    }
    let rules = DOCS.iter().find(|(id, _)| *id == doc).expect("the doc").1;
    rules.iter().filter(|r| c.held.contains(r)).any(|rule| {
        let declared = |role: &'static str| SLOTS.iter().filter(move |s| s.0 == *rule && s.4 == role);
        declared("require").all(|s| slot_matches(c, doc, s, hop)) && !declared("except").any(|s| slot_matches(c, doc, s, hop))
    })
}

fn visible(db: &mut Client, who: &str, held: &[&str]) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let list: Vec<String> = held.iter().map(|h| format!("\"{h}\"")).collect();
    let claims = format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\",\"rules_held\":[{}]}}", list.join(","));
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let ids = tx.query("SELECT id FROM docs", &[]).expect("the read").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn every_declared_row_must_match_and_no_excepted_one_may() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut failures = Vec::new();
    let (mut admitted, mut refused) = (0, 0);
    for who in ["ann", "bob", "cat", "dan", "eve"] {
        for held in [&ALL[..], &ALL[..2], &ALL[2..5], &[]] {
            let want: BTreeSet<String> = DOCS.iter().filter(|(id, _)| reads(Caller { who, held }, id, true)).map(|(id, _)| (*id).to_string()).collect();
            let got = visible(&mut db, who, held);
            admitted += got.len();
            refused += DOCS.len() - got.len();
            if got != want {
                failures.push(format!("{who} holding {held:?} reads {got:?}, want {want:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(admitted > 20 && refused > 20, "the grid both admits and refuses: {admitted} admitted, {refused} refused");
    for (who, doc, want, why) in [
        ("eve", "d_free", true, "an element that declares nothing is not held back"),
        ("eve", "d_none", false, "a row with no element binds nothing"),
        ("bob", "d_one", true, "the one declared edge"),
        ("bob", "d_two", true, "both declared edges"),
        ("cat", "d_two", false, "one of two declared edges"),
        ("bob", "d_bar", true, "the required edge and no excepted one"),
        ("cat", "d_bar", false, "the required edge and the excepted one"),
        ("bob", "d_grant", true, "a declared grant"),
        ("cat", "d_both", true, "an edge and a grant, both declared"),
        ("bob", "d_both", false, "the edge without the grant"),
        ("dan", "d_both", false, "the grant without the edge"),
        ("bob", "d_team", true, "a borrow through the declared field to a row the caller reads"),
        ("cat", "d_team", false, "a hop exists only through another field"),
        ("bob", "d_wrong_field", false, "a hop to a row the caller reads, through a field the slot does not declare"),
        ("bob", "d_chain", false, "the ancestor admits only through its own borrow, which one hop does not follow"),
    ] {
        assert_eq!(visible(&mut db, who, &ALL).contains(doc), want, "{who} on {doc}: {why}");
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
