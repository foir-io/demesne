use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const CALLER: &str = "demesne_call_caller";

#[derive(Clone, Copy)]
struct Schemas {
    rows: &'static str,
    auth: &'static str,
}

const ANCHORS: &str = "(@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"grant\") and grantee:read)";

fn spec(Schemas { rows, auth }: Schemas) -> String {
    format!(
        "definers schema \"{auth}\"\ntables schema \"{rows}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation edge_slot: member via edge doc_edges(principal_id, object_id) key rule_id slot slot\n  permission view = owner + some r in rules_live prefix \"read.\" held rules_held (every s in rule_slots(rule_id) where role = \"require\" nonempty ({ANCHORS}) and none s in rule_slots(rule_id) where role = \"except\" ({ANCHORS})) @rls maps select\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  relation of: member via object doc->view on doc_id\n  permission view = of @rls maps select\n}}\n"
    )
}

const SLOTS: [(&str, &str, &str, &str); 8] = [
    ("read.one", "1", "edge", "require"),
    ("read.two", "1", "edge", "require"),
    ("read.two", "2", "edge", "require"),
    ("read.bar", "1", "edge", "require"),
    ("read.bar", "2", "edge", "except"),
    ("read.grant", "1", "grant", "require"),
    ("read.both", "1", "edge", "require"),
    ("read.both", "2", "grant", "require"),
];
const DOCS: [(&str, &str, &[&str]); 9] = [
    ("d_none", "ann", &[]),
    ("d_free", "ann", &["read.free"]),
    ("d_one", "ann", &["read.one"]),
    ("d_two", "ann", &["read.two"]),
    ("d_bar", "ann", &["read.bar"]),
    ("d_grant", "ann", &["read.grant"]),
    ("d_both", "ann", &["read.both"]),
    ("d_bobs", "bob", &[]),
    ("d_gone", "ann", &["read.gone"]),
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
const HELD: [&str; 7] = ["read.free", "read.one", "read.two", "read.bar", "read.grant", "read.both", "read.gone"];

fn install(db: &mut Client, at: Schemas) {
    let Schemas { rows, auth } = at;
    let s = demesne_syntax::parse(&spec(at)).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {rows} CASCADE; DROP SCHEMA IF EXISTS {auth} CASCADE; CREATE SCHEMA {rows}; CREATE SCHEMA {auth};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {rows};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, rules_live text[]);
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, doc_id text);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text, slot integer);
         CREATE TABLE doc_acl (doc_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE rule_slots (rule_id text, slot integer, kind text, role text);"
    ))
    .expect("fresh schemas and tables");
    for (id, owner, rules) in DOCS {
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', $2, $3)", &[&id, &owner, &rules.to_vec()]).expect("a doc");
        db.execute("INSERT INTO notes VALUES ($1 || '_note', 'e1', 's1', $1)", &[&id]).expect("its note");
    }
    db.execute("INSERT INTO rule_slots VALUES ('read.gone', 1, 'edge', 'require')", &[]).expect("a declared slot, removed later");
    db.execute("INSERT INTO doc_edges VALUES ('bob', 'd_gone', 'read.gone', 1)", &[]).expect("the edge its slot asks for");
    for (rule, slot, kind, role) in SLOTS {
        db.execute("INSERT INTO rule_slots VALUES ($1, $2::text::integer, $3, $4)", &[&rule, &slot, &kind, &role]).expect("a declared slot");
    }
    for (who, doc, rule, slot) in EDGES {
        db.execute("INSERT INTO doc_edges VALUES ($1, $2, $3, $4::text::integer)", &[&who, &doc, &rule, &slot]).expect("an edge");
    }
    for (who, doc) in GRANTS {
        db.execute("INSERT INTO doc_acl VALUES ($2, 'member', $1, 'read')", &[&who, &doc]).expect("a grant");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {rows}, {auth} TO {CALLER}; GRANT SELECT ON {rows}.docs, {rows}.notes TO {CALLER}; RESET search_path;"))
        .expect("grants");
}

fn claims(who: &str, estate: &str, held: &[&str]) -> String {
    let list: Vec<String> = held.iter().map(|h| format!("\"{h}\"")).collect();
    format!("{{\"sub\":\"{who}\",\"estate_id\":\"{estate}\",\"space_id\":\"s1\",\"rules_held\":[{}]}}", list.join(","))
}

fn read_as(db: &mut Client, setting: &str, query: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&setting]).expect("the claims");
    let ids = tx.query(query, &[]).unwrap_or_else(|e| panic!("{query} under {setting:?}: {e}")).iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

fn docs(db: &mut Client, at: Schemas, setting: &str) -> BTreeSet<String> {
    read_as(db, setting, &format!("SELECT id FROM {}.docs", at.rows))
}

fn docs_through_notes(db: &mut Client, at: Schemas, setting: &str) -> BTreeSet<String> {
    read_as(db, setting, &format!("SELECT doc_id FROM {}.notes", at.rows))
}

fn asked(db: &mut Client, at: Schemas, setting: &str, doc: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&setting]).expect("the claims");
    let admitted: bool =
        tx.query_one(&format!("SELECT {}.doc_can_view($1)", at.auth), &[&doc]).unwrap_or_else(|e| panic!("doc_can_view({doc}) under {setting:?}: {e}")).get(0);
    tx.rollback().expect("rollback");
    admitted
}

fn connect() -> Client {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the per-call definer checks against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_borrowed_permission_read_once_a_call_admits_what_its_policy_admits_and_refuses_what_it_refuses() {
    let at = Schemas { rows: "demesne_call_grid_rows", auth: "demesne_call_grid_auth" };
    let mut db = connect();
    install(&mut db, at);
    let callers = ["ann", "bob", "cat", "dan", "eve"]
        .into_iter()
        .flat_map(|who| ["e1", "e2"].into_iter().flat_map(move |estate| [&HELD[..], &HELD[..3], &HELD[3..], &[]].map(|held| (who, estate, held))));
    let (mut admitted, mut refused, mut wrong) = (0, 0, Vec::new());
    for (who, estate, held) in callers {
        let setting = claims(who, estate, held);
        let (direct, borrowed) = (docs(&mut db, at, &setting), docs_through_notes(&mut db, at, &setting));
        admitted += borrowed.len();
        refused += DOCS.len() - borrowed.len();
        if direct != borrowed {
            wrong.push(format!("{who} in {estate} holding {held:?}: the policy reads {direct:?}, the borrow {borrowed:?}"));
        }
    }
    assert!(wrong.is_empty(), "{} disagreements:\n{}", wrong.len(), wrong.join("\n"));
    assert!(admitted > 20 && refused > 100, "the grid both admits and refuses through the borrow: {admitted} admitted, {refused} refused");
    let mut through = |who: &str, estate: &str| docs_through_notes(&mut db, at, &claims(who, estate, &HELD));
    let bob = through("bob", "e1");
    for (doc, want, why) in [
        ("d_one", true, "its one declared edge"),
        ("d_two", true, "both declared edges"),
        ("d_bar", true, "the required edge, and the excepted one is cat's"),
        ("d_grant", true, "a declared grant"),
        ("d_both", false, "the edge without the grant"),
        ("d_free", false, "an element that declares no row admits nobody"),
        ("d_bobs", true, "his own"),
        ("d_gone", true, "the edge its slot asks for, while the slot is declared"),
    ] {
        assert_eq!(bob.contains(doc), want, "bob on {doc}: {why}");
    }
    let cat = through("cat", "e1");
    assert!(!cat.contains("d_bar"), "the excepted edge refuses cat: {cat:?}");
    assert!(cat.contains("d_both"), "an edge and a grant, both declared: {cat:?}");
    assert!(through("bob", "e2").is_empty(), "another estate's claims reach nothing");
    db.batch_execute(&format!("DELETE FROM {}.rule_slots WHERE rule_id = 'read.gone'", at.rows)).expect("the slot removed");
    assert!(!docs_through_notes(&mut db, at, &claims("bob", "e1", &HELD)).contains("d_gone"), "an element whose declared rows are gone admits nobody");
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA {} CASCADE;", at.rows, at.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_definer_answers_by_the_claims_of_its_own_call_and_by_none_when_the_setting_is_empty() {
    let at = Schemas { rows: "demesne_call_ask_rows", auth: "demesne_call_ask_auth" };
    let mut db = connect();
    install(&mut db, at);
    assert!(asked(&mut db, at, &claims("bob", "e1", &HELD), "d_one"), "bob holds the edge d_one declares");
    assert!(!asked(&mut db, at, &claims("cat", "e1", &HELD), "d_one"), "cat holds none");
    assert!(!asked(&mut db, at, &claims("bob", "e1", &[]), "d_one"), "an element the claims don't hold is not tried");
    assert!(!asked(&mut db, at, &claims("bob", "e2", &HELD), "d_one"), "another estate's claims");
    assert!(asked(&mut db, at, &claims("ann", "e1", &[]), "d_none"), "the owner by her own term");
    for setting in ["", "{}"] {
        for (doc, _, _) in DOCS {
            assert!(!asked(&mut db, at, setting, doc), "{doc} under the setting {setting:?}: no claims admit nothing");
        }
    }
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA {} CASCADE;", at.rows, at.auth)).expect("drop the schemas");
}
