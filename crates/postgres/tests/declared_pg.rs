use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_decl_rows";
const AUTH: &str = "demesne_decl_auth";
const CALLER: &str = "demesne_decl_caller";

const ANCHORS: &str = "(@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"grant\") and grantee:read) + (@slot(kind, \"borrow\") and borrow)";

fn spec() -> String {
    spec_with("", ROWS, AUTH)
}

fn spec_with(counted: &str, rows: &str, auth: &str) -> String {
    spec_from("rule_slots(rule_id)", counted, rows, auth)
}

fn spec_from(source: &str, counted: &str, rows: &str, auth: &str) -> String {
    format!(
        "definers schema \"{auth}\"\ntables schema \"{rows}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation edge_slot: member via edge doc_edges(principal_id, object_id) key rule_id slot slot\n  relation borrow: member via composition doc_reads(descendant_id, ancestor_id) slot first_field from param\n  permission view = owner + some r in rules_live prefix \"read.\" held rules_held (every s in {source} where role = \"require\"{counted} ({ANCHORS}) and none s in {source} where role = \"except\" ({ANCHORS})) @rls maps select\n}}\n"
    )
}

const SLOTS: [(&str, &str, &str, &str, &str); 11] = [
    ("read.one", "1", "edge", "", "require"),
    ("read.two", "1", "edge", "", "require"),
    ("read.two", "2", "edge", "", "require"),
    ("read.bar", "1", "edge", "", "require"),
    ("read.bar", "2", "edge", "", "except"),
    ("read.grant", "1", "grant", "", "require"),
    ("read.team", "1", "borrow", "team", "require"),
    ("read.both", "1", "edge", "", "require"),
    ("read.both", "2", "grant", "", "require"),
    ("read.xb", "1", "edge", "", "require"),
    ("read.xb", "2", "borrow", "team", "except"),
];
const DOCS: [(&str, &[&str]); 12] = [
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
    ("d_xb", &["read.xb"]),
    ("d_under_xb", &["read.team"]),
];
const EDGES: [(&str, &str, &str, &str); 10] = [
    ("bob", "d_one", "read.one", "1"),
    ("bob", "d_two", "read.two", "1"),
    ("bob", "d_two", "read.two", "2"),
    ("cat", "d_two", "read.two", "2"),
    ("bob", "d_bar", "read.bar", "1"),
    ("cat", "d_bar", "read.bar", "1"),
    ("cat", "d_bar", "read.bar", "2"),
    ("bob", "d_both", "read.both", "1"),
    ("cat", "d_both", "read.both", "1"),
    ("bob", "d_xb", "read.xb", "1"),
];
const GRANTS: [(&str, &str); 3] = [("bob", "d_grant"), ("cat", "d_both"), ("dan", "d_both")];
const HOPS: [(&str, &str, &str); 5] = [
    ("d_team", "d_one", "team"),
    ("d_team", "d_two", "project"),
    ("d_chain", "d_team", "team"),
    ("d_wrong_field", "d_one", "project"),
    ("d_under_xb", "d_xb", "team"),
];
const ALL: [&str; 8] = ["read.free", "read.one", "read.two", "read.bar", "read.grant", "read.team", "read.both", "read.xb"];

fn install(db: &mut Client) {
    install_as(db, &spec(), ROWS, AUTH);
}

fn install_as(db: &mut Client, src: &str, rows_schema: &str, auth_schema: &str) {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {rows_schema} CASCADE; DROP SCHEMA IF EXISTS {auth_schema} CASCADE; CREATE SCHEMA {rows_schema}; CREATE SCHEMA {auth_schema};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {rows_schema};
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
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {rows_schema}, {auth_schema} TO {CALLER}; GRANT SELECT ON {rows_schema}.docs TO {CALLER};"))
        .expect("grants");
}

type Slot = (&'static str, &'static str, &'static str, &'static str, &'static str);

#[derive(Clone, Copy)]
struct Caller<'a> {
    who: &'a str,
    held: &'a [&'a str],
}

fn slot_matches(c: Caller, doc: &str, (element, slot, kind, param, role): &Slot, hop: bool) -> bool {
    match *kind {
        "edge" => EDGES.contains(&(c.who, doc, element, slot)),
        "grant" => GRANTS.contains(&(c.who, doc)),
        "borrow" if hop => HOPS.iter().any(|(from, to, field)| *from == doc && field == param && reads(c, to, false)),
        "borrow" => *role == "except",
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
        ("bob", "d_xb", true, "the required edge, and an excepted borrow that reaches nothing"),
        ("bob", "d_under_xb", false, "its ancestor declares an exception one hop cannot rule out, so the ancestor is judged barred"),
        ("bob", "d_chain", false, "the ancestor admits only through its own borrow, which one hop does not follow"),
    ] {
        assert_eq!(visible(&mut db, who, &ALL).contains(doc), want, "{who} on {doc}: {why}");
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_nonempty_every_admits_by_no_element_whose_declared_rows_are_none_or_gone() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let (rows, auth) = ("demesne_decl_nonempty_rows", "demesne_decl_nonempty_auth");
    let src = spec_with(" nonempty", rows, auth);
    assert!(src.contains("where role = \"require\" nonempty ("), "{src}");
    install_as(&mut db, &src, rows, auth);
    for (who, doc, want, why) in [
        ("eve", "d_free", false, "an element that declares no row admits nobody"),
        ("bob", "d_free", false, "nor anyone who meets what every other element requires"),
        ("bob", "d_one", true, "its one declared edge"),
        ("bob", "d_two", true, "both declared edges"),
        ("cat", "d_two", false, "one of two declared edges"),
        ("ann", "d_free", true, "the owner reads it by its own term"),
    ] {
        assert_eq!(visible(&mut db, who, &ALL).contains(doc), want, "{who} on {doc}: {why}");
    }
    db.batch_execute(&format!("DELETE FROM {rows}.rule_slots WHERE rule_id = 'read.one'")).expect("the rows removed");
    assert!(!visible(&mut db, "bob", &ALL).contains("d_one"), "an element whose declared rows are gone admits nobody");
    assert!(visible(&mut db, "bob", &ALL).contains("d_two"), "another element's rows still decide");
    assert!(visible(&mut db, "ann", &ALL).contains("d_one"), "the owner still reads it");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {rows} CASCADE; DROP SCHEMA {auth} CASCADE;")).expect("drop the schemas");
}

fn claims_of(who: &str) -> String {
    let list: Vec<String> = ALL.iter().map(|h| format!("\"{h}\"")).collect();
    format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\",\"rules_held\":[{}]}}", list.join(","))
}

fn named(db: &mut Client, auth: &str, doc: &str) -> (BTreeSet<String>, bool) {
    let rows =
        db.query(&format!("SELECT principal_id FROM {auth}.docs_accessors_conditional($1)"), &[&doc]).unwrap_or_else(|e| panic!("the listing of {doc}: {e}"));
    let ids: Vec<Option<String>> = rows.iter().map(|r| r.get(0)).collect();
    (ids.iter().flatten().cloned().collect(), ids.iter().any(Option::is_none))
}

fn admitted(db: &mut Client, auth: &str, doc: &str, who: &str) -> bool {
    db.query_one(&format!("SELECT {auth}.docs_admits($1, $2::text::jsonb)"), &[&doc, &claims_of(who)])
        .unwrap_or_else(|e| panic!("admits {who} on {doc}: {e}"))
        .get(0)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_reader_listing_names_the_grantees_an_every_admits_through_and_admits_decides_each() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let (rows, auth) = ("demesne_decl_listing_rows", "demesne_decl_listing_auth");
    install_as(&mut db, &spec_with(" nonempty", rows, auth), rows, auth);

    let (both, rest) = named(&mut db, auth, "d_both");
    assert!(both.contains("cat") && both.contains("dan"), "the grant shape's grantees are named on the row its element binds: {both:?}");
    assert!(rest, "the edge and borrow shapes can't be named through, so one row admits every caller it binds");
    assert!(admitted(&mut db, auth, "d_both", "cat"), "cat holds the grant and the edge both declared rows require");
    assert!(!admitted(&mut db, auth, "d_both", "dan"), "dan is named by the grant shape, yet lacks the edge the other declared row requires");
    assert!(visible(&mut db, "cat", &ALL).contains("d_both") && !visible(&mut db, "dan", &ALL).contains("d_both"), "as the policy decides");

    let (grant, _) = named(&mut db, auth, "d_grant");
    assert!(grant.contains("bob"), "bob's grant is named where its element binds: {grant:?}");
    assert!(admitted(&mut db, auth, "d_grant", "bob"), "and admitted");
    let (one, _) = named(&mut db, auth, "d_one");
    assert!(!one.contains("dan") && !one.contains("cat"), "no grantee of another row is named on one whose element declares an edge alone: {one:?}");
    assert!(!admitted(&mut db, auth, "d_one", "dan"), "nor admitted there");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {rows} CASCADE; DROP SCHEMA {auth} CASCADE;")).expect("drop the schemas");
}

fn minted(without: &[&str]) -> String {
    let mut by: std::collections::BTreeMap<&str, Vec<String>> = std::collections::BTreeMap::new();
    for (element, slot, kind, param, role) in SLOTS.iter().filter(|s| !without.contains(&s.0)) {
        by.entry(element).or_default().push(format!("{{\"slot\":{slot},\"kind\":\"{kind}\",\"param\":\"{param}\",\"role\":\"{role}\"}}"));
    }
    let entries: Vec<String> = by.iter().map(|(element, rows)| format!("\"{element}\":[{}]", rows.join(","))).collect();
    format!("{{{}}}", entries.join(","))
}

fn claims_with(who: &str, held: &[&str]) -> String {
    let list: Vec<String> = held.iter().map(|h| format!("\"{h}\"")).collect();
    format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\",\"rules_held\":[{}]}}", list.join(","))
}

fn under<T>(
    db: &mut Client,
    claims: &str,
    slots: Option<&str>,
    run: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<T, postgres::Error>,
) -> Result<T, String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    if let Some(slots) = slots {
        tx.execute("SELECT set_config('request.rule_slots', $1, true)", &[&slots]).expect("the declared rows");
    }
    let out = run(&mut tx).map_err(|e| e.as_db_error().map_or_else(|| e.to_string(), |d| d.message().to_string()));
    tx.rollback().expect("rollback");
    out
}

fn read_under(db: &mut Client, claims: &str, slots: Option<&str>) -> Result<BTreeSet<String>, String> {
    under(db, claims, slots, |tx| tx.query("SELECT id FROM docs", &[]).map(|rows| rows.iter().map(|r| r.get(0)).collect()))
}

fn admits_under(db: &mut Client, auth: &str, doc: &str, claims: &str, slots: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    tx.execute("SELECT set_config('request.rule_slots', $1, true)", &[&slots]).expect("the declared rows");
    let admitted = tx
        .query_one(&format!("SELECT {auth}.docs_admits($1, $2::text::jsonb)"), &[&doc, &claims])
        .unwrap_or_else(|e| panic!("admits on {doc} under {claims}: {e}"))
        .get(0);
    tx.rollback().expect("rollback");
    admitted
}

const TABLE_SCHEMAS: (&str, &str) = ("demesne_decl_table_rows", "demesne_decl_table_auth");
const SETTING_SCHEMAS: (&str, &str) = ("demesne_decl_setting_rows", "demesne_decl_setting_auth");

fn setting_against_table(db: &mut Client, counted: &str, c: Caller, slots: &str) -> (usize, Vec<String>) {
    let Caller { who, held } = c;
    let claims = claims_with(who, held);
    db.batch_execute(&format!("SET search_path = {}", TABLE_SCHEMAS.0)).expect("the table's schema");
    let want = read_under(db, &claims, Some(slots)).expect("the table's read");
    db.batch_execute(&format!("SET search_path = {}", SETTING_SCHEMAS.0)).expect("the setting's schema");
    let got = read_under(db, &claims, Some(slots)).expect("the setting's read");
    let mut wrong = Vec::new();
    if got != want {
        wrong.push(format!("{who}{counted} holding {held:?}: the setting admits {got:?}, the table {want:?}"));
    }
    let modelled: BTreeSet<String> = DOCS.iter().filter(|(id, _)| reads(c, id, true)).map(|(id, _)| (*id).to_string()).collect();
    if counted.is_empty() && got != modelled {
        wrong.push(format!("{who} holding {held:?}: the setting admits {got:?}, the model {modelled:?}"));
    }
    for (doc, _) in DOCS.iter().filter(|(doc, _)| admits_under(db, SETTING_SCHEMAS.1, doc, &claims, slots) != got.contains(*doc)) {
        wrong.push(format!("{who}{counted} holding {held:?}: the point check on {doc} disagrees with the policy"));
    }
    (got.len(), wrong)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_setting_scope_answers_as_the_table_its_rows_were_minted_from() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let ((table_rows, table_auth), (setting_rows, setting_auth)) = (TABLE_SCHEMAS, SETTING_SCHEMAS);
    let slots = minted(&[]);
    let mut failures = Vec::new();
    let (mut admitted, mut refused) = (0, 0);
    for counted in ["", " nonempty"] {
        let setting_spec = spec_from("setting rule_slots", counted, setting_rows, setting_auth);
        assert!(setting_spec.contains(&format!("every s in setting rule_slots where role = \"require\"{counted} (")), "{setting_spec}");
        install_as(&mut db, &spec_with(counted, table_rows, table_auth), table_rows, table_auth);
        install_as(&mut db, &setting_spec, setting_rows, setting_auth);
        for who in ["ann", "bob", "cat", "dan", "eve"] {
            for held in [&ALL[..], &ALL[..2], &ALL[2..5], &[]] {
                let (read, wrong) = setting_against_table(&mut db, counted, Caller { who, held }, &slots);
                admitted += read;
                refused += DOCS.len() - read;
                failures.extend(wrong);
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(admitted > 40 && refused > 40, "the grid both admits and refuses: {admitted} admitted, {refused} refused");
    db.batch_execute(&format!(
        "RESET search_path; DROP SCHEMA {table_rows} CASCADE; DROP SCHEMA {table_auth} CASCADE; DROP SCHEMA {setting_rows} CASCADE; DROP SCHEMA {setting_auth} CASCADE;"
    ))
    .expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_setting_scope_admits_nobody_without_its_setting_and_refuses_to_read_a_malformed_one() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let (rows, auth) = ("demesne_decl_setting_gone_rows", "demesne_decl_setting_gone_auth");
    install_as(&mut db, &spec_from("setting rule_slots", "", rows, auth), rows, auth);
    let read = |db: &mut Client, who: &str, slots: Option<&str>| read_under(db, &claims_with(who, &ALL), slots);
    let slots = minted(&[]);
    assert!(read(&mut db, "bob", Some(&slots)).expect("a read").contains("d_one"), "the minted setting admits bob by his one declared edge");
    assert!(read(&mut db, "eve", Some(&slots)).expect("a read").contains("d_free"), "an element the setting lists nothing under is not held back");
    for (what, value) in
        [("no setting", None), ("an empty setting", Some("")), ("an array", Some("[]")), ("a string", Some("\"read.one\"")), ("JSON null", Some("null"))]
    {
        for who in ["bob", "eve"] {
            let got = read(&mut db, who, value).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(got.is_empty(), "{what} in place of the object admits {who} to nothing, not even an element that declares nothing: {got:?}");
        }
        assert_eq!(read(&mut db, "ann", value).expect("the owner's read").len(), DOCS.len(), "{what}: the owner reads every row by its own term");
    }
    let err = read(&mut db, "bob", Some("{\"read.one\":")).map(|_| ()).expect_err("a setting that is not JSON");
    assert!(err.contains("invalid input syntax for type json"), "{err}");
    let without = minted(&["read.one"]);
    assert!(
        read(&mut db, "eve", Some(&without)).expect("a read").contains("d_one"),
        "an element missing from the setting's object declares nothing, as the table's no rows"
    );
    for (what, value, want) in [
        ("an object", "{}", "cannot call jsonb_to_recordset on a non-array"),
        ("JSON null", "null", "cannot call jsonb_to_recordset on a non-array"),
        ("a list of numbers", "[1]", "must be an array of objects"),
    ] {
        let bad = without.replacen('{', &format!("{{\"read.one\":{value},"), 1);
        let err = read(&mut db, "bob", Some(&bad)).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what} under an element: {err}");
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {rows} CASCADE; DROP SCHEMA {auth} CASCADE;")).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_negated_setting_scope_fails_closed_without_its_setting() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the declared-row checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let (rows, auth) = ("demesne_decl_setting_not_rows", "demesne_decl_setting_not_auth");
    let src = spec_from("setting rule_slots", " nonempty", rows, auth)
        .replace("  relation borrow:", "  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation borrow:")
        .replacen(
            &format!(
                "(every s in setting rule_slots where role = \"require\" nonempty ({ANCHORS}) and none s in setting rule_slots where role = \"except\" ({ANCHORS}))"
            ),
            &format!("(named and not every s in setting rule_slots where role = \"require\" nonempty ({ANCHORS}))"),
            1,
        );
    assert!(src.contains("(named and not every s in setting"), "{src}");
    install_as(&mut db, &src, rows, auth);
    let read = |db: &mut Client, who: &str, slots: Option<&str>| read_under(db, &claims_with(who, &ALL), slots).expect("a read");
    let slots = minted(&[]);
    assert!(!read(&mut db, "bob", Some(&slots)).contains("d_one"), "bob holds every edge read.one requires, so the not refuses him");
    assert!(read(&mut db, "cat", Some(&slots)).contains("d_two"), "cat holds one of the two edges read.two requires, so the not admits him");
    for (what, value) in [("no setting", None), ("an empty setting", Some("")), ("an array", Some("[]"))] {
        let got = read(&mut db, "cat", value);
        assert!(!got.contains("d_two"), "{what}: the scope can't be judged, so its negation admits nobody: {got:?}");
    }
    assert!(
        read(&mut db, "bob", Some(&minted(&["read.one"]))).contains("d_one"),
        "an element the setting lists nothing under fails the nonempty every, so the not admits"
    );
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {rows} CASCADE; DROP SCHEMA {auth} CASCADE;")).expect("drop the schemas");
}
