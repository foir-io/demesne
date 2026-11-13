use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_some_rows";
const AUTH: &str = "demesne_some_auth";
const CALLER: &str = "demesne_some_caller";

const SOME: &str = "some r in rules_live prefix \"read.\" held rules_held (((@element prefix \"read.edge.\" and named) + (@element prefix \"read.pair.\" and named and second) + (@element prefix \"read.open.\" and mode visibility = \"listed\") + (@element prefix \"read.tree.\" and parent)) and not barred)";

fn spec() -> String {
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id where slot = \"1\"\n  relation second: member via edge doc_edges(principal_id, object_id) key rule_id where slot = \"2\"\n  relation barred: member via edge doc_bars(principal_id, object_id) key rule_id\n  relation parent: member via composition docs(id, parent_id)\n  permission view = owner + {SOME} @rls maps select\n  permission edit = owner and (owner + {SOME}) @rls maps update\n}}\n"
    )
}

struct Doc {
    id: &'static str,
    owner: &'static str,
    parent: Option<&'static str>,
    visibility: &'static str,
    rules: &'static [&'static str],
}

const DOCS: [Doc; 8] = [
    Doc { id: "plain", owner: "ann", parent: None, visibility: "private", rules: &[] },
    Doc { id: "edge", owner: "ann", parent: None, visibility: "private", rules: &["read.edge.k1", "write.edge.k9"] },
    Doc { id: "pair", owner: "ann", parent: None, visibility: "private", rules: &["read.pair.k2"] },
    Doc { id: "open", owner: "ann", parent: None, visibility: "listed", rules: &["read.open.k3"] },
    Doc { id: "shut", owner: "ann", parent: None, visibility: "private", rules: &["read.open.k3"] },
    Doc { id: "child", owner: "ann", parent: Some("edge"), visibility: "private", rules: &["read.tree.k4"] },
    Doc { id: "grandchild", owner: "ann", parent: Some("child"), visibility: "private", rules: &["read.tree.k4"] },
    Doc { id: "two", owner: "ann", parent: None, visibility: "private", rules: &["read.edge.k5", "read.edge.k1"] },
];
const EDGES: [(&str, &str, &str, &str); 8] = [
    ("bob", "edge", "read.edge.k1", "1"),
    ("bob", "pair", "read.pair.k2", "1"),
    ("bob", "pair", "read.pair.k2", "2"),
    ("cat", "pair", "read.pair.k2", "1"),
    ("cat", "edge", "read.edge.k1", "1"),
    ("cat", "two", "read.edge.k5", "1"),
    ("dan", "edge", "read.edge.k7", "1"),
    ("bob", "two", "read.edge.k1", "2"),
];
const BARS: [(&str, &str, &str); 1] = [("cat", "edge", "read.edge.k1")];
const HELD: [&[&str]; 4] = [&[], &["read.edge.k1", "read.pair.k2", "read.open.k3", "read.tree.k4"], &["read.edge.k5"], &["write.edge.k9", "read.edge.k7"]];

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, parent_id text, visibility text, rules_live text[]);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text, slot text);
         CREATE TABLE doc_bars (principal_id text, object_id text, rule_id text);"
    ))
    .expect("fresh schemas and tables");
    for d in &DOCS {
        let rules: Vec<&str> = d.rules.to_vec();
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', $2, $3, $4, $5)", &[&d.id, &d.owner, &d.parent, &d.visibility, &rules]).expect("a doc");
    }
    db.batch_execute("INSERT INTO docs VALUES ('unset', 'e1', 's1', 'ann', NULL, 'listed', NULL)").expect("a doc with no rule set");
    for (who, doc, rule, slot) in EDGES {
        db.execute("INSERT INTO doc_edges VALUES ($1, $2, $3, $4)", &[&who, &doc, &rule, &slot]).expect("an edge");
    }
    for (who, doc, rule) in BARS {
        db.execute("INSERT INTO doc_bars VALUES ($1, $2, $3)", &[&who, &doc, &rule]).expect("a bar");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, UPDATE ON {ROWS}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};"
    ))
    .expect("grants");
}

fn edge(who: &str, doc: &str, rule: &str, slot: &str) -> bool {
    EDGES.contains(&(who, doc, rule, slot))
}

fn reads(who: &str, held: &[&str], d: &Doc) -> bool {
    if d.owner == who {
        return true;
    }
    d.rules.iter().filter(|r| r.starts_with("read.") && held.contains(r)).any(|r| {
        let anchor = if r.starts_with("read.edge.") {
            edge(who, d.id, r, "1")
        } else if r.starts_with("read.pair.") {
            edge(who, d.id, r, "1") && edge(who, d.id, r, "2")
        } else if r.starts_with("read.open.") {
            d.visibility == "listed"
        } else if r.starts_with("read.tree.") {
            d.parent.is_some_and(|p| reads_without_tree(who, held, DOCS.iter().find(|x| x.id == p).expect("the parent")))
        } else {
            false
        };
        anchor && !BARS.contains(&(who, d.id, r))
    })
}

fn reads_without_tree(who: &str, held: &[&str], d: &Doc) -> bool {
    if d.owner == who {
        return true;
    }
    d.rules.iter().filter(|r| r.starts_with("read.") && held.contains(r) && !r.starts_with("read.tree.")).any(|r| {
        let anchor = if r.starts_with("read.edge.") {
            edge(who, d.id, r, "1")
        } else if r.starts_with("read.pair.") {
            edge(who, d.id, r, "1") && edge(who, d.id, r, "2")
        } else {
            r.starts_with("read.open.") && d.visibility == "listed"
        };
        anchor && !BARS.contains(&(who, d.id, r))
    })
}

fn visible(db: &mut Client, who: &str, held: &[&str], update: bool) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let list: Vec<String> = held.iter().map(|h| format!("\"{h}\"")).collect();
    let claims = format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\",\"rules_held\":[{}]}}", list.join(","));
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let sql = if update { "UPDATE docs SET id = id RETURNING id" } else { "SELECT id FROM docs" };
    let ids = tx.query(sql, &[]).expect("the statement").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn some_admits_through_an_element_the_row_and_the_caller_both_hold() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the some checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut failures = Vec::new();
    let (mut admitted, mut refused) = (0, 0);
    for who in ["ann", "bob", "cat", "dan", "eve"] {
        for held in HELD {
            let want: BTreeSet<String> =
                DOCS.iter().filter(|d| reads(who, held, d)).map(|d| d.id.to_string()).chain((who == "ann").then(|| "unset".to_string())).collect();
            let got = visible(&mut db, who, held, false);
            admitted += got.len();
            refused += DOCS.len() + 1 - got.len();
            if got != want {
                failures.push(format!("{who} holding {held:?} reads {got:?}, want {want:?}"));
            }
            let owned: BTreeSet<String> =
                if who == "ann" { DOCS.iter().map(|d| d.id.to_string()).chain(["unset".to_string()]).collect() } else { BTreeSet::new() };
            let wrote = visible(&mut db, who, held, true);
            if wrote != owned {
                failures.push(format!("{who} holding {held:?} updates {wrote:?}, want {owned:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(admitted > 20 && refused > 20, "the grid both admits and refuses: {admitted} admitted, {refused} refused");
    let all = HELD[1];
    for (who, doc, want, why) in [
        ("bob", "edge", true, "an edge under an element both sides hold"),
        ("bob", "pair", true, "both slots matched"),
        ("cat", "pair", false, "one slot of two"),
        ("cat", "edge", false, "an edge, and a bar under the same element"),
        ("bob", "child", true, "the parent admits by its own edge"),
        ("bob", "grandchild", false, "the parent admits only through its own parent, which the cascade prunes"),
        ("eve", "open", true, "a row test inside the brackets"),
        ("eve", "shut", false, "the element is held and the row test fails"),
        ("bob", "two", false, "an edge in the wrong slot"),
    ] {
        assert_eq!(visible(&mut db, who, all, false).contains(doc), want, "{who} on {doc}: {why}");
    }
    assert!(!visible(&mut db, "bob", &[], false).contains("edge"), "an element the caller does not hold binds nothing");
    assert!(visible(&mut db, "cat", HELD[2], false).contains("two"), "a second element of the row's set is tried");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
