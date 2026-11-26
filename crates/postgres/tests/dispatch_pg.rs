use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_dispatch_rows";
const AUTH: &str = "demesne_dispatch_auth";
const CALLER: &str = "demesne_dispatch_caller";

const VIEW: &str = "owner + some r in rules_live prefix \"a.\" (named) + some r in rules_live prefix \"b.\" (mode visibility = \"listed\") + some t in tags prefix \"c.\" held tags_held (mode visibility = \"private\") + (mode visibility = \"listed\" and not (some r in rules_live prefix \"x.\" (named)))";

fn spec() -> String {
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  permission view = {VIEW} @rls maps select\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  relation of: member via object doc->view on doc_id\n  permission view = of @rls maps select\n}}\n"
    )
}

struct Doc {
    id: &'static str,
    visibility: &'static str,
    rules: &'static [&'static str],
    tags: &'static [&'static str],
}

const DOCS: [Doc; 10] = [
    Doc { id: "a", visibility: "private", rules: &["a.k1"], tags: &[] },
    Doc { id: "b", visibility: "listed", rules: &["b.k2"], tags: &[] },
    Doc { id: "b_shut", visibility: "private", rules: &["b.k2"], tags: &[] },
    Doc { id: "ab", visibility: "private", rules: &["b.k2", "a.k1"], tags: &[] },
    Doc { id: "c", visibility: "private", rules: &[], tags: &["c.t1"] },
    Doc { id: "ac", visibility: "private", rules: &["a.k1"], tags: &["c.t1"] },
    Doc { id: "none", visibility: "listed", rules: &["z.k9"], tags: &[] },
    Doc { id: "empty", visibility: "private", rules: &[], tags: &[] },
    Doc { id: "x", visibility: "listed", rules: &["x.k3"], tags: &[] },
    Doc { id: "ax", visibility: "listed", rules: &["a.k1", "x.k3"], tags: &[] },
];
const EDGES: [(&str, &str, &str); 5] = [("bob", "a", "a.k1"), ("bob", "ab", "a.k1"), ("bob", "ac", "a.k1"), ("bob", "x", "x.k3"), ("cat", "ax", "a.k1")];

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, visibility text, rules_live text[], tags text[]);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text);
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, doc_id text);"
    ))
    .expect("fresh schemas and tables");
    for d in &DOCS {
        let (rules, tags): (Vec<&str>, Vec<&str>) = (d.rules.to_vec(), d.tags.to_vec());
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', 'ann', $2, $3, $4)", &[&d.id, &d.visibility, &rules, &tags]).expect("a doc");
        db.execute("INSERT INTO notes VALUES ($1, 'e1', 's1', $1)", &[&d.id]).expect("its note");
    }
    for (who, doc, rule) in EDGES {
        db.execute("INSERT INTO doc_edges VALUES ($1, $2, $3)", &[&who, &doc, &rule]).expect("an edge");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON {ROWS}.docs, {ROWS}.notes TO {CALLER};")).expect("grants");
}

fn visible(db: &mut Client, who: &str, held: &str, table: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let claims = format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\",\"tags_held\":{held}}}");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let ids = tx.query(&format!("SELECT id FROM {table}"), &[]).expect("the statement").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_borrow_that_runs_one_family_s_query_answers_as_the_policy_on_every_row() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the dispatch checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut failures = Vec::new();
    let (mut admitted, mut refused) = (0, 0);
    let grid = ["ann", "bob", "cat", "eve"].into_iter().flat_map(|who| ["[]", "[\"c.t1\"]"].map(|held| (who, held)));
    for (who, held) in grid {
        let policy = visible(&mut db, who, held, "docs");
        let borrowed = visible(&mut db, who, held, "notes");
        admitted += policy.len();
        refused += DOCS.len() - policy.len();
        if borrowed != policy {
            failures.push(format!("{who} holding {held}: the borrow reads {borrowed:?}, the policy {policy:?}"));
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(admitted > 15 && refused > 15, "the grid both admits and refuses: {admitted} admitted, {refused} refused");
    for (who, held, doc, want, why) in [
        ("bob", "[]", "a", true, "one family's element, its edge held"),
        ("cat", "[]", "a", false, "one family's element, no edge"),
        ("eve", "[]", "b", true, "the other family alone"),
        ("eve", "[]", "b_shut", false, "the other family, its row test failing"),
        ("bob", "[]", "ab", true, "two families: the whole query admits through the one that holds"),
        ("eve", "[]", "ab", false, "two families, neither holding"),
        ("eve", "[\"c.t1\"]", "c", true, "a family of another column, its element held"),
        ("eve", "[]", "c", false, "a family of another column, its element not held"),
        ("eve", "[]", "none", true, "no family's element: the pruned query, whose negated term holds"),
        ("eve", "[]", "empty", false, "no element at all, and private"),
        ("bob", "[]", "x", false, "the negated family alone, naming the caller: its term bars"),
        ("eve", "[]", "x", true, "the negated family alone, naming someone else"),
        ("cat", "[]", "ax", true, "a family that admits beside the negated one"),
    ] {
        for table in ["docs", "notes"] {
            assert_eq!(visible(&mut db, who, held, table).contains(doc), want, "{who} on {doc} of {table}: {why}");
        }
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
