use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_clear_rows";
const AUTH: &str = "demesne_clear_auth";
const CALLER: &str = "demesne_clear_caller";

const SOME: &str = "some r in rules_live prefix \"read.\" clear of rules_cleared (mode visibility = \"listed\")";

fn spec() -> String {
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  permission view = owner + {SOME} @rls maps select\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  relation of: member via object doc->view on doc_id\n  permission view = of @rls maps select\n}}\n"
    )
}

struct Doc {
    id: &'static str,
    visibility: &'static str,
    rules: &'static [&'static str],
}

const DOCS: [Doc; 6] = [
    Doc { id: "one", visibility: "listed", rules: &["read.s.m1"] },
    Doc { id: "other", visibility: "listed", rules: &["read.s.m2"] },
    Doc { id: "both", visibility: "listed", rules: &["read.s.m2", "read.s.m1"] },
    Doc { id: "shut", visibility: "private", rules: &["read.s.m1"] },
    Doc { id: "bare", visibility: "listed", rules: &[] },
    Doc { id: "write", visibility: "listed", rules: &["write.s.m1"] },
];

#[derive(Debug, Clone, Copy)]
enum Cleared {
    Absent,
    Text(&'static str),
    List(&'static [Option<&'static str>]),
}

impl Cleared {
    fn json(self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Text(t) => Some(format!("\"{t}\"")),
            Self::List(items) => {
                Some(format!("[{}]", items.iter().map(|i| i.map_or_else(|| "null".to_string(), |v| format!("\"{v}\""))).collect::<Vec<_>>().join(",")))
            }
        }
    }
}

const CLAIMS: [Cleared; 6] = [
    Cleared::Absent,
    Cleared::Text("read.s.m1"),
    Cleared::List(&[]),
    Cleared::List(&[Some("read.s.m2")]),
    Cleared::List(&[Some("read.s.m1"), Some("read.s.m2")]),
    Cleared::List(&[None]),
];

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, visibility text, rules_live text[]);
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, doc_id text);"
    ))
    .expect("fresh schemas and tables");
    for d in &DOCS {
        let rules: Vec<&str> = d.rules.to_vec();
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', 'ann', $2, $3)", &[&d.id, &d.visibility, &rules]).expect("a doc");
        db.execute("INSERT INTO notes VALUES ($1, 'e1', 's1', $1)", &[&d.id]).expect("its note");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON {ROWS}.docs, {ROWS}.notes TO {CALLER};")).expect("grants");
}

fn reads(who: &str, cleared: Cleared, d: &Doc) -> bool {
    if who == "ann" {
        return true;
    }
    let Cleared::List(items) = cleared else {
        return false;
    };
    if items.iter().any(Option::is_none) {
        return false;
    }
    d.visibility == "listed" && d.rules.iter().any(|r| r.starts_with("read.") && !items.contains(&Some(*r)))
}

fn visible(db: &mut Client, who: &str, cleared: Cleared, table: &str) -> Result<BTreeSet<String>, String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let extra = cleared.json().map(|c| format!(",\"rules_cleared\":{c}")).unwrap_or_default();
    let claims = format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\"{extra}}}");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let ids = tx.query(&format!("SELECT id FROM {table}"), &[]).map_err(|e| e.to_string())?.iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    Ok(ids)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn clear_of_binds_only_what_a_carried_list_leaves_out() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the clear-of checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut failures = Vec::new();
    let (mut admitted, mut refused) = (0, 0);
    let grid = ["ann", "bob"].into_iter().flat_map(|who| CLAIMS.into_iter().flat_map(move |cleared| ["docs", "notes"].map(|table| (who, cleared, table))));
    for (who, cleared, table) in grid {
        let want: BTreeSet<String> = DOCS.iter().filter(|d| reads(who, cleared, d)).map(|d| d.id.to_string()).collect();
        let got = match visible(&mut db, who, cleared, table) {
            Ok(got) => got,
            Err(e) => {
                failures.push(format!("{who} with rules_cleared {cleared:?} on {table}: {e}"));
                continue;
            }
        };
        admitted += got.len();
        refused += DOCS.len() - got.len();
        if got != want {
            failures.push(format!("{who} with rules_cleared {cleared:?} reads {got:?} of {table}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(admitted > 20 && refused > 20, "the grid both admits and refuses: {admitted} admitted, {refused} refused");
    for (cleared, doc, want, why) in [
        (Cleared::Absent, "one", false, "claims carrying no list bind nothing: a call that never computed it is cleared of nothing"),
        (Cleared::Text("read.s.m1"), "one", false, "a claim that isn't an array is no list"),
        (Cleared::List(&[None]), "one", false, "a list holding a null clears nothing"),
        (Cleared::List(&[]), "one", true, "an empty list leaves every element"),
        (Cleared::List(&[Some("read.s.m2")]), "other", false, "the one element the list names is barred"),
        (Cleared::List(&[Some("read.s.m2")]), "one", true, "an element the list doesn't name binds"),
        (Cleared::List(&[Some("read.s.m2")]), "both", true, "a second element of the row's set is tried"),
        (Cleared::List(&[Some("read.s.m1"), Some("read.s.m2")]), "both", false, "every element named"),
        (Cleared::List(&[]), "shut", false, "the element binds and the brackets fail"),
        (Cleared::List(&[]), "write", false, "the prefix still narrows"),
    ] {
        for table in ["docs", "notes"] {
            assert_eq!(visible(&mut db, "bob", cleared, table).expect("the statement").contains(doc), want, "bob on {doc} of {table} with {cleared:?}: {why}");
        }
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
