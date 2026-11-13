use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_casc_rows";
const AUTH: &str = "demesne_casc_auth";
const CALLER: &str = "demesne_casc_caller";

const DOCS: [(&str, &str, Option<&str>); 6] = [
    ("root", "ann", None),
    ("child", "ann", Some("root")),
    ("grandchild", "ann", Some("child")),
    ("bobs", "bob", None),
    ("under_bobs", "ann", Some("bobs")),
    ("two_under_bobs", "ann", Some("under_bobs")),
];

fn install(db: &mut Client) {
    let spec = format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate }}\nsubject member {{ anchor estate; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate\n  relation owner: member via owner_id\n  relation parent: member via composition docs(id, parent_id)\n  permission view = owner + (@kind(\"auditor\") and parent) @rls maps select\n}}\n"
    );
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, owner_id text, parent_id text);"
    ))
    .expect("fresh schemas and tables");
    for (id, owner, parent) in DOCS {
        db.execute("INSERT INTO docs VALUES ($1, 'e1', $2, $3)", &[&id, &owner, &parent]).expect("a doc");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON {ROWS}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};"))
        .expect("grants");
}

fn visible(db: &mut Client, who: &str, kind: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"kind\":\"{kind}\"}}")])
        .expect("the claims");
    let ids = tx.query("SELECT id FROM docs", &[]).expect("the read").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

fn owner_of(id: &str) -> &'static str {
    DOCS.iter().find(|d| d.0 == id).expect("the doc").1
}

fn reads(who: &str, kind: &str, (_, owner, parent): &(&str, &str, Option<&str>)) -> bool {
    *owner == who || (kind == "auditor" && parent.is_some_and(|p| owner_of(p) == who))
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_row_is_reached_through_its_parent_only_when_the_parent_admits_without_borrowing() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the cascade checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let own = |ids: &[&str]| -> BTreeSet<String> { ids.iter().map(|i| (*i).to_string()).collect() };
    assert_eq!(visible(&mut db, "cat", "auditor"), own(&[]), "an auditor who reads no parent reads nothing hung from one");
    assert_eq!(visible(&mut db, "bob", "auditor"), own(&["bobs", "under_bobs"]), "an auditor reads a row whose parent they own, and not the row beneath that");
    let mut outcomes = BTreeSet::new();
    for who in ["ann", "bob", "cat"] {
        for kind in ["auditor", "member"] {
            let want: BTreeSet<String> = DOCS.iter().filter(|d| reads(who, kind, d)).map(|d| d.0.to_string()).collect();
            let got = visible(&mut db, who, kind);
            assert_eq!(got, want, "{who} as {kind}");
            outcomes.insert(got.is_empty());
            outcomes.insert(got.len() == DOCS.len());
        }
    }
    assert_eq!(outcomes.len(), 2, "the grid holds callers who read some rows and callers who read none");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
