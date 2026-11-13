use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_clock_rows";
const AUTH: &str = "demesne_clock_auth";
const CALLER: &str = "demesne_clock_caller";

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_row_is_read_inside_its_window_and_an_unset_bound_is_no_bound() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the clock checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let spec = format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate }}\nsubject member {{ anchor estate; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate\n  permission view = @scoped and @clock(opens_at reached) and not @clock(closes_at reached) @rls maps select\n}}\n"
    );
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let rls = demesne_emit_sql::Sql::new(&s).emit_rls().expect("the policies compile");
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, opens_at timestamptz, closes_at timestamptz);
         INSERT INTO docs VALUES
           ('open', 'e1', now() - interval '1 hour', now() + interval '1 hour'),
           ('open_ended', 'e1', now() - interval '1 hour', NULL),
           ('not_yet', 'e1', now() + interval '1 hour', NULL),
           ('closed', 'e1', now() - interval '2 hours', now() - interval '1 hour'),
           ('never_opens', 'e1', NULL, NULL),
           ('elsewhere', 'e2', now() - interval '1 hour', NULL);"
    ))
    .expect("fresh schemas, tables and rows");
    for stmt in [rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS} TO {CALLER}; GRANT SELECT ON {ROWS}.docs TO {CALLER};")).expect("grants");
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}; SELECT set_config('request.jwt.claims', '{{\"estate_id\":\"e1\"}}', true)")).expect("the caller");
    let read: BTreeSet<String> = tx.query("SELECT id FROM docs", &[]).expect("the read").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    assert_eq!(
        read,
        BTreeSet::from(["open".to_string(), "open_ended".to_string()]),
        "inside the window, a NULL closing time closes nothing, and a NULL opening time never opens"
    );
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
