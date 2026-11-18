use demesne_emit_sql::Sql;
use postgres::{Client, NoTls};

fn spec(edit: &str) -> demesne_syntax::Spec {
    let src = format!(
        "definers schema \"demesne_sv_auth\"\ntables schema \"demesne_sv_rows\"\ntopology {{ level tenant }}\nsubject member {{ anchor tenant; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped tenant\n  relation owner: member via owner_id\n  permission view = owner @rls maps select\n{edit}}}\n"
    );
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    s
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_migration_that_drops_a_policy_and_no_function_applies() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to apply a migration to a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_sv_rows CASCADE; DROP SCHEMA IF EXISTS demesne_sv_auth CASCADE;
         CREATE SCHEMA demesne_sv_rows; CREATE SCHEMA demesne_sv_auth;
         DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         CREATE TABLE demesne_sv_rows.docs (id text PRIMARY KEY, tenant_id text, owner_id text);",
    )
    .expect("fresh schemas");
    let (before, after) = (spec("  permission edit = owner @rls maps update\n"), spec(""));
    let mut b = String::new();
    Sql::new(&before).write_all_sql(&mut b).expect("the SQL compiles");
    db.batch_execute(&b).unwrap_or_else(|e| panic!("apply: {e:?}"));
    let previous = Sql::new(&before).manifest().expect("a manifest");
    let migration = Sql::new(&after).migration(&previous).expect("the migration compiles");
    assert!(migration.contains("DROP POLICY IF EXISTS docs_update ON demesne_sv_rows.docs;") && !migration.contains("DROP FUNCTION"), "{migration}");
    db.batch_execute(&migration).unwrap_or_else(|e| panic!("the migration applies: {e:?}\n{migration}"));
    let left: i64 = db.query_one("SELECT count(*) FROM pg_policy WHERE polrelid = 'demesne_sv_rows.docs'::regclass", &[]).expect("the policies").get(0);
    assert_eq!(left, 1, "only the select policy is left");
}
