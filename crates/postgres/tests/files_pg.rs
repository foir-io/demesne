use demesne_emit_sql::{Sql, file_sql, validate_files};
use demesne_postgres::drift;
use postgres::{Client, NoTls};

const SCHEMAS: &str = "definers schema \"multi_auth\"\ntables schema \"multi_rows\"\n";
const FILES: [&str; 3] = ["base.demesne", "extra.demesne", "last.demesne"];
const TABLES: &str = "
CREATE TABLE support_grants (holder_id text, tenant_id text, ended_at timestamptz);
CREATE TABLE acl (resource_id text, principal_kind text, principal_id text, access text, resource_type text, tenant_id text, workspace_id text);
CREATE TABLE docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
CREATE TABLE notes (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text, doc_id text);
";

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to apply a spec in several files to a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../testdata/multi/{name}", env!("CARGO_MANIFEST_DIR"))).expect("the fixture reads")
}

fn all_sql(s: &demesne_syntax::Spec) -> String {
    let mut b = String::new();
    Sql::new(s).write_all_sql(&mut b).expect("the spec emits");
    b
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn each_file_applied_in_order_leaves_the_database_its_prefix_describes() {
    let mut texts: Vec<String> = FILES.iter().map(|n| fixture(n)).collect();
    texts[0] = format!("{SCHEMAS}{}", texts[0]);
    let files = demesne_syntax::parse_files(FILES.iter().copied().zip(texts.iter().map(String::as_bytes))).expect("the files parse");
    validate_files(&files).expect("the files validate");
    let mut db = connect();
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS multi_rows CASCADE; DROP SCHEMA IF EXISTS multi_auth CASCADE; CREATE SCHEMA multi_rows; CREATE SCHEMA multi_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         SET search_path = multi_rows; {TABLES} RESET search_path;"
    ))
    .expect("fresh schemas");
    for k in 0..files.len() {
        let sql = file_sql(&files, k).expect("the file emits");
        db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply {}: {e}\n{sql}", files.names()[k]));
        let d = drift(&mut db, &all_sql(files.prefix(k)), &[]).expect("diff runs");
        let found: Vec<String> = d.findings.iter().map(|f| format!("{} {} — {}", f.kind.label(), f.object, f.detail)).collect();
        assert!(found.is_empty(), "after {}, the database differs from its prefix:\n{}", files.names()[k], found.join("\n"));
    }
    let manage: String = db.query_one("SELECT pg_get_functiondef('multi_auth.acl_manage(text, text)'::regprocedure)", &[]).expect("the function exists").get(0);
    assert!(manage.contains("WHEN 'note' THEN multi_auth.note_can_edit(p_id)"), "{manage}");
    let gone: Option<String> = db.query_one("SELECT to_regproc('multi_auth.doc_readable')::text", &[]).expect("the lookup runs").get(0);
    assert_eq!(gone, None);
}
