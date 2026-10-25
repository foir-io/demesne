use demesne_emit_sql::Sql;
use demesne_postgres::{DriftKind, drift};
use postgres::{Client, NoTls};

const SPEC: &str = r#"
definers schema "d38_auth"
tables schema "d38_rows"

topology {
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}

subject member { anchor workspace; reach self; identifies member_ref; roles none; binds owner }

object note {
  table  notes
  pk     note_pk
  scoped org > workspace
  relation owner:   member via owner_ref
  relation grantee: member via grant note_acl(note_ref, grantee_kind, grantee_ref, perm)
  permission view = owner + mode visibility = "open" + grantee:read @rls maps select
}

object doc {
  table  docs
  pk     doc_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner + mode visibility = "open" @rls maps select
  track visibility
}
"#;

const TABLES: &str = "
CREATE TABLE notes (note_pk text PRIMARY KEY, org_ref text, ws_ref text, owner_ref text, visibility text);
CREATE TABLE docs (doc_pk text PRIMARY KEY, org_ref text, ws_ref text, owner_ref text, visibility text);
CREATE TABLE note_acl (note_ref text, grantee_kind text, grantee_ref text, perm text);
";

fn connect() -> Client {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to run diff against a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn sql() -> String {
    let s = demesne_syntax::parse(SPEC).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut b = String::new();
    Sql::new(&s).write_all_sql(&mut b).expect("the SQL compiles");
    b
}

fn install(db: &mut Client, sql: &str) {
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS d38_rows CASCADE; DROP SCHEMA IF EXISTS d38_auth CASCADE; CREATE SCHEMA d38_rows; CREATE SCHEMA d38_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         SET search_path = d38_rows; {TABLES} RESET search_path;"
    ))
    .expect("fresh schemas");
    db.batch_execute(sql).unwrap_or_else(|e| panic!("apply: {e}"));
}

fn temporaries(db: &mut Client) -> i64 {
    db.query_one("SELECT count(*) FROM pg_class WHERE relnamespace = pg_my_temp_schema()", &[]).expect("the temp schema").get(0)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn diff_reports_every_way_the_live_database_differs_from_the_spec() {
    let mut db = connect();
    let sql = sql();
    install(&mut db, &sql);

    let clean = drift(&mut db, &sql, &[]).expect("diff runs");
    assert_eq!(clean.findings, [], "the database the SQL just built is in sync");
    assert_eq!((clean.policies, clean.functions, clean.triggers), (2, 3, 1));
    assert_eq!(temporaries(&mut db), 0, "diff leaves nothing in the session");

    db.batch_execute(
        "ALTER POLICY notes_select ON d38_rows.notes USING (true);
         ALTER POLICY docs_select ON d38_rows.docs TO public;
         CREATE OR REPLACE FUNCTION d38_auth.note_acl_grants(p_member_id text, p_note_id text, p_access text) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT true $$;
         DROP TRIGGER docs_obj_changelog ON d38_rows.docs;
         DROP FUNCTION d38_auth.docs_obj_changelog();
         CREATE POLICY rogue ON d38_rows.notes FOR SELECT USING (true);
         CREATE FUNCTION d38_auth.hand_written(p text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;
         CREATE FUNCTION d38_auth.forgotten() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
         CREATE TRIGGER forgotten AFTER INSERT ON d38_rows.docs FOR EACH ROW EXECUTE FUNCTION d38_auth.forgotten();",
    )
    .expect("drift");
    let allow = ["function d38_auth.hand_written(text)".to_string(), "function d38_auth.gone(text)".to_string()];
    let d = drift(&mut db, &sql, &allow).expect("diff runs");
    let got: Vec<(DriftKind, &str)> = d.findings.iter().map(|f| (f.kind, f.object.as_str())).collect();
    assert_eq!(
        got,
        [
            (DriftKind::Changed, "policy docs_select on d38_rows.docs"),
            (DriftKind::Changed, "policy notes_select on d38_rows.notes"),
            (DriftKind::Changed, "function d38_auth.note_acl_grants(text, text, text)"),
            (DriftKind::Missing, "function d38_auth.docs_obj_changelog()"),
            (DriftKind::Invalid, "trigger docs_obj_changelog on d38_rows.docs"),
            (DriftKind::Orphan, "policy rogue on d38_rows.notes"),
            (DriftKind::Orphan, "function d38_auth.forgotten()"),
            (DriftKind::Orphan, "trigger forgotten on d38_rows.docs"),
            (DriftKind::Stale, "function d38_auth.gone(text)"),
        ],
        "{:#?}",
        d.findings
    );
    let detail = |object: &str| d.findings.iter().find(|f| f.object == object).map(|f| f.detail.clone()).unwrap_or_default();
    assert!(
        detail("policy notes_select on d38_rows.notes").starts_with("USING: live `true`, generated `"),
        "{}",
        detail("policy notes_select on d38_rows.notes")
    );
    assert_eq!(detail("policy docs_select on d38_rows.docs"), "roles: live public, generated authenticated");
    assert_eq!(
        detail("function d38_auth.note_acl_grants(text, text, text)"),
        "its live definition is not the generated one (re-apply it): live `STABLE`, generated `STABLE STRICT SECURITY DEFINER`"
    );
    assert_eq!(
        detail("trigger docs_obj_changelog on d38_rows.docs"),
        "the generated trigger does not compile against the live database: function d38_auth.docs_obj_changelog() does not exist"
    );
    assert_eq!(temporaries(&mut db), 0, "diff leaves nothing in the session");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn diff_resolves_an_unqualified_table_as_the_migration_did() {
    let mut db = connect();
    let sql = "ALTER TABLE d38_path.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_select ON d38_path.items FOR SELECT TO public USING (EXISTS (SELECT 1 FROM items p WHERE p.id = parent));
";
    db.batch_execute(
        "DROP SCHEMA IF EXISTS d38_path CASCADE; CREATE SCHEMA d38_path; CREATE TABLE d38_path.items (id text, parent text); SET search_path = d38_path",
    )
    .expect("a fresh schema");
    db.batch_execute(sql).expect("apply");
    let d = drift(&mut db, sql, &[]).expect("diff runs");
    assert_eq!((d.findings, d.policies), (vec![], 1), "the copy's `items` is the live table, not the shadow beside it");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn diff_reports_a_governed_table_the_database_lacks() {
    let mut db = connect();
    db.batch_execute("DROP SCHEMA IF EXISTS d38_absent CASCADE; CREATE SCHEMA d38_absent").expect("a fresh schema");
    let sql = "ALTER TABLE d38_absent.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_select ON d38_absent.items FOR SELECT TO public USING (true);
";
    let d = drift(&mut db, sql, &[]).expect("diff runs");
    let got: Vec<(DriftKind, &str, &str)> = d.findings.iter().map(|f| (f.kind, f.object.as_str(), f.detail.as_str())).collect();
    assert_eq!(got, [(DriftKind::Missing, "table d38_absent.items", "the spec governs it, but the database has no such table")]);
}
