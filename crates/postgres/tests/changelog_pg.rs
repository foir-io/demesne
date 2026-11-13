use postgres::error::SqlState;
use postgres::{Client, NoTls};

const ROWS: &str = "demesne_cl_rows";
const AUTH: &str = "demesne_cl_auth";

const SPEC: &str = "changelog checked\ntopology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\nobject doc {\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id where owner_kind = \"member\"\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access) tracked\n  permission view = owner + mode visibility = \"public\" + grantee:read @rls maps select\n  permission edit = owner @rls maps update\n  track owner\n  track visibility\n}\n";

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let changelog = demesne_emit_sql::Sql::new(&s).changelog_sql();
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, owner_kind text, visibility text);
         CREATE TABLE doc_acl (doc_id text, principal_kind text, principal_id text, access text);
         INSERT INTO docs VALUES ('d1', 'e1', 's1', 'm1', 'member', 'private');"
    ))
    .expect("fresh schemas and tables");
    db.batch_execute(&changelog).unwrap_or_else(|e| panic!("apply: {e}\n{changelog}"));
}

fn commit(db: &mut Client, statements: &[&str]) -> Result<(), postgres::Error> {
    let mut tx = db.transaction().expect("a transaction");
    for s in statements {
        tx.batch_execute(s).unwrap_or_else(|e| panic!("{s}: {e}"));
    }
    tx.commit()
}

fn log(rel: &str, resource: &str, kind: &str, principal: &str, op: &str) -> String {
    format!(
        "INSERT INTO {AUTH}._authz_changelog (rel, resource_id, principal_kind, principal_id, op) VALUES ('{rel}', '{resource}', '{kind}', '{principal}', '{op}')"
    )
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_commit_that_changes_a_tracked_source_without_its_changelog_row_is_refused() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the changelog checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let grant = "INSERT INTO doc_acl VALUES ('d1', 'member', 'm2', 'read')";
    let revoke = "DELETE FROM doc_acl WHERE doc_id = 'd1' AND principal_id = 'm2'";
    let reown = "UPDATE docs SET owner_id = 'm3' WHERE id = 'd1'";
    let publish = "UPDATE docs SET visibility = 'public' WHERE id = 'd1'";
    let (granted, revoked) = (log("doc_acl", "d1", "member", "m2", "grant"), log("doc_acl", "d1", "member", "m2", "revoke"));
    let (unowned, owned) = (log("doc", "d1", "member", "m1", "revoke"), log("doc", "d1", "member", "m3", "grant"));
    let shown = log("doc", "d1", "", "", "visibility");
    let other = log("doc_acl", "d1", "member", "m9", "grant");
    let cases: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
        ("a grant alone", vec![grant], Some("doc_acl_changelog_written")),
        ("a grant with another principal's row", vec![grant, &owned], Some("doc_acl_changelog_written")),
        ("a grant with a revoke's row", vec![grant, &revoked], Some("doc_acl_changelog_written")),
        ("a grant with a row naming someone else", vec![grant, &other], Some("doc_acl_changelog_written")),
        ("a grant with its row written first", vec![&granted, grant], None),
        ("a revoke alone", vec![revoke], Some("doc_acl_changelog_written")),
        ("a revoke with its row written after", vec![revoke, &revoked], None),
        ("a new owner alone", vec![reown], Some("docs_changelog_written")),
        ("a new owner with only the grant half", vec![reown, &owned], Some("docs_changelog_written")),
        ("a new owner with only the revoke half", vec![reown, &unowned], Some("docs_changelog_written")),
        ("a new owner with both halves", vec![reown, &unowned, &owned], None),
        ("a visibility change alone", vec![publish], Some("docs_changelog_written")),
        ("a visibility change with its row", vec![publish, &shown], None),
        ("an update of an untracked column", vec!["UPDATE docs SET space_id = 's2' WHERE id = 'd1'"], None),
        ("a changelog row with no change", vec![&shown], None),
    ];
    let mut failures = Vec::new();
    for (what, statements, refused_by) in &cases {
        let got = commit(&mut db, statements);
        let constraint = got.as_ref().err().map(|e| {
            let detail = e.as_db_error().unwrap_or_else(|| panic!("{what}: {e}"));
            assert_eq!(detail.code(), &SqlState::CHECK_VIOLATION, "{what}: {detail}");
            detail.constraint().unwrap_or("").to_string()
        });
        if constraint.as_deref() != *refused_by {
            failures.push(format!("{what}: refused by {constraint:?}, want {refused_by:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    commit(&mut db, &[&granted]).expect("a changelog row commits by itself");
    commit(&mut db, &[grant]).expect_err("a row written by an earlier transaction does not cover a later change");
    let deferred: i64 = db
        .query_one("SELECT count(*) FROM pg_trigger WHERE tgconstraint <> 0 AND tgname IN ('doc_acl_changelog', 'docs_obj_changelog')", &[])
        .expect("the triggers")
        .get(0);
    assert_eq!(deferred, 2, "both triggers are deferred constraint triggers");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
