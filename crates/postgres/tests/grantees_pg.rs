use demesne_emit_sql::{ExecuteLists, Manifest, Sql};
use demesne_postgres::{Drift, DriftKind, Grantees, drift};
use postgres::{Client, NoTls};

const WORKER: &str = "demesne_ge_worker";

fn spec(tag: &str) -> demesne_syntax::Spec {
    let src = format!(
        r#"definers schema "demesne_ge_{tag}_auth"
tables schema "demesne_ge_{tag}_rows"
topology {{
  level platform virtual
  level tenant  parent platform
  level project parent tenant
}}
vocabulary admin {{
  permission tenant:manage implies records:*
  permission records:read
  permission records:write
}}
rolestore admin {{
  assignments role_assignments
  kind        principal_kind = "user"
  subject     user_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}}
subject staff    {{ anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }}
subject customer {{ anchor project; reach self; identifies customer_id; roles none; binds owner }}
object doc {{
  table docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) tracked async
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = grantee:read + team + @holds(records:read) @rls maps select
}}
"#
    );
    let s = demesne_syntax::parse(&src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    s
}

struct Installed {
    sql: String,
    manifest: Manifest,
    lists: ExecuteLists,
    auth: String,
}

fn install(db: &mut Client, tag: &str) -> Installed {
    let (rows, auth) = (format!("demesne_ge_{tag}_rows"), format!("demesne_ge_{tag}_auth"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {rows} CASCADE; DROP SCHEMA IF EXISTS {auth} CASCADE; CREATE SCHEMA {rows}; CREATE SCHEMA {auth};
         DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         DO $$ BEGIN CREATE ROLE {WORKER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         CREATE TABLE {rows}.docs (id text PRIMARY KEY, tenant_id text, project_id text, team_id text);
         CREATE TABLE {rows}.dacl (resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE {rows}.tc (grp text, mem text);
         CREATE TABLE {rows}.te (mem text, grp text);
         CREATE TABLE {rows}.roles (id text PRIMARY KEY, key text, permissions text[]);
         CREATE TABLE {rows}.role_assignments (principal_kind text, user_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);"
    ))
    .expect("fresh schemas");
    let s = spec(tag);
    let compiled = Sql::new(&s);
    let mut sql = String::new();
    compiled.write_all_sql(&mut sql).expect("the SQL compiles");
    db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply: {e}"));
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {auth} TO authenticated, {WORKER}")).expect("the schema grant");
    let manifest = compiled.manifest().expect("a manifest");
    let lists = manifest.execute.clone().expect("the manifest records who may run each function");
    assert!(!lists.grantable.is_empty() && !lists.revoked.is_empty(), "the spec has a grantable and a revoked function: {lists:?}");
    Installed { sql, manifest, lists, auth }
}

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run diff against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

fn granted(d: &Drift) -> Vec<(String, String)> {
    d.findings.iter().filter(|f| f.kind == DriftKind::Granted).map(|f| (f.object.clone(), f.detail.clone())).collect()
}

fn names(d: &Drift, object: &str, statement: &str) -> bool {
    granted(d).iter().any(|(o, detail)| o == object && detail.ends_with(statement))
}

fn worker(at: &Installed) -> Grantees {
    Grantees::new(&at.manifest, &[WORKER.to_string()]).expect("a worker role is a grantee")
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_grantees_grant_of_a_grantable_function_is_accepted() {
    let mut db = connect();
    let at = install(&mut db, "ok");
    for f in &at.lists.grantable {
        db.batch_execute(&format!("GRANT EXECUTE ON FUNCTION {f} TO {WORKER}")).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
    let accepted = drift(&mut db, &at.sql, &[], &worker(&at)).expect("diff runs");
    assert_eq!(accepted.findings, [], "the worker holds only what the manifest lets it be granted");
    let unnamed = drift(&mut db, &at.sql, &[], &Grantees::default()).expect("diff runs");
    for f in &at.lists.grantable {
        let statement = format!("REVOKE EXECUTE ON FUNCTION {f} FROM {WORKER};");
        assert!(
            names(&unnamed, &format!("function {f}"), &statement),
            "with no grantee named, the worker's grant of {f} is reported: {:#?}",
            granted(&unnamed)
        );
    }
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA demesne_ge_ok_rows CASCADE", at.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_grantees_grant_of_a_revoked_function_is_still_reported() {
    let mut db = connect();
    let at = install(&mut db, "rv");
    for f in &at.lists.revoked {
        db.batch_execute(&format!("GRANT EXECUTE ON FUNCTION {f} TO {WORKER}")).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
    let d = drift(&mut db, &at.sql, &[], &worker(&at)).expect("diff runs");
    for f in &at.lists.revoked {
        let statement = format!("REVOKE EXECUTE ON FUNCTION {f} FROM {WORKER};");
        assert!(names(&d, &format!("function {f}"), &statement), "the worker's grant of revoked {f} is reported: {:#?}", granted(&d));
    }
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA demesne_ge_rv_rows CASCADE", at.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_default_privilege_to_a_grantee_is_still_reported() {
    let mut db = connect();
    let at = install(&mut db, "dp");
    let owner: String = db.query_one("SELECT quote_ident(current_user)", &[]).expect("the owner").get(0);
    db.batch_execute(&format!("ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT EXECUTE ON FUNCTIONS TO {WORKER}", at.auth)).expect("a default privilege");
    let d = drift(&mut db, &at.sql, &[], &worker(&at)).expect("diff runs");
    let statement = format!("ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {} REVOKE EXECUTE ON FUNCTIONS FROM {WORKER};", at.auth);
    assert!(
        names(&d, &format!("default privileges for role {owner} in schema {}", at.auth), &statement),
        "the default privilege to the worker is reported: {:#?}",
        granted(&d)
    );
    db.batch_execute(&format!("ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE EXECUTE ON FUNCTIONS FROM {WORKER}", at.auth)).expect("take it back");
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA demesne_ge_dp_rows CASCADE", at.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_request_roles_grants_of_a_grantable_function_are_reported_unless_named() {
    let mut db = connect();
    let at = install(&mut db, "rq");
    for f in &at.lists.grantable {
        db.batch_execute(&format!("GRANT EXECUTE ON FUNCTION {f} TO anon, authenticated, {WORKER}")).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
    for (what, grantees) in [("no grantee named", Grantees::default()), ("the worker named", worker(&at))] {
        let d = drift(&mut db, &at.sql, &[], &grantees).expect("diff runs");
        for f in &at.lists.grantable {
            for role in ["anon", "authenticated"] {
                let statement = format!("REVOKE EXECUTE ON FUNCTION {f} FROM {role};");
                assert!(names(&d, &format!("function {f}"), &statement), "{what}: {role}'s grant of {f} is reported: {:#?}", granted(&d));
            }
        }
    }
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA demesne_ge_rq_rows CASCADE", at.auth)).expect("drop the schemas");
}
