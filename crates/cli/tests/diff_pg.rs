#![cfg(feature = "db")]

use postgres::{Client, NoTls};
use std::fmt::Write;
use std::process::{Command, Output};

const WORKER: &str = "demesne_gc_worker";

const SPEC: &str = r#"definers schema "demesne_gc_auth"
tables schema "demesne_gc_rows"
topology {
  level platform virtual
  level tenant  parent platform
  level project parent tenant
}
vocabulary admin {
  permission tenant:manage implies records:*
  permission records:read
  permission records:write
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "user"
  subject     user_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}
subject staff    { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
subject customer { anchor project; reach self; identifies customer_id; roles none; binds owner }
object doc {
  table docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) tracked async
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = grantee:read + team + @holds(records:read) @rls maps select
  export view as doc_viewable(id text as check_doc_id, tenant_id text as row_tenant_id, project_id text as row_project_id, team_id text as row_team_id)
}
"#;

fn demesne(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_demesne")).args(args).output().expect("the CLI runs")
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_database_set_up_as_the_supabase_guide_says_passes_diff_exit_code() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to run diff against a live Postgres"));
    let mut db = Client::connect(&url, NoTls).expect("connect");
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS demesne_gc_rows CASCADE; DROP SCHEMA IF EXISTS demesne_gc_auth CASCADE;
         CREATE SCHEMA demesne_gc_rows; CREATE SCHEMA demesne_gc_auth;
         DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         DO $$ BEGIN CREATE ROLE {WORKER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         CREATE TABLE demesne_gc_rows.docs (id text PRIMARY KEY, tenant_id text, project_id text, team_id text);
         CREATE TABLE demesne_gc_rows.dacl (resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE demesne_gc_rows.tc (grp text, mem text);
         CREATE TABLE demesne_gc_rows.te (mem text, grp text);
         CREATE TABLE demesne_gc_rows.roles (id text PRIMARY KEY, key text, permissions text[]);
         CREATE TABLE demesne_gc_rows.role_assignments (principal_kind text, user_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);"
    ))
    .expect("fresh schemas");
    let spec = format!("{}/diff_pg.demesne", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&spec, SPEC).expect("the spec writes");

    let emitted = demesne(&["emit", &spec, "all"]);
    assert!(emitted.status.success(), "emit: {}", text(&emitted));
    db.batch_execute(&String::from_utf8_lossy(&emitted.stdout)).expect("the authorization SQL applies");
    let parsed = demesne_syntax::parse(SPEC).expect("the spec parses");
    let lists = demesne_emit_sql::Sql::new(&parsed).manifest().expect("a manifest").execute.expect("the manifest records who may run each function");
    assert!(
        !lists.callable.is_empty() && !lists.grantable.is_empty() && !lists.revoked.is_empty(),
        "the spec has a callable, a grantable and a revoked function: {lists:?}"
    );
    let mut grants = String::from("grant usage on schema demesne_gc_auth to authenticated;\n");
    for f in &lists.callable {
        writeln!(grants, "grant execute on function {f} to authenticated;").expect("fmt::Write for String never fails");
    }
    writeln!(grants, "grant usage on schema demesne_gc_auth to {WORKER};").expect("fmt::Write for String never fails");
    for f in &lists.grantable {
        writeln!(grants, "grant execute on function {f} to {WORKER};").expect("fmt::Write for String never fails");
    }
    db.batch_execute(&grants).unwrap_or_else(|e| panic!("the guide's grants: {e}\n{grants}"));

    let named = demesne(&["diff", &spec, &url, "--grantee", WORKER, "--exit-code"]);
    assert!(named.status.success(), "with the worker named a grantee, the guide's setup is in sync: {}", text(&named));
    assert!(text(&named).contains("in sync:"), "{}", text(&named));

    let unnamed = demesne(&["diff", &spec, &url, "--exit-code"]);
    assert!(!unnamed.status.success(), "with no grantee named, the worker's grants are drift: {}", text(&unnamed));
    assert!(text(&unnamed).contains(&format!("FROM {WORKER};")), "{}", text(&unnamed));

    let public = demesne(&["diff", &spec, &url, "--grantee", "PUBLIC", "--exit-code"]);
    assert!(!public.status.success(), "PUBLIC is no grantee: {}", text(&public));
    assert!(text(&public).contains("PUBLIC"), "{}", text(&public));

    db.batch_execute("DROP SCHEMA demesne_gc_auth CASCADE; DROP SCHEMA demesne_gc_rows CASCADE;").expect("drop the schemas");
}
