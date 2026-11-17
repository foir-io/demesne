use demesne_emit_sql::Sql;
use postgres::{Client, NoTls};

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to apply a spec's SQL to a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn sql(view: &str) -> String {
    let src = format!(
        r#"definers schema "demesne_ex_auth"
tables schema "demesne_ex_rows"
topology {{ level tenant level project parent tenant }}
vocabulary cust {{ permission self:read }}
subject customer {{ anchor project reach self identifies customer_id roles configurable cust binds owner }}
object doc {{
  table docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access)
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = {view} @rls maps select
}}
"#
    );
    let s = demesne_syntax::parse(&src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut b = String::new();
    Sql::new(&s).write_all_sql(&mut b).expect("the SQL compiles");
    b
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn applying_a_specs_sql_leaves_public_the_right_to_run_each_function_that_the_sql_states() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_ex_rows CASCADE; DROP SCHEMA IF EXISTS demesne_ex_auth CASCADE;
         CREATE SCHEMA demesne_ex_rows; CREATE SCHEMA demesne_ex_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_ex_rows.docs (id text PRIMARY KEY, tenant_id text, project_id text, team_id text);
         CREATE TABLE demesne_ex_rows.dacl (resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE demesne_ex_rows.tc (grp text, mem text);
         CREATE TABLE demesne_ex_rows.te (mem text, grp text);",
    )
    .expect("fresh schemas");
    let listed = "demesne_ex_auth.docs_team_flat_resources()";
    for (view, public) in [("grantee:read + team", false), ("team", true), ("grantee:read + team", false), ("team", true)] {
        let sql = sql(view);
        db.batch_execute(&sql).unwrap_or_else(|e| panic!("{view}: apply: {e}"));
        let may: bool =
            db.query_one("SELECT has_function_privilege('public', $1::text::regprocedure, 'EXECUTE')", &[&listed]).expect("the function is live").get(0);
        assert_eq!(may, public, "{view}: may PUBLIC run {listed}");
    }
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn public_may_run_no_function_the_manifest_lists_for_a_role_you_grant() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_gr_rows CASCADE; DROP SCHEMA IF EXISTS demesne_gr_auth CASCADE;
         CREATE SCHEMA demesne_gr_rows; CREATE SCHEMA demesne_gr_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_gr_rows.docs (id text PRIMARY KEY, tenant_id text, project_id text, team_id text);
         CREATE TABLE demesne_gr_rows.dacl (resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE demesne_gr_rows.tc (grp text, mem text);
         CREATE TABLE demesne_gr_rows.te (mem text, grp text);",
    )
    .expect("fresh schemas");
    let src = r#"definers schema "demesne_gr_auth"
tables schema "demesne_gr_rows"
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) tracked async
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = grantee:read + team @rls maps select
}
"#;
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = Sql::new(&s);
    let mut b = String::new();
    sql.write_all_sql(&mut b).expect("the SQL compiles");
    db.batch_execute(&b).unwrap_or_else(|e| panic!("apply: {e}"));
    let lists = sql.manifest().expect("a manifest").execute.expect("the manifest records who may run each function");
    for f in ["apply()", "rebuild()", "watermark()"]
        .map(|s| format!("demesne_gr_auth.docs_grantee_async_{s}"))
        .into_iter()
        .chain(["demesne_gr_auth.docs_team_flat_reconcile()".to_string()])
    {
        assert!(lists.grantable.contains(&f), "{f} is not grantable: {:?}", lists.grantable);
    }
    let may = |db: &mut Client, f: &str| -> bool {
        db.query_one("SELECT has_function_privilege('public', $1::text::regprocedure, 'EXECUTE')", &[&f]).unwrap_or_else(|e| panic!("{f}: {e}")).get(0)
    };
    for f in &lists.grantable {
        assert!(!may(&mut db, f), "PUBLIC may run {f}");
    }
    let affordance = lists.internal.iter().chain(&lists.callable).find(|f| f.contains("_async_affordance(")).expect("the affordance is PUBLIC's");
    assert!(may(&mut db, affordance), "PUBLIC may not run {affordance}");
}
