use demesne_emit_sql::Sql;
use postgres::{Client, NoTls};

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to apply a spec's SQL to a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn sql(borrowed: bool) -> String {
    let view = if borrowed { "doc" } else { "author" };
    let src = format!(
        r#"definers schema "demesne_ex_auth"
tables schema "demesne_ex_rows"
topology {{ level tenant level workspace parent tenant }}
grant support at tenant via edge support_grants(holder_id, tenant_id)
subject staff {{ anchor tenant; reach via grant support; identifies sub; roles none }}
subject member {{ anchor workspace; reach self; identifies member_id; roles none; binds owner }}
object acl_entry {{
  table acl
  scoped tenant > workspace
  permission view = @store_manage @rls maps select
  permission edit = @store_manage @rls maps update
}}
object doc {{
  table docs
  scoped tenant > workspace
  relation owner: member via owner_id
  relation grantee: member via grant acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view = owner + grantee:read + grantee:write @rls maps select
  permission edit = owner + grantee:write @rls maps update
}}
object note {{
  table notes
  scoped tenant > workspace
  relation author: member via author_id
  relation doc: member via object doc->edit on doc_id
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
         CREATE TABLE demesne_ex_rows.support_grants (holder_id text, tenant_id text);
         CREATE TABLE demesne_ex_rows.acl (id text PRIMARY KEY, tenant_id text, workspace_id text, resource_type text, resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE demesne_ex_rows.docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
         CREATE TABLE demesne_ex_rows.notes (id text PRIMARY KEY, tenant_id text, workspace_id text, doc_id text, author_id text);",
    )
    .expect("fresh schemas");
    let checked = "demesne_ex_auth.doc_can_edit(text)";
    for borrowed in [false, true, false, true] {
        let sql = sql(borrowed);
        db.batch_execute(&sql).unwrap_or_else(|e| panic!("borrowed {borrowed}: apply: {e}"));
        let may: bool =
            db.query_one("SELECT has_function_privilege('public', $1::text::regprocedure, 'EXECUTE')", &[&checked]).expect("the function is live").get(0);
        assert_eq!(may, borrowed, "borrowed {borrowed}: may PUBLIC run {checked}");
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

fn moving(note: &str) -> demesne_syntax::Spec {
    let src = format!(
        r#"definers schema "demesne_mv_auth"
tables schema "demesne_mv_rows"
topology {{ level tenant level workspace parent tenant }}
grant support at tenant via edge support_grants(holder_id, tenant_id)
subject staff {{ anchor tenant; reach via grant support; identifies sub; roles none }}
subject member {{ anchor workspace; reach self; identifies member_id; roles none; binds owner }}
object acl_entry {{
  table acl
  scoped tenant > workspace
  permission view = @store_manage @rls maps select
  permission edit = @store_manage @rls maps update
}}
object doc {{
  table docs
  scoped tenant > workspace
  relation owner: member via owner_id
  relation grantee: member via grant acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view = owner + grantee:read + grantee:write @rls maps select
  permission edit = owner + grantee:write @rls maps update
}}
{note}"#
    );
    let s = demesne_syntax::parse(&src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    s
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_spec_moves_between_the_stores_check_and_a_borrows_and_back_by_migrating() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_mv_rows CASCADE; DROP SCHEMA IF EXISTS demesne_mv_auth CASCADE;
         CREATE SCHEMA demesne_mv_rows; CREATE SCHEMA demesne_mv_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_mv_rows.support_grants (holder_id text, tenant_id text);
         CREATE TABLE demesne_mv_rows.acl (id text PRIMARY KEY, tenant_id text, workspace_id text, resource_type text, resource_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE demesne_mv_rows.docs (id text PRIMARY KEY, tenant_id text, workspace_id text, owner_id text);
         CREATE TABLE demesne_mv_rows.notes (id text PRIMARY KEY, tenant_id text, workspace_id text, doc_id text);
         CREATE FUNCTION demesne_mv_auth.doc_can_edit(p_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT false $$;",
    )
    .expect("fresh schemas, and the check as an earlier release named it");
    let store = moving("");
    let borrow = moving(
        "object note {\n  table notes\n  scoped tenant > workspace\n  relation doc: member via object doc->edit on doc_id\n  permission view = doc @rls maps select\n}\n",
    );
    let all = |s: &demesne_syntax::Spec| {
        let mut b = String::new();
        Sql::new(s).write_all_sql(&mut b).expect("the SQL compiles");
        b
    };
    db.batch_execute(&all(&store)).unwrap_or_else(|e| panic!("over the earlier name: {e:?}"));
    let named: Vec<String> =
        db.query_one("SELECT proargnames::text[] FROM pg_proc WHERE oid = 'demesne_mv_auth.doc_can_edit(text)'::regprocedure", &[]).expect("the check").get(0);
    assert_eq!(named, ["p_doc_id"], "the earlier name gave way");
    for (from, to, what) in [(&store, &borrow, "store to borrow"), (&borrow, &store, "borrow to store")] {
        let previous = Sql::new(from).manifest().expect("the previous manifest");
        let migration = Sql::new(to).migration(&previous).expect("the migration compiles");
        db.batch_execute(&migration).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        let d = demesne_postgres::drift(&mut db, &all(to), &[]).unwrap_or_else(|e| panic!("{what}: diff: {e}"));
        assert_eq!(d.findings, [], "{what}: the database is what the spec emits");
    }
}

fn renamed(subject: &str) -> demesne_syntax::Spec {
    let src = format!(
        "definers schema \"demesne_rn_auth\"
tables schema \"demesne_rn_rows\"
topology {{ level tenant }}
subject {subject} {{ anchor tenant; reach self; identifies member_id; roles none; binds owner }}
object doc {{
  table docs
  scoped tenant
  relation owner: {subject} via owner_id
  relation grantee: {subject} via grant acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + grantee:read @rls maps select
}}
object note {{
  table notes
  scoped tenant
  relation owner: {subject} via owner_id
  permission view = owner @rls maps select
}}
"
    );
    let s = demesne_syntax::parse(&src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    s
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn renaming_a_subject_migrates_although_a_parameter_is_named_after_it() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_rn_rows CASCADE; DROP SCHEMA IF EXISTS demesne_rn_auth CASCADE;
         CREATE SCHEMA demesne_rn_rows; CREATE SCHEMA demesne_rn_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_rn_rows.docs (id text PRIMARY KEY, tenant_id text, owner_id text);
         CREATE TABLE demesne_rn_rows.notes (id text PRIMARY KEY, tenant_id text, owner_id text);
         CREATE TABLE demesne_rn_rows.acl (doc_id text, principal_kind text, principal_id text, access text);",
    )
    .expect("fresh schemas");
    let (before, after) = (renamed("member"), renamed("customer"));
    let mut b = String::new();
    Sql::new(&before).write_all_sql(&mut b).expect("the SQL compiles");
    db.batch_execute(&b).unwrap_or_else(|e| panic!("apply: {e:?}"));
    let previous = Sql::new(&before).manifest().expect("a manifest");
    let migration = Sql::new(&after).migration(&previous).expect("the migration compiles");
    assert!(
        migration
            .starts_with("DROP POLICY IF EXISTS docs_select ON demesne_rn_rows.docs;\nDROP FUNCTION IF EXISTS demesne_rn_auth.acl_grants(text, text, text);\n"),
        "{migration:.300}"
    );
    let oids = |db: &mut Client| -> Vec<(String, u32)> {
        db.query(
            "SELECT polname::text, oid FROM pg_policy WHERE polrelid IN ('demesne_rn_rows.docs'::regclass, 'demesne_rn_rows.notes'::regclass) ORDER BY 1",
            &[],
        )
        .expect("the policies")
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
    };
    let was = oids(&mut db);
    db.batch_execute(&migration).unwrap_or_else(|e| panic!("the migration applies: {e:?}"));
    let is = oids(&mut db);
    let kept: Vec<&str> = was.iter().filter(|w| is.contains(w)).map(|(name, _)| name.as_str()).collect();
    assert_eq!(kept, ["notes_select"], "only the policy that calls the renamed check is created again: {was:?} -> {is:?}");
    let mut sql = String::new();
    Sql::new(&after).write_all_sql(&mut sql).expect("the SQL compiles");
    let d = demesne_postgres::drift(&mut db, &sql, &[]).unwrap_or_else(|e| panic!("diff: {e}"));
    assert_eq!(d.findings, [], "the database is what the renamed spec emits");
    let named: Vec<String> = db
        .query_one("SELECT proargnames::text[] FROM pg_proc WHERE oid = 'demesne_rn_auth.acl_grants(text, text, text)'::regprocedure", &[])
        .expect("the check")
        .get(0);
    assert_eq!(named[0], "p_customer_id", "{named:?}");
}

fn guarded(subject: &str) -> demesne_syntax::Spec {
    let src = format!(
        "definers schema \"demesne_tx_auth\"
tables schema \"demesne_tx_rows\"
topology {{ level tenant }}
subject {subject} {{ anchor tenant; reach self; identifies member_id; roles none; binds owner }}
object doc {{
  table docs
  scoped tenant
  relation owner: {subject} via owner_id
  relation grantee: {subject} via grant acl(doc_id, principal_kind, principal_id, access)
  permission view = owner @rls maps select
  require view = grantee
}}
"
    );
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    s
}

fn seen(reader: &mut Client) -> Result<i64, postgres::Error> {
    let mut tx = reader.transaction()?;
    tx.batch_execute(
        "SET LOCAL lock_timeout = '300ms'; SET LOCAL ROLE demesne_tx_reader;
         SELECT set_config('request.jwt.claims', '{\"member_id\":\"m1\",\"tenant_id\":\"t1\"}', true);",
    )?;
    let n = tx.query_one("SELECT count(*) FROM demesne_tx_rows.docs", &[])?.get(0);
    tx.rollback()?;
    Ok(n)
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_reader_never_sees_a_table_without_its_require_while_a_migration_renames_what_it_calls() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_tx_rows CASCADE; DROP SCHEMA IF EXISTS demesne_tx_auth CASCADE;
         CREATE SCHEMA demesne_tx_rows; CREATE SCHEMA demesne_tx_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'demesne_tx_reader') THEN CREATE ROLE demesne_tx_reader NOLOGIN; END IF; END $$;
         GRANT authenticated TO demesne_tx_reader;
         CREATE TABLE demesne_tx_rows.docs (id text PRIMARY KEY, tenant_id text, owner_id text);
         CREATE TABLE demesne_tx_rows.acl (doc_id text, principal_kind text, principal_id text, access text);
         INSERT INTO demesne_tx_rows.docs VALUES ('d1', 't1', 'm1');
         GRANT USAGE ON SCHEMA demesne_tx_rows, demesne_tx_auth TO demesne_tx_reader;
         GRANT SELECT ON ALL TABLES IN SCHEMA demesne_tx_rows TO demesne_tx_reader;",
    )
    .expect("fresh schemas, and a row its owner may read only without the require");
    let (before, after) = (guarded("member"), guarded("customer"));
    let mut b = String::new();
    Sql::new(&before).write_all_sql(&mut b).expect("the SQL compiles");
    db.batch_execute(&b).unwrap_or_else(|e| panic!("apply: {e:?}"));
    let mut reader = connect();
    assert_eq!(seen(&mut reader).expect("a read"), 0, "the require bars the owner, who holds no grant");
    let migration = Sql::new(&after).migration(&Sql::new(&before).manifest().expect("a manifest")).expect("the migration compiles");
    assert!(migration.contains("DROP POLICY IF EXISTS docs_select_require ON demesne_tx_rows.docs;"), "{migration:.400}");
    db.batch_execute(&format!("BEGIN;\n{migration}")).unwrap_or_else(|e| panic!("the migration, inside one transaction: {e:?}"));
    let waited = seen(&mut reader).expect_err("a read waits for the migration");
    assert_eq!(waited.code(), Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE), "{waited:?}");
    db.batch_execute("COMMIT").expect("commit");
    assert_eq!(seen(&mut reader).expect("a read"), 0, "after the migration the require bars the owner again");
    let back = Sql::new(&before).migration(&Sql::new(&after).manifest().expect("a manifest")).expect("the migration compiles");
    let (first, rest) = back.split_at(back.find("CREATE OR REPLACE FUNCTION").expect("the migration creates a function"));
    db.batch_execute(first).expect("the drops, outside a transaction");
    assert_eq!(seen(&mut reader).expect("a read"), 1, "without one transaction a reader sees the row the require bars");
    db.batch_execute(rest).expect("the rest");
    assert_eq!(seen(&mut reader).expect("a read"), 0);
}
