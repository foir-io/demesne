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

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_policy_that_calls_a_function_whose_argument_types_changed_is_created_again_though_its_text_is_the_same() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_rt_rows CASCADE; DROP SCHEMA IF EXISTS demesne_rt_auth CASCADE;
         CREATE SCHEMA demesne_rt_rows; CREATE SCHEMA demesne_rt_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_rt_rows.docs (id bigint PRIMARY KEY, tenant_id bigint, owner_id bigint);
         CREATE TABLE demesne_rt_rows.notes (id bigint PRIMARY KEY, tenant_id bigint, doc_id integer);",
    )
    .expect("fresh schemas");
    let src = "definers schema \"demesne_rt_auth\"\ntables schema \"demesne_rt_rows\"\nidentifiers bigint\ntopology { level tenant }\nsubject member { anchor tenant; reach self; identifies member_id; roles none; binds owner }\nobject doc {\n  table docs\n  scoped tenant\n  relation owner: member via owner_id\n  permission view = owner @rls maps select\n}\nobject note {\n  table notes\n  scoped tenant\n  relation doc: member via object doc->view on doc_id\n  permission view = doc @rls maps select\n}\n";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the SQL compiles");
    db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply: {e:?}"));
    let (wide, narrow) = ("demesne_rt_auth.doc_can_view(bigint)", "demesne_rt_auth.doc_can_view(integer)");
    let made = demesne_emit_sql::objects(&sql)
        .expect("objects")
        .into_iter()
        .find(|(o, _)| *o == demesne_emit_sql::Object::Function(wide.to_string()))
        .expect("the borrow")
        .1;
    let policy = demesne_emit_sql::objects(&sql)
        .expect("objects")
        .into_iter()
        .find(|(o, _)| matches!(o, demesne_emit_sql::Object::Policy { name, .. } if name == "notes_select"))
        .expect("the policy")
        .1;
    db.batch_execute(&format!(
        "DROP POLICY notes_select ON demesne_rt_rows.notes; DROP FUNCTION {wide}; {}; {policy};",
        made.replace("(p_doc_id bigint)", "(p_doc_id integer)")
    ))
    .expect("the borrow as an earlier spec typed it, and its policy, whose text is the same");
    let mut previous = Sql::new(&s).manifest().expect("a manifest");
    previous.execute = None;
    previous.functions.remove(wide);
    previous.functions.insert(narrow.to_string());
    let heads = previous.heads.as_mut().expect("heads");
    let head = heads.remove(wide).expect("the borrow's head");
    assert!(head.policies.iter().any(|(_, name)| name == "notes_select"), "{head:?}");
    heads.insert(narrow.to_string(), head);
    let digests = previous.digests.as_mut().expect("digests");
    let digest = digests.remove(&format!("function {wide}")).expect("the borrow's digest");
    digests.insert(format!("function {narrow}"), digest);
    let migration = Sql::new(&s).migration(&previous).expect("the migration compiles");
    assert!(migration.starts_with("DROP POLICY IF EXISTS notes_select ON demesne_rt_rows.notes;\n"), "{migration:.300}");
    db.batch_execute(&format!("BEGIN;\n{migration}COMMIT;")).unwrap_or_else(|e| panic!("the migration applies: {e:?}"));
    let d = demesne_postgres::drift(&mut db, &sql, &[]).unwrap_or_else(|e| panic!("diff: {e}"));
    assert_eq!(d.findings, [], "the database is what the spec emits");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_function_answers_only_for_its_own_subjects_identity_though_another_subject_shares_the_id() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_id_rows CASCADE; DROP SCHEMA IF EXISTS demesne_id_auth CASCADE;
         CREATE SCHEMA demesne_id_rows; CREATE SCHEMA demesne_id_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_id_rows.docs (id text PRIMARY KEY, tenant_id text, owner_id text);
         CREATE TABLE demesne_id_rows.acl (doc_id text, principal_kind text, principal_id text, access text);
         INSERT INTO demesne_id_rows.acl VALUES ('10', 'member', '1', 'read');
         GRANT USAGE ON SCHEMA demesne_id_rows, demesne_id_auth TO authenticated;",
    )
    .expect("fresh schemas, and member 1's grant on doc 10");
    let src = "definers schema \"demesne_id_auth\"\ntables schema \"demesne_id_rows\"\ntopology { level tenant }\nsubject member { anchor tenant; reach self; identifies member_id; roles none; binds owner }\nsubject operator { anchor tenant; reach self; identifies operator_id; roles none }\nobject doc {\n  table docs\n  scoped tenant\n  relation owner: member via owner_id\n  relation grantee: member via grant acl(doc_id, principal_kind, principal_id, access)\n  permission view = owner + grantee:read @rls maps select\n}\n";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the SQL compiles");
    db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply: {e:?}"));
    let asks = |db: &mut Client, claims: &str| -> bool {
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute(&format!("SET LOCAL ROLE authenticated; SELECT set_config('request.jwt.claims', '{claims}', true);")).expect("the claims");
        let held: Option<bool> = tx.query_one("SELECT demesne_id_auth.acl_grants('1', '10', 'read')", &[]).expect("the check").get(0);
        tx.rollback().expect("rollback");
        held.unwrap_or(false)
    };
    assert!(asks(&mut db, r#"{"member_id":"1","tenant_id":"7"}"#), "member 1 asks about its own grant");
    assert!(!asks(&mut db, r#"{"operator_id":"1","tenant_id":"7"}"#), "operator 1 shares the id, and is not member 1");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_relation_of_another_subject_than_the_owner_admits_that_subject_by_its_own_claim() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_gp_rows CASCADE; DROP SCHEMA IF EXISTS demesne_gp_auth CASCADE;
         CREATE SCHEMA demesne_gp_rows; CREATE SCHEMA demesne_gp_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_gp_rows.docs (id text PRIMARY KEY, tenant_id text, project_id text, owner_id text, team_id text);
         CREATE TABLE demesne_gp_rows.notes (id text PRIMARY KEY, tenant_id text, project_id text, circle_id text);
         CREATE TABLE demesne_gp_rows.boards (id text PRIMARY KEY, tenant_id text, project_id text, crew_id text);
         CREATE TABLE demesne_gp_rows.pages (id text PRIMARY KEY, tenant_id text, project_id text, folder_id text);
         CREATE TABLE demesne_gp_rows.tc (grp text, mem text);
         CREATE TABLE demesne_gp_rows.te (mem text, grp text);
         CREATE TABLE demesne_gp_rows.folders (id text PRIMARY KEY, parent_id text);
         CREATE TABLE demesne_gp_rows.folder_paths (ancestor_id text, descendant_id text, PRIMARY KEY (ancestor_id, descendant_id));",
    )
    .expect("fresh schemas");
    let path = format!("{}/../../testdata/bindings/group-of-another-subject.demesne", env!("CARGO_MANIFEST_DIR"));
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s = demesne_syntax::parse(&format!("definers schema \"demesne_gp_auth\"\ntables schema \"demesne_gp_rows\"\n{body}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the SQL compiles");
    db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply: {e:?}"));
    db.batch_execute(
        "SET search_path = demesne_gp_rows;
         INSERT INTO te VALUES ('s1', 'g1'), ('c5', 'g2'), ('s2', 'g3');
         INSERT INTO docs VALUES ('d1', 't1', 'p1', 'c9', 'g1');
         INSERT INTO notes VALUES ('n1', 't1', 'p1', 'g2');
         INSERT INTO boards VALUES ('b1', 't1', 'p1', 'g3');
         INSERT INTO folders VALUES ('s1', NULL), ('f2', 's1');
         INSERT INTO pages VALUES ('q1', 't1', 'p1', 'f2');
         RESET search_path;
         GRANT USAGE ON SCHEMA demesne_gp_rows, demesne_gp_auth TO authenticated;
         GRANT SELECT ON ALL TABLES IN SCHEMA demesne_gp_rows TO authenticated;",
    )
    .expect("staff s1 in team g1 and over folder f2, customer c5 in circle g2, staff s2 in crew g3");
    let read = |db: &mut Client, claims: &str, sql: &str| -> i64 {
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute("SET LOCAL ROLE authenticated").expect("the role");
        tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
        let n: i64 = tx.query_one(sql, &[]).unwrap_or_else(|e| panic!("{sql} under {claims}: {e:?}")).get(0);
        tx.rollback().expect("rollback");
        n
    };
    let scoped = |identity: &str| format!(r#"{{{identity},"tenant_id":"t1","project_id":"p1"}}"#);
    let count = |table: &str| format!("SELECT count(*) FROM demesne_gp_rows.{table}");
    let cases: [(&str, &str, &str, i64); 13] = [
        ("staff s1 is in team g1", r#""sub":"s1""#, "docs", 1),
        ("staff s2 is not", r#""sub":"s2""#, "docs", 0),
        ("customer c9 owns d1", r#""customer_id":"c9""#, "docs", 1),
        ("a credential carrying a customer is judged as that customer, not as staff s1", r#""customer_id":"c7","sub":"s1""#, "docs", 0),
        ("customer c5 is in circle g2, over a closure staff relations share", r#""customer_id":"c5""#, "notes", 1),
        ("staff s1 is not in circle g2", r#""sub":"s1""#, "notes", 0),
        ("staff s2 is in crew g3, through the flat", r#""sub":"s2""#, "boards", 1),
        ("staff s1 is not", r#""sub":"s1""#, "boards", 0),
        ("a credential carrying a customer is not staff s2 on the flat", r#""customer_id":"c7","sub":"s2""#, "boards", 0),
        ("staff s1 reaches folder f2", r#""sub":"s1""#, "pages", 1),
        ("staff s2 does not", r#""sub":"s2""#, "pages", 0),
        ("the crew's boards for staff s2", r#""sub":"s2""#, "resources", 1),
        ("none for staff s1", r#""sub":"s1""#, "resources", 0),
    ];
    for (why, identity, table, want) in cases {
        let sql = if table == "resources" { "SELECT count(*) FROM demesne_gp_auth.boards_crew_flat_resources()".to_string() } else { count(table) };
        assert_eq!(read(&mut db, &scoped(identity), &sql), want, "{why}");
    }
    db.batch_execute("DROP SCHEMA demesne_gp_rows CASCADE; DROP SCHEMA demesne_gp_auth CASCADE;").expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn an_operator_identified_as_the_staff_are_holds_every_role_where_it_presents_a_scope() {
    let mut db = connect();
    db.batch_execute(
        "DROP SCHEMA IF EXISTS demesne_op_rows CASCADE; DROP SCHEMA IF EXISTS demesne_op_auth CASCADE;
         CREATE SCHEMA demesne_op_rows; CREATE SCHEMA demesne_op_auth;
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
         CREATE TABLE demesne_op_rows.resources (id text PRIMARY KEY, tenant_id text, project_id text);
         CREATE TABLE demesne_op_rows.roles (id text PRIMARY KEY, key text);
         CREATE TABLE demesne_op_rows.role_grants (grantee_kind text, grantee_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);
         CREATE TABLE demesne_op_rows.ops_users (user_ref text PRIMARY KEY, is_ops boolean, state text);",
    )
    .expect("fresh schemas");
    let path = format!("{}/../../testdata/bindings/operator-holds-every-role.demesne", env!("CARGO_MANIFEST_DIR"));
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s = demesne_syntax::parse(&format!("definers schema \"demesne_op_auth\"\ntables schema \"demesne_op_rows\"\n{body}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the SQL compiles");
    db.batch_execute(&sql).unwrap_or_else(|e| panic!("apply: {e:?}"));
    db.batch_execute(
        "INSERT INTO demesne_op_rows.ops_users VALUES ('o1', true, 'ON');
         INSERT INTO demesne_op_rows.resources VALUES ('r1', 't1', 'p1');
         GRANT USAGE ON SCHEMA demesne_op_rows, demesne_op_auth TO authenticated;
         GRANT SELECT ON ALL TABLES IN SCHEMA demesne_op_rows TO authenticated;",
    )
    .expect("operator o1, holding no role, and a resource in tenant t1");
    let read = |db: &mut Client, claims: &str| -> i64 {
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute("SET LOCAL ROLE authenticated").expect("the role");
        tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
        let n: i64 = tx.query_one("SELECT count(*) FROM demesne_op_rows.resources", &[]).expect("the read").get(0);
        tx.rollback().expect("rollback");
        n
    };
    let cases = [
        (
            "operator o1 presenting the project's scope holds the tenant's owner role, through the role check alone",
            r#"{"sub":"o1","tenant_id":"t1","project_id":"p1"}"#,
            1,
        ),
        ("o1 presenting no project is admitted by the operator's own branch", r#"{"sub":"o1"}"#, 1),
        ("a staff member with no role is not", r#"{"sub":"s9","tenant_id":"t1","project_id":"p1"}"#, 0),
    ];
    for (why, claims, want) in cases {
        assert_eq!(read(&mut db, claims), want, "{why}");
    }
    db.batch_execute("DROP SCHEMA demesne_op_rows CASCADE; DROP SCHEMA demesne_op_auth CASCADE;").expect("drop the schemas");
}
