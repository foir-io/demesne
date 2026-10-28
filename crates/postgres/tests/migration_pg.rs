use demesne_emit_sql::Sql;
use postgres::{Client, NoTls};

const HEADER: &str = r"
topology {
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}

subject member { anchor workspace; reach self; identifies member_ref; roles none; binds owner }
";

const DOC: &str = r#"
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
CREATE TABLE note_shares (note_ref text, grantee_kind text, grantee_ref text, perm text);
";

const GONE: &[&str] = &[
    "function {p}_auth.note_acl_grants(text,text,text)",
    "function {p}_auth.docs_obj_changelog()",
    "policy docs_select on {p}_rows.docs",
    "trigger docs_obj_changelog on {p}_rows.docs",
    "index {p}_auth._authz_changelog_seq_idx",
    "index {p}_auth._authz_changelog_principal_idx",
];

struct Surfaces {
    prefix: &'static str,
    before: demesne_syntax::Spec,
    after: demesne_syntax::Spec,
}

impl Surfaces {
    fn new(prefix: &'static str) -> Self {
        let schemas = format!("definers schema \"{prefix}_auth\"\ntables schema \"{prefix}_rows\"\n");
        Self { prefix, before: spec(&format!("{schemas}{HEADER}{}{DOC}", note("note_acl"))), after: spec(&format!("{schemas}{HEADER}{}", note("note_shares"))) }
    }

    fn name(&self, template: &str) -> String {
        template.replace("{p}", self.prefix)
    }

    fn gone(&self) -> Vec<String> {
        GONE.iter().map(|g| self.name(g)).collect()
    }

    fn install(&self, db: &mut Client) -> Vec<String> {
        let schemas = self.name("DROP SCHEMA IF EXISTS {p}_rows CASCADE; DROP SCHEMA IF EXISTS {p}_auth CASCADE; CREATE SCHEMA {p}_rows; CREATE SCHEMA {p}_auth; SET search_path = {p}_rows;");
        apply(db, &format!("{schemas} {TABLES} RESET search_path;"));
        apply(db, &all_sql(&self.before));
        self.present(db)
    }

    fn migration(&self) -> String {
        let previous = Sql::new(&self.before).manifest().expect("the previous surface has a manifest");
        Sql::new(&self.after).migration(&previous).expect("the migration compiles")
    }

    fn present(&self, db: &mut Client) -> Vec<String> {
        let q = self.name(
            "SELECT 'function ' || p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace = '{p}_auth'::regnamespace
             UNION ALL SELECT 'policy ' || polname || ' on ' || polrelid::regclass::text FROM pg_policy WHERE polrelid::regclass::text LIKE '{p}_rows.%'
             UNION ALL SELECT 'trigger ' || tgname || ' on ' || tgrelid::regclass::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid::regclass::text LIKE '{p}_rows.%'
             UNION ALL SELECT 'index ' || c.oid::regclass::text FROM pg_class c WHERE c.relkind = 'i' AND c.relnamespace = '{p}_auth'::regnamespace
             ORDER BY 1",
        );
        db.query(&q, &[]).expect("the catalog query").iter().map(|r| r.get(0)).collect()
    }
}

fn note(grants: &str) -> String {
    format!(
        r#"
object note {{
  table  notes
  pk     note_pk
  scoped org > workspace
  relation owner:   member via owner_ref
  relation grantee: member via grant {grants}(note_ref, grantee_kind, grantee_ref, perm)
  permission view = owner + mode visibility = "open" + grantee:read @rls maps select
}}
"#
    )
}

fn spec(src: &str) -> demesne_syntax::Spec {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    s
}

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to run the migration against a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn apply(db: &mut Client, sql: &str) {
    db.batch_execute(sql).unwrap_or_else(|e| panic!("apply: {e}\n{sql}"));
}

fn all_sql(s: &demesne_syntax::Spec) -> String {
    let mut b = String::new();
    Sql::new(s).write_all_sql(&mut b).expect("the SQL compiles");
    b
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_migration_drops_what_the_spec_stopped_emitting() {
    let mut db = connect();
    let sf = Surfaces::new("d15_drops");
    let installed = sf.install(&mut db);
    let missing: Vec<String> = sf.gone().into_iter().filter(|g| !installed.contains(g)).collect();
    assert!(missing.is_empty(), "the previous surface never created {missing:?}; live: {installed:?}");

    apply(&mut db, &all_sql(&sf.after));
    let live = sf.present(&mut db);
    let kept: Vec<String> = sf.gone().into_iter().filter(|g| live.contains(g)).collect();
    assert_eq!(kept, sf.gone(), "the plain SQL leaves every superseded object in place; live: {live:?}");

    apply(&mut db, &sf.migration());
    let live = sf.present(&mut db);
    let survived: Vec<String> = sf.gone().into_iter().filter(|g| live.contains(g)).collect();
    assert!(survived.is_empty(), "the migration left {survived:?}; live: {live:?}");
    for want in
        ["function {p}_auth.note_shares_grants(text,text,text)", "function {p}_auth.notes_accessors_conditional(text)", "policy notes_select on {p}_rows.notes"]
    {
        assert!(live.contains(&sf.name(want)), "the migration removed {want}; live: {live:?}");
    }
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_migration_fails_whole_when_a_dropped_name_survives_under_another_signature() {
    let mut db = connect();
    let sf = Surfaces::new("d15_overload");
    sf.install(&mut db);
    apply(&mut db, &sf.name("CREATE FUNCTION {p}_auth.note_acl_grants(text, text) RETURNS boolean LANGUAGE sql AS 'SELECT true'"));
    let before = sf.present(&mut db);

    let err = db.batch_execute(&sf.migration()).expect_err("an overload of a dropped function survives the exact drop");
    let msg = err.as_db_error().map_or_else(|| err.to_string(), |e| e.message().to_string());
    assert_eq!(msg, sf.name("demesne: still present after the drops: function {p}_auth.note_acl_grants(text,text)"));
    assert_eq!(sf.present(&mut db), before, "a failed migration must change nothing");
}
