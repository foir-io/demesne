use demesne_emit_sql::Sql;
use postgres::{Client, NoTls};

const TENANT: u32 = 1;
const PROJECT: u32 = 2;
const MEMBER: u32 = 10;
const STRANGER: u32 = 11;
const VIEWER: u32 = 20;
const OWNER: u32 = 21;
const HELPER: u32 = 30;
const UNHELPED: u32 = 31;
const OWNED: u32 = 40;
const GRANTED: u32 = 41;
const CHILD: u32 = 42;
const TEAMED: u32 = 43;
const NOBODYS: u32 = 44;
const TEAM: u32 = 50;
const NOTE: u32 = 60;
const STRAY_NOTE: u32 = 61;
const LEDGER: u32 = 70;
const OTHER_LEDGER: u32 = 71;
const RESOURCE: u32 = 80;
const SHARED: u32 = 90;
const UNSHARED: u32 = 91;
const GRANT: u32 = 100;
const VIEWER_ROLE: u32 = 200;
const OWNER_ROLE: u32 = 201;
const SUBFOLDER: u32 = 110;
const LOOSE_FOLDER: u32 = 111;
const PAGE: u32 = 120;
const LOOSE_PAGE: u32 = 121;
const OPERATOR: u32 = 32;
const LAPSED: u32 = 33;
const NEW_FOLDER: u32 = 112;
const BOARD: u32 = 130;
const LOOSE_BOARD: u32 = 131;

const NAMED: [(&str, u32); 33] = [
    ("TENANT", TENANT),
    ("PROJECT", PROJECT),
    ("MEMBER", MEMBER),
    ("STRANGER", STRANGER),
    ("VIEWER", VIEWER),
    ("OWNER", OWNER),
    ("HELPER", HELPER),
    ("UNHELPED", UNHELPED),
    ("OWNED", OWNED),
    ("GRANTED", GRANTED),
    ("CHILD", CHILD),
    ("TEAMED", TEAMED),
    ("NOBODYS", NOBODYS),
    ("TEAM", TEAM),
    ("NOTE", NOTE),
    ("STRAY_NOTE", STRAY_NOTE),
    ("LEDGER", LEDGER),
    ("OTHER_LEDGER", OTHER_LEDGER),
    ("RESOURCE", RESOURCE),
    ("SHARED", SHARED),
    ("UNSHARED", UNSHARED),
    ("GRANT", GRANT),
    ("VIEWER_ROLE", VIEWER_ROLE),
    ("OWNER_ROLE", OWNER_ROLE),
    ("SUBFOLDER", SUBFOLDER),
    ("LOOSE_FOLDER", LOOSE_FOLDER),
    ("PAGE", PAGE),
    ("LOOSE_PAGE", LOOSE_PAGE),
    ("OPERATOR", OPERATOR),
    ("LAPSED", LAPSED),
    ("NEW_FOLDER", NEW_FOLDER),
    ("BOARD", BOARD),
    ("LOOSE_BOARD", LOOSE_BOARD),
];

const TABLES: &str = "
CREATE TABLE docs (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, owner_id <T>, parent_id <T>, team_id <T>);
CREATE TABLE acl (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, resource_type text, resource_id <T>, principal_kind text, principal_id <T>, access text);
CREATE TABLE tc (grp <T>, mem <T>);
CREATE TABLE te (mem <T>, grp <T>);
CREATE TABLE notes (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, doc_id <T>);
CREATE TABLE ledgers (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, owner_id <T>);
CREATE TABLE resources (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>);
CREATE TABLE roles (id <T> PRIMARY KEY, key text);
CREATE TABLE role_grants (grantee_kind text, grantee_id <T>, tenant_id <T>, project_id <T>, role_id <T>, revoked_at timestamptz);
CREATE TABLE support_grants (holder_id <T>, tenant_id <T>);
CREATE TABLE folios (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, rules_live text[]);
CREATE TABLE folio_shares (member_id <T>, folio_id <T>, rule_id text);
CREATE TABLE folders (id <T> PRIMARY KEY, parent_id <T>);
CREATE TABLE folder_paths (ancestor_id <T>, descendant_id <T>, PRIMARY KEY (ancestor_id, descendant_id));
CREATE TABLE pages (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, folder_id <T>);
CREATE TABLE ops_users (user_ref <T> PRIMARY KEY, is_ops boolean, state text);
CREATE TABLE boards (id <T> PRIMARY KEY, tenant_id <T>, project_id <T>, crew_id <T>);
";

const ROWS: &str = "
INSERT INTO roles VALUES (<VIEWER_ROLE>, 'viewer'), (<OWNER_ROLE>, 'owner');
INSERT INTO role_grants VALUES ('staff', <VIEWER>, <TENANT>, <PROJECT>, <VIEWER_ROLE>, NULL), ('staff', <OWNER>, <TENANT>, NULL, <OWNER_ROLE>, NULL);
INSERT INTO support_grants VALUES (<HELPER>, <TENANT>);
INSERT INTO docs VALUES
  (<OWNED>, <TENANT>, <PROJECT>, <MEMBER>, NULL, NULL),
  (<GRANTED>, <TENANT>, <PROJECT>, <STRANGER>, NULL, NULL),
  (<CHILD>, <TENANT>, <PROJECT>, NULL, <OWNED>, NULL),
  (<TEAMED>, <TENANT>, <PROJECT>, NULL, NULL, <TEAM>),
  (<NOBODYS>, <TENANT>, <PROJECT>, NULL, NULL, NULL);
INSERT INTO acl VALUES (<GRANT>, <TENANT>, <PROJECT>, 'doc', <GRANTED>, 'member', <MEMBER>, 'read');
INSERT INTO te VALUES (<MEMBER>, <TEAM>);
INSERT INTO notes VALUES (<NOTE>, <TENANT>, <PROJECT>, <OWNED>), (<STRAY_NOTE>, <TENANT>, <PROJECT>, <NOBODYS>);
INSERT INTO ledgers VALUES (<LEDGER>, <TENANT>, <PROJECT>, <MEMBER>), (<OTHER_LEDGER>, <TENANT>, <PROJECT>, <STRANGER>);
INSERT INTO resources VALUES (<RESOURCE>, <TENANT>, <PROJECT>);
INSERT INTO folios VALUES (<SHARED>, <TENANT>, <PROJECT>, '{read.a}'), (<UNSHARED>, <TENANT>, <PROJECT>, '{read.a}');
INSERT INTO folio_shares VALUES (<MEMBER>, <SHARED>, 'read.a');
INSERT INTO folders VALUES (<MEMBER>, NULL), (<SUBFOLDER>, <MEMBER>), (<LOOSE_FOLDER>, NULL);
INSERT INTO pages VALUES (<PAGE>, <TENANT>, <PROJECT>, <SUBFOLDER>), (<LOOSE_PAGE>, <TENANT>, <PROJECT>, <LOOSE_FOLDER>);
INSERT INTO ops_users VALUES (<OPERATOR>, true, 'ON'), (<LAPSED>, true, 'OFF');
INSERT INTO boards VALUES (<BOARD>, <TENANT>, <PROJECT>, <TEAM>), (<LOOSE_BOARD>, <TENANT>, <PROJECT>, NULL);
";

const FORGED: &str = "
INSERT INTO pg_temp.ops_users VALUES (<LAPSED>, true, 'ON');
INSERT INTO pg_temp.roles VALUES (<VIEWER_ROLE>, 'viewer'), (<OWNER_ROLE>, 'owner');
INSERT INTO pg_temp.role_grants VALUES ('staff', <OWNER>, <TENANT>, <PROJECT>, <VIEWER_ROLE>, NULL), ('staff', <VIEWER>, <TENANT>, NULL, <OWNER_ROLE>, NULL);
INSERT INTO pg_temp.acl VALUES (<GRANT>, <TENANT>, <PROJECT>, 'doc', <GRANTED>, 'member', <MEMBER>, 'write');
INSERT INTO pg_temp.support_grants VALUES (<UNHELPED>, <TENANT>);
INSERT INTO pg_temp.tc VALUES (<TEAM>, <STRANGER>);
INSERT INTO pg_temp.te VALUES (<STRANGER>, <TEAM>);
INSERT INTO pg_temp.folio_shares VALUES (<MEMBER>, <UNSHARED>, 'read.a');
INSERT INTO pg_temp.folder_paths VALUES (<MEMBER>, <LOOSE_FOLDER>);
INSERT INTO pg_temp.docs VALUES (<NOBODYS>, <TENANT>, <PROJECT>, <MEMBER>, NULL, NULL);
INSERT INTO pg_temp.ledgers VALUES (<OTHER_LEDGER>, <TENANT>, <PROJECT>, <MEMBER>);
INSERT INTO pg_temp.boards VALUES (<LOOSE_BOARD>, <TENANT>, <PROJECT>, <TEAM>);
";

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to apply a spec's SQL to a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

struct World {
    ty: &'static str,
    rows: String,
    auth: String,
}

impl World {
    fn new(ty: &'static str, what: &str) -> Self {
        Self { ty, rows: format!("demesne_ids_{ty}_{what}_rows"), auth: format!("demesne_ids_{ty}_{what}_auth") }
    }

    fn id(&self, n: u32) -> String {
        if self.ty == "uuid" { format!("00000000-0000-4000-8000-{n:012}") } else { n.to_string() }
    }

    fn lit(&self, n: u32) -> String {
        format!("'{}'", self.id(n))
    }

    fn ids(&self, ns: &[u32]) -> Vec<String> {
        let mut out: Vec<String> = ns.iter().map(|n| self.id(*n)).collect();
        out.sort();
        out
    }

    fn claims(&self, pairs: &[(&str, u32)], held: &[&str]) -> String {
        let mut fields: Vec<String> = pairs.iter().map(|(k, v)| format!("\"{k}\":\"{}\"", self.id(*v))).collect();
        if !held.is_empty() {
            let held: Vec<String> = held.iter().map(|h| format!("\"{h}\"")).collect();
            fields.push(format!("\"rules_held\":[{}]", held.join(",")));
        }
        format!("{{{}}}", fields.join(","))
    }

    fn fill(&self, template: &str) -> String {
        NAMED.iter().fold(template.replace("<T>", self.ty), |sql, (name, n)| sql.replace(&format!("<{name}>"), &self.lit(*n)))
    }

    fn build(&self, db: &mut Client) {
        let (rows, auth) = (&self.rows, &self.auth);
        db.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {rows} CASCADE; DROP SCHEMA IF EXISTS {auth} CASCADE; CREATE SCHEMA {rows}; CREATE SCHEMA {auth}; SET search_path = {rows};
             DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
             {} RESET search_path;",
            self.fill(TABLES)
        ))
        .expect("fresh schemas and tables of the spec's id type");
        let path = format!("{}/../../testdata/ids/{}.demesne", env!("CARGO_MANIFEST_DIR"), self.ty);
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let spec = demesne_syntax::parse(&format!("definers schema \"{auth}\"\ntables schema \"{rows}\"\n{body}")).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        demesne_emit_sql::validate(&spec).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        let mut sql = String::new();
        Sql::new(&spec).write_all_sql(&mut sql).unwrap_or_else(|e| panic!("{path}: {e}"));
        db.batch_execute(&sql).unwrap_or_else(|e| panic!("{path}: the SQL applies: {e:?}"));
        db.batch_execute(&format!(
            "SET search_path = {rows}; {} RESET search_path; GRANT USAGE ON SCHEMA {rows}, {auth} TO authenticated; GRANT SELECT ON ALL TABLES IN SCHEMA {rows} TO authenticated;",
            self.fill(ROWS)
        ))
        .expect("the rows");
    }

    fn shadow(&self, db: &mut Client) {
        let tables: Vec<String> = db
            .query("SELECT tablename::text FROM pg_tables WHERE schemaname = $1 ORDER BY 1", &[&self.rows])
            .expect("the tables")
            .iter()
            .map(|row| row.get(0))
            .collect();
        let shadows: Vec<String> = tables.iter().map(|t| format!("CREATE TEMP TABLE {t} (LIKE {}.{t});", self.rows)).collect();
        db.batch_execute(&format!(
            "DO $$ BEGIN PERFORM pg_advisory_xact_lock(hashtext('demesne_ids_temporary')); IF NOT has_database_privilege('authenticated', current_database(), 'TEMPORARY') THEN EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO authenticated', current_database()); END IF; END $$;
             SET ROLE authenticated; {} {} RESET ROLE;",
            shadows.join(" "),
            self.fill(FORGED)
        ))
        .unwrap_or_else(|e| panic!("{}: a session holding TEMPORARY shadows every table: {e:?}", self.ty));
    }

    fn visible(&self, db: &mut Client, claims: &str, table: &str) -> Vec<String> {
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute("SET LOCAL ROLE authenticated").expect("the role");
        tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
        let got = tx
            .query(&format!("SELECT id::text FROM {}.{table} ORDER BY 1", self.rows), &[])
            .unwrap_or_else(|e| panic!("{}: {table} under {claims}: {e:?}", self.ty))
            .iter()
            .map(|row| row.get(0))
            .collect();
        tx.rollback().expect("rollback");
        got
    }

    fn answer(&self, db: &mut Client, claims: &str, caller: bool, call: &str) -> bool {
        let (setup, call) = call.rsplit_once("; ").unwrap_or(("", call));
        let mut tx = db.transaction().expect("a transaction");
        tx.batch_execute(setup).unwrap_or_else(|e| panic!("{}: {setup}: {e:?}", self.ty));
        if caller {
            tx.batch_execute("SET LOCAL ROLE authenticated").expect("the role");
        }
        tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
        let got = tx.query_one(&format!("SELECT ({call}) IS TRUE"), &[]).unwrap_or_else(|e| panic!("{}: {call} under {claims}: {e:?}", self.ty)).get(0);
        tx.rollback().expect("rollback");
        got
    }
}

struct Callers {
    member: String,
    unheld: String,
    stranger: String,
    helped: String,
    unhelped: String,
    viewer: String,
    owner: String,
    operator: String,
    lapsed: String,
    supporter: String,
}

impl Callers {
    fn new(w: &World) -> Self {
        Self {
            member: w.claims(&[("member_id", MEMBER), ("tenant_id", TENANT), ("project_id", PROJECT)], &["read.a"]),
            unheld: w.claims(&[("member_id", MEMBER), ("tenant_id", TENANT), ("project_id", PROJECT)], &[]),
            stranger: w.claims(&[("member_id", STRANGER), ("tenant_id", TENANT), ("project_id", PROJECT)], &["read.a"]),
            helped: w.claims(&[("member_id", MEMBER), ("sub", HELPER), ("project_id", PROJECT)], &[]),
            unhelped: w.claims(&[("member_id", MEMBER), ("sub", UNHELPED), ("project_id", PROJECT)], &[]),
            viewer: w.claims(&[("staff_id", VIEWER), ("tenant_id", TENANT), ("project_id", PROJECT)], &[]),
            owner: w.claims(&[("staff_id", OWNER), ("tenant_id", TENANT), ("project_id", PROJECT)], &[]),
            operator: w.claims(&[("operator_id", OPERATOR)], &[]),
            lapsed: w.claims(&[("operator_id", LAPSED)], &[]),
            supporter: w.claims(&[("staff_id", HELPER), ("sub", HELPER), ("tenant_id", TENANT), ("project_id", PROJECT)], &[]),
        }
    }
}

fn each_caller_sees_its_rows(w: &World, db: &mut Client, c: &Callers) {
    let Callers { member, unheld, stranger, helped, unhelped, viewer, owner, operator, lapsed, supporter } = c;
    let rows: [(&str, &str, &[u32]); 25] = [
        (member, "docs", &[OWNED, GRANTED, CHILD, TEAMED]),
        (stranger, "docs", &[GRANTED]),
        (helped, "docs", &[OWNED, GRANTED, CHILD, TEAMED]),
        (unhelped, "docs", &[]),
        (viewer, "docs", &[]),
        (member, "notes", &[NOTE]),
        (stranger, "notes", &[]),
        (member, "ledgers", &[LEDGER]),
        (stranger, "ledgers", &[OTHER_LEDGER]),
        (member, "folios", &[SHARED]),
        (unheld, "folios", &[]),
        (stranger, "folios", &[]),
        (member, "acl", &[]),
        (stranger, "acl", &[GRANT]),
        (viewer, "resources", &[RESOURCE]),
        (owner, "resources", &[RESOURCE]),
        (member, "resources", &[]),
        (helped, "notes", &[NOTE]),
        (member, "pages", &[PAGE]),
        (stranger, "pages", &[]),
        (operator, "docs", &[OWNED, GRANTED, CHILD, TEAMED, NOBODYS]),
        (lapsed, "docs", &[]),
        (member, "boards", &[BOARD]),
        (stranger, "boards", &[]),
        (supporter, "resources", &[]),
    ];
    for (claims, table, want) in rows {
        assert_eq!(w.visible(db, claims, table), w.ids(want), "{}: {table} under {claims}", w.ty);
    }
}

fn each_function_admits_and_refuses(w: &World, db: &mut Client, c: &Callers) {
    let Callers { member, stranger, helped, unhelped, viewer, owner, operator, lapsed, supporter, .. } = c;
    let (a, i) = (&w.auth, |n| w.lit(n));
    let calls: Vec<(&str, bool, String, bool)> = vec![
        (operator, true, format!("{a}.is_ops({})", i(OPERATOR)), true),
        (lapsed, true, format!("{a}.is_ops({})", i(LAPSED)), false),
        (member, true, format!("{a}.boards_crew_flat_member({}, {})", i(BOARD), i(MEMBER)), true),
        (member, true, format!("{a}.boards_crew_flat_member({}, {})", i(LOOSE_BOARD), i(MEMBER)), false),
        (member, true, format!("{} IN (SELECT {a}.boards_crew_flat_resources())", i(BOARD)), true),
        (stranger, true, format!("{} IN (SELECT {a}.boards_crew_flat_resources())", i(BOARD)), false),
        ("{}", false, format!("{a}.boards_crew_flat_reconcile() = 0"), true),
        ("{}", false, format!("DELETE FROM {a}.boards_crew_flat; {a}.boards_crew_flat_reconcile() = 0"), false),
        (member, true, format!("{a}.member_can_access_ledger({}, {}, 'edit')", i(MEMBER), i(LEDGER)), true),
        (member, true, format!("{a}.member_can_access_ledger({}, {}, 'edit')", i(MEMBER), i(OTHER_LEDGER)), false),
        (stranger, true, format!("{a}.member_can_access_ledger({}, {}, 'edit')", i(MEMBER), i(LEDGER)), false),
        (member, true, format!("{a}.acl_grants_doc({}, {}, 'read')", i(MEMBER), i(GRANTED)), true),
        (member, true, format!("{a}.acl_grants_doc({}, {}, 'write')", i(MEMBER), i(GRANTED)), false),
        (member, true, format!("{a}.tc_member({}, {})", i(TEAM), i(MEMBER)), true),
        (stranger, true, format!("{a}.tc_member({}, {})", i(TEAM), i(STRANGER)), false),
        (member, true, format!("{a}.folio_shared_keyed({}, {}, 'read.a')", i(MEMBER), i(SHARED)), true),
        (member, true, format!("{a}.folio_shared_keyed({}, {}, 'read.a')", i(MEMBER), i(UNSHARED)), false),
        (member, true, format!("{a}.doc_composition_parent({}, 'read')", i(CHILD)), true),
        (member, true, format!("{a}.doc_composition_parent({}, 'read')", i(NOBODYS)), false),
        (member, true, format!("{a}.folder_paths_reachable({}, {})", i(MEMBER), i(SUBFOLDER)), true),
        (member, true, format!("{a}.folder_paths_reachable({}, {})", i(MEMBER), i(LOOSE_FOLDER)), false),
        (member, true, format!("{a}.doc_can_view({})", i(OWNED)), true),
        (member, true, format!("{a}.doc_can_view({})", i(NOBODYS)), false),
        (stranger, true, format!("{a}.acl_manage('doc', {})", i(GRANTED)), true),
        (member, true, format!("{a}.acl_manage('doc', {})", i(GRANTED)), false),
        (viewer, true, format!("{a}.staff_has_resource_role({}, {}, {})", i(VIEWER), i(TENANT), i(PROJECT)), true),
        (owner, true, format!("{a}.staff_has_resource_role({}, {}, {})", i(OWNER), i(TENANT), i(PROJECT)), false),
        (owner, true, format!("{a}.is_tenant_staff({}, {})", i(OWNER), i(TENANT)), true),
        (viewer, true, format!("{a}.is_tenant_staff({}, {})", i(VIEWER), i(TENANT)), false),
        (supporter, true, format!("{a}.is_tenant_staff({}, {})", i(HELPER), i(TENANT)), false),
        (helped, true, format!("{} IN (SELECT {a}.support_grants_reach_set({}))", i(TENANT), i(HELPER)), true),
        (unhelped, true, format!("{} IN (SELECT {a}.support_grants_reach_set({}))", i(TENANT), i(UNHELPED)), false),
        (stranger, false, format!("{a}.doc_can_edit({})", i(GRANTED)), true),
        (member, false, format!("{a}.doc_can_edit({})", i(GRANTED)), false),
        ("{}", false, format!("{a}.docs_admits({}, '{member}')", i(OWNED)), true),
        ("{}", false, format!("{a}.docs_admits({}, '{member}')", i(NOBODYS)), false),
        ("{}", false, format!("{} IN (SELECT principal_id FROM {a}.docs_accessors({}))", i(MEMBER), i(CHILD)), true),
        ("{}", false, format!("{} IN (SELECT principal_id FROM {a}.docs_accessors({}))", i(MEMBER), i(NOBODYS)), false),
        ("{}", false, format!("{} IN (SELECT principal_id FROM {a}.docs_direct_accessors({}))", i(MEMBER), i(TEAMED)), true),
        ("{}", false, format!("{} IN (SELECT principal_id FROM {a}.docs_direct_accessors({}))", i(STRANGER), i(TEAMED)), false),
    ];
    for (claims, caller, call, want) in &calls {
        assert_eq!(w.answer(db, claims, *caller, call), *want, "{}: {call} under {claims}", w.ty);
    }
    let made: Vec<String> = db
        .query("SELECT p.proname::text FROM pg_proc p WHERE p.pronamespace = to_regnamespace($1) AND p.prorettype <> 'trigger'::regtype ORDER BY 1", &[&w.auth])
        .expect("the functions")
        .iter()
        .map(|row| row.get(0))
        .collect();
    let tried = |f: &String, want: bool| calls.iter().any(|(_, _, call, w)| *w == want && call.contains(&format!(".{f}(")));
    let untried: Vec<&String> = made.iter().filter(|f| !(tried(f, true) && tried(f, false))).collect();
    assert!(untried.is_empty(), "{}: every function the spec makes is answered here, admitting and refusing: {untried:?}", w.ty);
}

fn admits_and_refuses_through_every_generator_taking_an_id(ty: &'static str) {
    let w = World::new(ty, "plain");
    let mut db = connect();
    w.build(&mut db);
    let callers = Callers::new(&w);
    each_caller_sees_its_rows(&w, &mut db, &callers);
    each_function_admits_and_refuses(&w, &mut db, &callers);
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA {} CASCADE;", w.rows, w.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn an_integer_id_spec_admits_and_refuses_through_every_generator_taking_an_id() {
    admits_and_refuses_through_every_generator_taking_an_id("integer");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_uuid_id_spec_admits_and_refuses_through_every_generator_taking_an_id() {
    admits_and_refuses_through_every_generator_taking_an_id("uuid");
}

fn no_temporary_table_shadows_a_table_a_generated_function_reads(ty: &'static str) {
    let w = World::new(ty, "shadowed");
    let mut db = connect();
    w.build(&mut db);
    let callers = Callers::new(&w);
    let mut forger = connect();
    w.shadow(&mut forger);
    each_caller_sees_its_rows(&w, &mut forger, &callers);
    each_function_admits_and_refuses(&w, &mut forger, &callers);
    let rows = &w.rows;
    forger
        .batch_execute(&w.fill(&format!("DELETE FROM {rows}.te WHERE mem = <MEMBER>; INSERT INTO {rows}.folders VALUES (<NEW_FOLDER>, <MEMBER>);")))
        .expect("a write through the group's and the closure's triggers");
    drop(forger);
    let (a, i) = (&w.auth, |n| w.lit(n));
    let left = format!("{a}.tc_member({}, {})", i(TEAM), i(MEMBER));
    assert!(!w.answer(&mut db, &callers.member, true, &left), "{ty}: the group's rebuild cleared the real closure, not the forger's");
    let flat = format!("{a}.boards_crew_flat_member({}, {})", i(BOARD), i(MEMBER));
    assert!(!w.answer(&mut db, &callers.member, true, &flat), "{ty}: the flat followed the real closure, not the forger's");
    let added = format!("{a}.folder_paths_reachable({}, {})", i(MEMBER), i(NEW_FOLDER));
    assert!(w.answer(&mut db, &callers.member, true, &added), "{ty}: the closure's trigger wrote the real closure, not the forger's");
    db.batch_execute(&format!("DROP SCHEMA {} CASCADE; DROP SCHEMA {} CASCADE;", w.rows, w.auth)).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn an_integer_id_spec_reads_no_table_a_temporary_one_shadows() {
    no_temporary_table_shadows_a_table_a_generated_function_reads("integer");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_uuid_id_spec_reads_no_table_a_temporary_one_shadows() {
    no_temporary_table_shadows_a_table_a_generated_function_reads("uuid");
}
