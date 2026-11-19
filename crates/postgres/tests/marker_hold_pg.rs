use postgres::{Client, NoTls, Transaction};

const ROWS: &str = "demesne_hold_rows";
const AUTH: &str = "demesne_hold_auth";
const CALLER: &str = "demesne_hold_caller";

const SPEC: &str = "topology {
  level platform virtual
  level estate parent platform
  level space parent estate
}
grant visit at space via edge visits(guest_id, space_id)
subject operator { anchor platform; reach descendants; identifies op_id via membership operators(user_id, is_op); roles none }
subject member   { anchor space; reach self; identifies sub; roles none }
subject guest    { anchor space; reach via grant visit; identifies guest_id; roles none }
object estate {
  table estates
  level estate
  scoped estate
  marker locked_by from claim lock_id confines select, insert, update, delete
  permission view = @scoped @rls maps select
}
object space {
  table spaces
  level space
  scoped estate > space
  marker locked_by from claim lock_id confines select, insert, update, delete
  permission view = @scoped @rls maps select
}
object note {
  table notes
  scoped estate > space
  permission view = @public @rls maps select
  permission add = @self(author_id) @rls maps insert
  permission edit = @scoped @rls maps update
}
";

const ANN: &str = r#"{"sub":"ann","estate_id":"e1","space_id":"s1","lock_id":"L1"}"#;
const OPERATOR: &str = r#"{"op_id":"op1","lock_id":"L1"}"#;
const GUEST: &str = r#"{"guest_id":"g1","estate_id":"e1","lock_id":"L1"}"#;

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {ROWS};
         CREATE TABLE estates (id text PRIMARY KEY, locked_by text);
         CREATE TABLE spaces (id text PRIMARY KEY, estate_id text, locked_by text);
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, author_id text, body text);
         CREATE TABLE operators (user_id text PRIMARY KEY, is_op boolean NOT NULL);
         CREATE TABLE visits (guest_id text, space_id text, PRIMARY KEY (guest_id, space_id));
         RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), sql.triggers_sql(), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER}; SET search_path = {ROWS};
         INSERT INTO estates VALUES ('e1', NULL), ('e2', NULL), ('e3', 'L1');
         INSERT INTO spaces VALUES ('s1', 'e1', NULL), ('s2', 'e1', NULL), ('s3', 'e2', NULL), ('s4', 'e3', 'L1');
         INSERT INTO notes VALUES ('n1', 'e1', 's1', 'ann', 'first'), ('n2', 'e1', 's2', 'ann', 'first'), ('n3', 'e2', 's3', 'ann', 'first'), ('n4', 'e3', 's4', 'ann', 'first');
         INSERT INTO operators VALUES ('op1', true);
         INSERT INTO visits VALUES ('g1', 's2');"
    ))
    .expect("grants and rows");
}

fn become_caller(tx: &mut Transaction<'_>, claims: &str) {
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
}

fn attempt(db: &mut Client, claims: &str, write: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, claims);
    let admitted = match tx.execute(write, &[]) {
        Ok(n) => n == 1,
        Err(e) => {
            assert_eq!(e.code().map(postgres::error::SqlState::code), Some("42501"), "{write} as {claims}: {e}");
            false
        }
    };
    tx.rollback().expect("rollback");
    admitted
}

fn probe(db: &mut Client, claims: &str, table: &str, container: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, claims);
    let call = format!("SELECT {AUTH}.{table}_locked_by_marker_admits($1, 'L1')");
    let answer: bool = tx.query_one(&call, &[&container]).expect("the marker function answers").get(0);
    tx.rollback().expect("rollback");
    answer
}

fn insert(estate: &str, space: &str) -> String {
    format!("INSERT INTO notes VALUES ('fresh', '{estate}', '{space}', 'ann', 'new')")
}

fn read(note: &str) -> String {
    format!("SELECT id FROM notes WHERE id = '{note}'")
}

fn update(note: &str) -> String {
    format!("UPDATE notes SET body = 'second' WHERE id = '{note}'")
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_marker_confines_what_it_names_to_callers_that_hold_the_container() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the marker hold checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);

    let cases = [
        ("an @self write in the caller's own space", ANN, insert("e1", "s1"), true),
        ("an @self write in another space of the caller's estate", ANN, insert("e1", "s2"), false),
        ("an @self write in another estate", ANN, insert("e2", "s3"), false),
        ("an @public read in the caller's own space", ANN, read("n1"), true),
        ("an @public read in another space of the caller's estate", ANN, read("n2"), false),
        ("an @public read in another estate", ANN, read("n3"), false),
        ("an operator's write in another estate", OPERATOR, update("n3"), true),
        ("a guest's write in the space it visits", GUEST, update("n2"), true),
        ("a guest's write in a space it does not visit", GUEST, update("n1"), false),
    ];
    for (what, claims, write, want) in &cases {
        assert_eq!(attempt(&mut db, claims, write), *want, "{what}");
    }

    let probes = [
        ("the caller's own estate", "estates", "e1", true),
        ("another estate, unmarked", "estates", "e2", false),
        ("another estate, marked with the caller's claim", "estates", "e3", false),
        ("an estate that does not exist", "estates", "e9", false),
        ("the caller's own space", "spaces", "s1", true),
        ("another space of the caller's estate", "spaces", "s2", false),
        ("a space of another estate, unmarked", "spaces", "s3", false),
        ("a space of another estate, marked with the caller's claim", "spaces", "s4", false),
    ];
    for (what, table, container, want) in probes {
        assert_eq!(probe(&mut db, ANN, table, container), want, "probe of {what}");
    }

    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
