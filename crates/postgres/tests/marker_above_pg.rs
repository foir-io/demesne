use postgres::{Client, NoTls, Transaction};

const ROWS: &str = "demesne_above_rows";
const AUTH: &str = "demesne_above_auth";
const CALLER: &str = "demesne_above_caller";

const SPEC: &str = "topology {
  level platform virtual
  level estate parent platform
  level space parent estate
}
grant visit at space via edge visits(guest_id, space_id)
subject operator { anchor platform; reach descendants; identifies op_id via membership operators(user_id, is_op); roles none }
subject member   { anchor space; reach self; identifies sub; roles none }
subject guest    { anchor space; reach via grant visit; identifies guest_id; roles none }
object space {
  table spaces
  level space
  scoped estate
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
const ANN_AT_THE_ESTATE: &str = r#"{"sub":"ann","estate_id":"e1","lock_id":"L1"}"#;
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
         INSERT INTO spaces VALUES ('s1', 'e1', NULL), ('s2', 'e1', 'L1'), ('s3', 'e1', 'L2'), ('s4', 'e2', NULL);
         INSERT INTO notes VALUES ('n1', 'e1', 's1', 'ann', 'first'), ('n2', 'e1', 's2', 'ann', 'first'), ('n3', 'e1', 's3', 'ann', 'first'), ('n4', 'e2', 's4', 'ann', 'first');
         INSERT INTO operators VALUES ('op1', true);
         INSERT INTO visits VALUES ('g1', 's2'), ('g1', 's3');"
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

fn probe(db: &mut Client, claims: &str, container: &str) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, claims);
    let call = format!("SELECT {AUTH}.spaces_locked_by_marker_admits($1, 'L1')");
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
fn a_container_scoped_only_above_its_level_is_held_by_whoever_the_levels_above_contain_or_reach() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the marker checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);

    let cases = [
        ("an @self write in the caller's own space", ANN, insert("e1", "s1"), true),
        ("an @self write in another space of the caller's estate, marked with its claim", ANN, insert("e1", "s2"), true),
        ("an @self write in another space of the caller's estate, marked with another claim", ANN, insert("e1", "s3"), false),
        ("an @self write in another estate", ANN, insert("e2", "s4"), false),
        ("an @self write from the estate, in an unmarked space of it", ANN_AT_THE_ESTATE, insert("e1", "s1"), true),
        ("an @public read in another space of the caller's estate, marked with its claim", ANN, read("n2"), true),
        ("an @public read in a space marked with another claim", ANN, read("n3"), false),
        ("an @public read in another estate", ANN, read("n4"), false),
        ("an operator's write in another estate", OPERATOR, update("n4"), true),
        ("a guest's write in a space it visits, marked with its claim", GUEST, update("n2"), true),
        ("a guest's write in a space it visits, marked with another claim", GUEST, update("n3"), false),
        ("a guest's write in a space it does not visit", GUEST, update("n1"), false),
    ];
    for (what, claims, write, want) in &cases {
        assert_eq!(attempt(&mut db, claims, write), *want, "{what}");
    }

    let probes = [
        ("the caller's own space", "s1", true),
        ("another space of the caller's estate, marked with its claim", "s2", true),
        ("a space of the caller's estate marked with another claim", "s3", false),
        ("a space of another estate", "s4", false),
        ("a space that does not exist", "s9", false),
    ];
    for (what, container, want) in probes {
        assert_eq!(probe(&mut db, ANN, container), want, "probe of {what}");
    }

    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
