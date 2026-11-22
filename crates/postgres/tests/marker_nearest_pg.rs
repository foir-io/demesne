use postgres::{Client, NoTls, Transaction};
use std::fmt::Write as _;

const ROWS: &str = "demesne_nearest_rows";
const AUTH: &str = "demesne_nearest_auth";
const CALLER: &str = "demesne_nearest_caller";

const SPEC: &str = "topology {
  level estate
  level space parent estate
}
subject member { anchor space; reach self; identifies sub; roles none }
closure paths(anc, des)
  base spaces(id, parent_id)
  scope estate_id
  depth hops
object space {
  table spaces
  level space
  scoped estate
  marker made_by from claim job_id confines insert, update, delete through nearest closure paths
  marker kept_by from claim kind_id confines insert, update, delete through nearest closure paths
  permission view = @scoped @rls maps select
}
object note {
  table notes
  scoped estate > space
  permission view = @scoped @rls maps select
  permission add = @scoped @rls maps insert
  permission edit = @scoped @rls maps update
  permission remove = @scoped @rls maps delete
}
object ledger {
  table ledgers
  scoped estate
  beneath space
  permission view = @scoped @rls maps select
  permission add = @scoped @rls maps insert
  permission edit = @scoped @rls maps update
  permission remove = @scoped @rls maps delete
}
";

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
         CREATE TABLE spaces (id text PRIMARY KEY, estate_id text NOT NULL, parent_id text REFERENCES spaces(id), made_by text, kept_by text);
         CREATE TABLE paths (anc text NOT NULL, des text NOT NULL, estate_id text, hops integer NOT NULL, PRIMARY KEY (anc, des));
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, body text);
         CREATE TABLE ledgers (id text PRIMARY KEY, estate_id text, space_id text, body text);
         RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), sql.triggers_sql(), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER}; SET search_path = {ROWS};
         INSERT INTO spaces VALUES ('s_place', 'e1', NULL, NULL, NULL), ('s_sib', 'e1', NULL, NULL, NULL), ('s_far', 'e2', NULL, NULL, NULL);
         INSERT INTO spaces VALUES ('s_a', 'e1', 's_place', 'job_a', 'kind_a'), ('s_k', 'e1', 's_place', NULL, 'kind_k');
         INSERT INTO spaces VALUES ('s_a_low', 'e1', 's_a', NULL, NULL), ('s_b', 'e1', 's_a', 'job_b', 'kind_b');
         INSERT INTO notes SELECT 'n_' || id, estate_id, id, 'first' FROM spaces;
         INSERT INTO ledgers SELECT 'l_' || id, estate_id, id, 'first' FROM spaces;
         INSERT INTO notes VALUES ('n_estate', 'e1', NULL, 'first');
         INSERT INTO ledgers VALUES ('l_estate', 'e1', NULL, 'first');"
    ))
    .expect("grants and rows");
}

fn claims(estate: &str, space: &str, job: Option<(&str, &str)>) -> String {
    let mut c = format!(r#"{{"sub":"ann","estate_id":"{estate}""#);
    if !space.is_empty() {
        write!(c, r#","space_id":"{space}""#).expect("fmt::Write for String never fails");
    }
    if let Some((job, kind)) = job {
        write!(c, r#","job_id":"{job}","kind_id":"{kind}""#).expect("fmt::Write for String never fails");
    }
    c.push('}');
    c
}

fn become_caller(tx: &mut Transaction<'_>, claims: &str) {
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}; SET LOCAL search_path = {ROWS}")).expect("the caller role");
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

fn writes(db: &mut Client, claims: &str, table: &str, space: &str) -> String {
    let (id, col) =
        if space.is_empty() { (format!("{}_estate", &table[..1]), "NULL".to_owned()) } else { (format!("{}_{space}", &table[..1]), format!("'{space}'")) };
    let estate = if space == "s_far" { "e2" } else { "e1" };
    let done: Vec<&str> = [
        ("insert", format!("INSERT INTO {table} VALUES ('fresh', '{estate}', {col}, 'new')")),
        ("update", format!("UPDATE {table} SET body = 'second' WHERE id = '{id}'")),
        ("delete", format!("DELETE FROM {table} WHERE id = '{id}'")),
    ]
    .into_iter()
    .filter_map(|(what, write)| attempt(db, claims, &write).then_some(what))
    .collect();
    if done.is_empty() { "-".to_owned() } else { done.join(" ") }
}

const A: Option<(&str, &str)> = Some(("job_a", "kind_a"));
const B: Option<(&str, &str)> = Some(("job_b", "kind_b"));

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_nearest_marked_container_decides_for_the_objects_scoped_at_its_level_and_those_beneath_it() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the marker checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);

    let callers = [
        ("no job, at the estate", "e1", "", None),
        ("no job, in an unmarked space", "e1", "s_place", None),
        ("no job, in job A's space", "e1", "s_a", None),
        ("no job, in an unmarked space beneath job A's", "e1", "s_a_low", None),
        ("no job, in kind K's space", "e1", "s_k", None),
        ("job A, in an unmarked space", "e1", "s_place", A),
        ("job A, in its own space", "e1", "s_a", A),
        ("job A, in an unmarked space beneath its own", "e1", "s_a_low", A),
        ("job A, in job B's space inside its own", "e1", "s_b", A),
        ("another job of kind A, in job A's space", "e1", "s_a", Some(("job_a2", "kind_a"))),
        ("job B, in its own space inside job A's", "e1", "s_b", B),
        ("job B, in job A's space", "e1", "s_a", B),
        ("a job of kind K, in kind K's space", "e1", "s_k", Some(("job_k", "kind_k"))),
        ("a job of another kind, in kind K's space", "e1", "s_k", Some(("job_z", "kind_z"))),
        ("job A, in another estate", "e2", "s_far", A),
    ];
    let mut lines = Vec::new();
    for (what, estate, space, job) in callers {
        let c = claims(estate, space, job);
        let (notes, ledgers) = (writes(&mut db, &c, "notes", space), writes(&mut db, &c, "ledgers", space));
        lines.push(format!("{what}: notes {notes}; ledgers {ledgers}"));
    }
    let lines = lines.join("\n");
    assert_eq!(
        lines,
        "no job, at the estate: notes -; ledgers insert update delete
no job, in an unmarked space: notes insert update delete; ledgers insert update delete
no job, in job A's space: notes -; ledgers -
no job, in an unmarked space beneath job A's: notes -; ledgers -
no job, in kind K's space: notes -; ledgers -
job A, in an unmarked space: notes insert update delete; ledgers insert update delete
job A, in its own space: notes insert update delete; ledgers insert update delete
job A, in an unmarked space beneath its own: notes insert update delete; ledgers insert update delete
job A, in job B's space inside its own: notes -; ledgers -
another job of kind A, in job A's space: notes -; ledgers -
job B, in its own space inside job A's: notes insert update delete; ledgers insert update delete
job B, in job A's space: notes -; ledgers -
a job of kind K, in kind K's space: notes insert update delete; ledgers insert update delete
a job of another kind, in kind K's space: notes -; ledgers -
job A, in another estate: notes insert update delete; ledgers insert update delete",
        "\n{lines}\n"
    );

    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
