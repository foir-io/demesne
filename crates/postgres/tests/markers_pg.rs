use postgres::{Client, NoTls, Transaction};

const ROWS: &str = "demesne_marker_rows";
const AUTH: &str = "demesne_marker_auth";
const CALLER: &str = "demesne_marker_caller";

const SPEC: &str = "topology { level estate level space parent estate }
subject member { anchor space; reach self; identifies sub; roles none }
closure paths(anc, des) base spaces(id, parent_id)
object space {
  table spaces
  level space
  scoped estate > space
  marker made_by from claim job_id confines insert, update, delete through closure paths
  marker held_for from claim hold_id confines update
  marker sealed_by from claim seal_id confines select, update, delete
  permission view = @scoped @rls maps select
  permission edit = @scoped @rls maps update
}
object note {
  table notes
  scoped estate > space wildcard confers select
  permission view = @scoped @rls maps select
  permission add = @scoped @rls maps insert
  permission edit = @scoped @rls maps update
  permission remove = @scoped @rls maps delete
}
";

type Space = (&'static str, Option<&'static str>, Option<i64>, Option<&'static str>, Option<&'static str>);

const SPACES: [Space; 7] = [
    ("plain", None, None, None, None),
    ("job", None, Some(101), None, None),
    ("under_job", Some("job"), None, None, None),
    ("held", None, None, Some("h1"), None),
    ("under_held", Some("held"), None, None, None),
    ("both", Some("under_job"), Some(102), Some("h1"), None),
    ("sealed", None, None, None, Some("s1")),
];

const NOTES: [(&str, Option<&str>); 9] = [
    ("n_plain", Some("plain")),
    ("n_job", Some("job")),
    ("n_under_job", Some("under_job")),
    ("n_held", Some("held")),
    ("n_under_held", Some("under_held")),
    ("n_both", Some("both")),
    ("n_sealed", Some("sealed")),
    ("n_wild", None),
    ("n_ghost", Some("nowhere")),
];

#[derive(Clone, Copy, Debug)]
struct Caller {
    job: Option<&'static str>,
    hold: Option<&'static str>,
    seal: Option<&'static str>,
}

fn callers() -> Vec<Caller> {
    let mut out = Vec::new();
    for job in [None, Some("101"), Some("102")] {
        for hold in [None, Some("h1"), Some("h2")] {
            for seal in [None, Some("s1")] {
                out.push(Caller { job, hold, seal });
            }
        }
    }
    out
}

fn space(id: &str) -> Option<Space> {
    SPACES.iter().copied().find(|s| s.0 == id)
}

fn job_admits(id: &str, job: Option<&str>) -> bool {
    let Some((_, parent, made_by, _, _)) = space(id) else { return false };
    let own = made_by.is_none_or(|m| job == Some(m.to_string().as_str()));
    own && parent.is_none_or(|p| job_admits(p, job))
}

fn oracle(op: &str, at: Option<&str>, c: Caller) -> bool {
    let Some(at) = at else { return true };
    let Some((_, _, _, held_for, sealed_by)) = space(at) else { return false };
    let read = sealed_by.is_none_or(|s| c.seal == Some(s));
    let job = job_admits(at, c.job);
    let hold = held_for.is_none_or(|h| c.hold == Some(h));
    match op {
        "select" => read,
        "insert" => job,
        "update" => read && job && hold,
        _ => read && job,
    }
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE spaces (id text PRIMARY KEY, estate_id text, parent_id text, made_by bigint, held_for text, sealed_by text);
         CREATE TABLE paths (anc text, des text, PRIMARY KEY (anc, des));
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, body text);
         RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), sql.triggers_sql(), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER}; SET search_path = {ROWS};"
    ))
    .expect("grants");
    for (id, parent, made_by, held_for, sealed_by) in SPACES {
        db.execute("INSERT INTO spaces VALUES ($1, 'e1', $2, $3, $4, $5)", &[&id, &parent, &made_by, &held_for, &sealed_by]).expect("a space");
    }
    for (id, at) in NOTES {
        db.execute("INSERT INTO notes VALUES ($1, 'e1', $2, 'first')", &[&id, &at]).expect("a note");
    }
}

fn become_caller(tx: &mut Transaction<'_>, at: Option<&str>, c: Caller) {
    let field = |k: &str, v: Option<&str>| v.map(|v| format!(",\"{k}\":\"{v}\"")).unwrap_or_default();
    let claims = format!(
        "{{\"sub\":\"ann\",\"estate_id\":\"e1\"{}{}{}{}}}",
        field("space_id", at),
        field("job_id", c.job),
        field("hold_id", c.hold),
        field("seal_id", c.seal)
    );
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
}

fn attempt(db: &mut Client, op: &str, note: &str, at: Option<&str>, c: Caller) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, at, c);
    let done = match op {
        "select" => tx.query("SELECT id FROM notes WHERE id = $1", &[&note]).map(|r| r.len() == 1),
        "insert" => tx.execute("INSERT INTO notes VALUES ('fresh', 'e1', $1, 'new')", &[&at]).map(|n| n == 1),
        "update" => tx.execute("UPDATE notes SET body = 'second' WHERE id = $1", &[&note]).map(|n| n == 1),
        _ => tx.execute("DELETE FROM notes WHERE id = $1", &[&note]).map(|n| n == 1),
    };
    let admitted = match done {
        Ok(admitted) => admitted,
        Err(e) => {
            assert_eq!(e.code().map(postgres::error::SqlState::code), Some("42501"), "{op} {note} {c:?}: {e}");
            false
        }
    };
    tx.rollback().expect("rollback");
    admitted
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn rows_beneath_a_marked_container_are_written_only_by_the_session_the_marker_names() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the marker checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut cells = 0;
    for op in ["select", "insert", "update", "delete"] {
        let mut outcomes = [0, 0];
        for (note, at) in NOTES {
            for c in callers() {
                let want = oracle(op, at, c);
                assert_eq!(attempt(&mut db, op, note, at, c), want, "{op} on {note} by {c:?}");
                outcomes[usize::from(want)] += 1;
                cells += 1;
            }
        }
        assert!(outcomes[0] > 0 && outcomes[1] > 0, "{op} is both admitted and refused: {outcomes:?}");
    }
    assert_eq!(cells, 4 * 9 * 18);

    let nobody = Caller { job: None, hold: None, seal: None };
    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, Some("job"), nobody);
    assert_eq!(
        tx.execute("UPDATE spaces SET held_for = held_for WHERE id = 'job'", &[]).expect("the container"),
        1,
        "the container's own row keeps its own rule"
    );
    tx.rollback().expect("rollback");

    let mut tx = db.transaction().expect("a transaction");
    become_caller(&mut tx, Some("under_held"), nobody);
    assert_eq!(tx.execute("UPDATE notes SET body = 'second' WHERE id = 'n_under_held'", &[]).expect("before the mark"), 1);
    tx.batch_execute(&format!("RESET ROLE; UPDATE {ROWS}.spaces SET made_by = 103 WHERE id = 'held'; SET LOCAL ROLE {CALLER}"))
        .expect("a container above is marked");
    assert_eq!(
        tx.execute("UPDATE notes SET body = 'third' WHERE id = 'n_under_held'", &[]).expect("after the mark"),
        0,
        "a mark set above ends the write in the same transaction"
    );
    tx.rollback().expect("rollback");

    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
