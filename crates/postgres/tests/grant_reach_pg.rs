use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_gr_rows";
const AUTH: &str = "demesne_gr_auth";
const CALLER: &str = "demesne_gr_caller";

const SPEC: &str = r#"topology { level control virtual level estate parent control level space parent estate }

grant support at estate via edge approvals(holder_id, estate_id)

subject helper { anchor control; reach via grant support; identifies sub; roles none }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }

object ledger {
  table ledgers
  scoped estate
  permission view = @scoped and @row(state, "open") @rls maps select
  permission edit = @scoped and @row(state, "open") @rls maps update
  permission open_only = @scoped and @row(state, "open") @rls predicate
}

object passbook {
  table passbooks
  scoped estate
  permission view = (@scoped and @row(state, "open")) + via grant support @rls maps select
}

object memo {
  table memos
  scoped estate
  permission view = @scoped @rls maps select
}

object keepsake {
  table keepsakes
  scoped estate
  relation owner: member via holder_id
  permission view = @self(holder_id) @rls maps select
}

object space {
  table spaces
  level space
  scoped estate > space
  permission view = @scoped and @row(state, "open") @rls maps select
}

object note {
  table notes
  scoped estate > space
  permission view = @scoped and @row(state, "open") @rls maps select
}

object entry {
  table entries
  scoped estate > space
  relation in_open_ledger: member via object ledger->open_only on ledger_id
  permission view = @scoped and in_open_ledger @rls maps select
}
"#;

const DECLARED: &str = r#"topology { level control virtual level estate parent control level space parent estate }

grant audit at estate via edge audits(holder_id, estate_id) scope space on space_id missing deny

subject auditor { anchor control; reach via grant audit; identifies sub; roles none }

object book {
  table books
  scoped estate
  reach audit unscoped for select
  permission view = @scoped and @row(state, "open") @rls maps select
  permission edit = @scoped and @row(state, "open") @rls maps update blind
}
"#;

const TABLES: &str = "CREATE TABLE approvals (holder_id text, estate_id text);
    CREATE TABLE ledgers (id text PRIMARY KEY, estate_id text, state text);
    CREATE TABLE passbooks (id text PRIMARY KEY, estate_id text, state text);
    CREATE TABLE memos (id text PRIMARY KEY, estate_id text, state text);
    CREATE TABLE keepsakes (id text PRIMARY KEY, estate_id text, holder_id text);
    CREATE TABLE spaces (id text PRIMARY KEY, estate_id text, state text);
    CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text, state text);
    CREATE TABLE entries (id text PRIMARY KEY, estate_id text, space_id text, ledger_id text);
    INSERT INTO approvals VALUES ('hal', 'e1'), ('hob', 'e1'), ('hob', 'e2');";

const DECLARED_TABLES: &str = "CREATE TABLE audits (holder_id text, estate_id text, space_id text);
    CREATE TABLE books (id text PRIMARY KEY, estate_id text, state text);
    INSERT INTO audits VALUES ('hal', 'e1', NULL), ('hob', 'e1', 's1');";

const PLAIN: [(&str, &str, &str); 4] = [("e1-open", "e1", "open"), ("e1-shut", "e1", "shut"), ("e2-open", "e2", "open"), ("e2-shut", "e2", "shut")];
const KEEPSAKES: [(&str, &str, &str); 3] = [("k1", "e1", "hal"), ("k2", "e1", "ann"), ("k3", "e2", "hal")];
const SPACES: [(&str, &str, &str); 4] = [("s1", "e1", "open"), ("s2", "e1", "shut"), ("s3", "e2", "open"), ("s4", "e2", "shut")];
const NOTES: [(&str, &str, &str, &str); 5] =
    [("n1", "e1", "s1", "open"), ("n2", "e1", "s1", "shut"), ("n3", "e1", "s2", "open"), ("n4", "e2", "s3", "open"), ("n5", "e2", "s3", "shut")];
const ENTRIES: [(&str, &str, &str, &str); 6] = [
    ("x1", "e1", "s1", "e1-open"),
    ("x2", "e1", "s1", "e1-shut"),
    ("x3", "e1", "s1", "e2-open"),
    ("x4", "e2", "s3", "e2-open"),
    ("x5", "e2", "s3", "e1-open"),
    ("x6", "e1", "s2", "e1-open"),
];

#[derive(Debug, Clone, Copy)]
struct Caller {
    sub: &'static str,
    estate: Option<&'static str>,
    space: Option<&'static str>,
}

const CALLERS: [Caller; 8] = [
    Caller { sub: "ann", estate: Some("e1"), space: Some("s1") },
    Caller { sub: "ann", estate: Some("e2"), space: Some("s3") },
    Caller { sub: "hal", estate: None, space: None },
    Caller { sub: "hal", estate: Some("e2"), space: Some("s3") },
    Caller { sub: "hal", estate: Some("e1"), space: Some("s1") },
    Caller { sub: "hob", estate: None, space: None },
    Caller { sub: "ivy", estate: None, space: None },
    Caller { sub: "ivy", estate: Some("e1"), space: Some("s2") },
];

impl Caller {
    fn claims(self) -> String {
        let mut keys = vec![format!("\"sub\":\"{}\"", self.sub)];
        keys.extend(self.estate.map(|e| format!("\"estate_id\":\"{e}\"")));
        keys.extend(self.space.map(|s| format!("\"space_id\":\"{s}\"")));
        format!("{{{}}}", keys.join(","))
    }

    fn holds(self, estate: &str) -> bool {
        matches!((self.sub, estate), ("hal", "e1") | ("hob", "e1" | "e2"))
    }

    fn stands_in(self, estate: &str) -> bool {
        self.estate == Some(estate)
    }

    fn reaches(self, estate: &str) -> bool {
        self.holds(estate) || self.stands_in(estate)
    }

    fn reads_open_ledger(self, ledger: &str) -> bool {
        PLAIN.iter().any(|(id, estate, state)| *id == ledger && self.reaches(estate) && *state == "open")
    }
}

fn install(db: &mut Client, spec: &str, tables: &str, written: &[&str]) {
    let spec = format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{spec}");
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "RESET search_path; DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         {tables}"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON ALL TABLES IN SCHEMA {ROWS} TO {CALLER};")).expect("grants");
    for table in written {
        db.batch_execute(&format!("GRANT UPDATE ON {ROWS}.{table} TO {CALLER}")).expect("the write grant");
    }
}

fn fill(db: &mut Client) {
    for table in ["ledgers", "passbooks", "memos"] {
        for (id, estate, state) in PLAIN {
            db.execute(&format!("INSERT INTO {table} VALUES ($1, $2, $3)"), &[&id, &estate, &state]).expect("a row");
        }
    }
    for (id, estate, holder) in KEEPSAKES {
        db.execute("INSERT INTO keepsakes VALUES ($1, $2, $3)", &[&id, &estate, &holder]).expect("a keepsake");
    }
    for (id, estate, state) in SPACES {
        db.execute("INSERT INTO spaces VALUES ($1, $2, $3)", &[&id, &estate, &state]).expect("a space");
    }
    for (id, estate, space, state) in NOTES {
        db.execute("INSERT INTO notes VALUES ($1, $2, $3, $4)", &[&id, &estate, &space, &state]).expect("a note");
    }
    for (id, estate, space, ledger) in ENTRIES {
        db.execute("INSERT INTO entries VALUES ($1, $2, $3, $4)", &[&id, &estate, &space, &ledger]).expect("an entry");
    }
}

fn ids(db: &mut Client, who: Caller, statement: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&who.claims()]).expect("the claims");
    let ids = tx.query(statement, &[]).unwrap_or_else(|e| panic!("{statement}: {e}")).iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

fn wanted<'a>(rows: impl Iterator<Item = (&'a str, bool)>) -> BTreeSet<String> {
    rows.filter(|(_, admitted)| *admitted).map(|(id, _)| id.to_string()).collect()
}

#[derive(Default)]
struct Cells {
    admitted: usize,
    refused: usize,
}

impl Cells {
    fn judge(&mut self, what: &str, who: Caller, rows: usize, got: &BTreeSet<String>, want: &BTreeSet<String>) {
        assert_eq!(got, want, "{what} as {who:?}");
        self.admitted += got.len();
        self.refused += rows - got.len();
    }
}

fn judge_bound_and_named(db: &mut Client, cells: &mut Cells) {
    for who in CALLERS {
        let bound = wanted(PLAIN.iter().map(|(id, estate, state)| (*id, who.reaches(estate) && *state == "open")));
        cells.judge("a one-level object, read", who, PLAIN.len(), &ids(db, who, "SELECT id FROM ledgers"), &bound);
        cells.judge("a one-level object, written", who, PLAIN.len(), &ids(db, who, "UPDATE ledgers SET state = state RETURNING id"), &bound);
        let named = wanted(PLAIN.iter().map(|(id, estate, state)| (*id, who.holds(estate) || (who.stands_in(estate) && *state == "open"))));
        cells.judge("a grant named in the permission", who, PLAIN.len(), &ids(db, who, "SELECT id FROM passbooks"), &named);
        let alone = wanted(PLAIN.iter().map(|(id, estate, _)| (*id, who.reaches(estate))));
        cells.judge("the scope alone", who, PLAIN.len(), &ids(db, who, "SELECT id FROM memos"), &alone);
        let own = wanted(KEEPSAKES.iter().map(|(id, _, holder)| (*id, *holder == who.sub)));
        cells.judge("no term under the scope", who, KEEPSAKES.len(), &ids(db, who, "SELECT id FROM keepsakes"), &own);
        let level = wanted(SPACES.iter().map(|(id, estate, state)| (*id, who.reaches(estate) && *state == "open")));
        cells.judge("a level's own table", who, SPACES.len(), &ids(db, who, "SELECT id FROM spaces"), &level);
        let lower = wanted(NOTES.iter().map(|(id, estate, space, state)| (*id, who.reaches(estate) && who.space == Some(*space) && *state == "open")));
        cells.judge("an object with a lower level", who, NOTES.len(), &ids(db, who, "SELECT id FROM notes"), &lower);
        let borrowed =
            wanted(ENTRIES.iter().map(|(id, estate, space, ledger)| (*id, who.reaches(estate) && who.space == Some(*space) && who.reads_open_ledger(ledger))));
        cells.judge("a borrowed predicate", who, ENTRIES.len(), &ids(db, who, "SELECT id FROM entries"), &borrowed);
    }
}

fn audited(who: Caller, estate: &str, narrowed_counts: bool) -> bool {
    match (who.sub, estate) {
        ("hal", "e1") => true,
        ("hob", "e1") => narrowed_counts && who.space == Some("s1"),
        _ => false,
    }
}

fn judge_declared(db: &mut Client, cells: &mut Cells) {
    let callers = [
        CALLERS[0],
        CALLERS[2],
        CALLERS[3],
        CALLERS[5],
        Caller { sub: "hob", estate: Some("e2"), space: Some("s1") },
        Caller { sub: "hob", estate: Some("e1"), space: Some("s1") },
    ];
    for who in callers {
        let read = |estate: &str, state: &str| audited(who, estate, false) || (who.stands_in(estate) && state == "open");
        let reads = wanted(PLAIN.iter().map(|(id, estate, state)| (*id, read(estate, state))));
        cells.judge("a declared reach, read", who, PLAIN.len(), &ids(db, who, "SELECT id FROM books"), &reads);
        let writes = wanted(
            PLAIN.iter().map(|(id, estate, state)| (*id, read(estate, state) && (audited(who, estate, true) || who.stands_in(estate)) && *state == "open")),
        );
        cells.judge("a declared reach, written", who, PLAIN.len(), &ids(db, who, "UPDATE books SET state = state RETURNING id"), &writes);
    }
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_grant_gives_reach_and_the_permissions_terms_still_bind_its_callers() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the grant reach checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let mut cells = Cells::default();
    install(&mut db, SPEC, TABLES, &["ledgers"]);
    fill(&mut db);
    let hal = CALLERS[2];
    assert_eq!(
        ids(&mut db, hal, "SELECT id FROM ledgers"),
        wanted([("e1-open", true)].into_iter()),
        "a grant's holder reads the open row and not the shut one"
    );
    assert_eq!(
        ids(&mut db, hal, "SELECT id FROM passbooks"),
        wanted([("e1-open", true), ("e1-shut", true)].into_iter()),
        "where the permission names the grant, its holder reads both"
    );
    judge_bound_and_named(&mut db, &mut cells);
    install(&mut db, DECLARED, DECLARED_TABLES, &["books"]);
    for (id, estate, state) in PLAIN {
        db.execute("INSERT INTO books VALUES ($1, $2, $3)", &[&id, &estate, &state]).expect("a book");
    }
    assert_eq!(
        ids(&mut db, hal, "SELECT id FROM books"),
        wanted([("e1-open", true), ("e1-shut", true)].into_iter()),
        "a reach the object declares for select passes without the terms"
    );
    assert_eq!(
        ids(&mut db, hal, "UPDATE books SET state = state RETURNING id"),
        wanted([("e1-open", true)].into_iter()),
        "and the write it does not declare is bound by them"
    );
    judge_declared(&mut db, &mut cells);
    eprintln!("grant reach grid: {} cells, {} admitted, {} refused", cells.admitted + cells.refused, cells.admitted, cells.refused);
    assert!(cells.admitted > 40 && cells.refused > 40, "the grid both admits and refuses: {} and {}", cells.admitted, cells.refused);
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
