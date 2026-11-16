use postgres::{Client, NoTls};

const ROWS: &str = "demesne_pc_rows";
const AUTH: &str = "demesne_pc_auth";
const CALLER: &str = "demesne_pc_caller";

const SPEC: &str = r#"topology { level control virtual level estate parent control level space parent estate }

grant support at estate via edge approvals(holder_id, estate_id)

subject helper { anchor control; reach via grant support; identifies sub; roles none }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }

object ledger {
  table ledgers
  scoped estate
  permission view = @scoped @rls maps select
  permission open_only = @scoped and @row(state, "open") @rls predicate
  check open_only for select as ledger_open(id text as id)
  check open_only as ledger_open_any(id text)
}

object entry {
  table entries
  scoped estate > space
  relation in_open_ledger: member via object ledger->open_only on ledger_id for select
  permission view = @scoped and in_open_ledger @rls maps select
}
"#;

const TABLES: &str = "CREATE TABLE approvals (holder_id text, estate_id text);
    CREATE TABLE ledgers (id text PRIMARY KEY, estate_id text, state text);
    CREATE TABLE entries (id text PRIMARY KEY, estate_id text, space_id text, ledger_id text);
    INSERT INTO approvals VALUES ('hal', 'e1'), ('hob', 'e1'), ('hob', 'e2');
    INSERT INTO ledgers VALUES ('e1-open', 'e1', 'open'), ('e1-shut', 'e1', 'shut'), ('e2-open', 'e2', 'open'), ('e2-shut', 'e2', 'shut');";

const LEDGERS: [(&str, &str, &str); 4] = [("e1-open", "e1", "open"), ("e1-shut", "e1", "shut"), ("e2-open", "e2", "open"), ("e2-shut", "e2", "shut")];

#[derive(Debug, Clone, Copy)]
struct Caller {
    sub: &'static str,
    estate: Option<&'static str>,
    space: Option<&'static str>,
}

const CALLERS: [Caller; 7] = [
    Caller { sub: "ann", estate: Some("e1"), space: Some("s1") },
    Caller { sub: "ann", estate: Some("e2"), space: Some("s3") },
    Caller { sub: "hal", estate: None, space: None },
    Caller { sub: "hal", estate: Some("e2"), space: Some("s3") },
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

    fn reaches(self, estate: &str) -> bool {
        matches!((self.sub, estate), ("hal", "e1") | ("hob", "e1" | "e2")) || self.estate == Some(estate)
    }

    fn passes(self, ledger: &str) -> bool {
        LEDGERS.iter().any(|(id, estate, state)| *id == ledger && self.reaches(estate) && *state == "open")
    }
}

fn install(db: &mut Client) {
    let spec = format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}");
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "RESET search_path; DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         {TABLES}"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT EXECUTE ON FUNCTION {AUTH}.ledger_can_open_only_for_select(text) TO {CALLER};"
    ))
    .expect("the borrow, granted to compare against");
}

fn answer(db: &mut Client, who: Caller, function: &str, id: Option<&str>) -> Option<bool> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&who.claims()]).expect("the claims");
    let statement = format!("SELECT {AUTH}.{function}($1)");
    let got = tx.query_one(&statement, &[&id]).unwrap_or_else(|e| panic!("{statement} as {who:?}: {e}")).get(0);
    tx.rollback().expect("rollback");
    got
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_point_check_answers_as_the_borrow_does_for_the_one_row_its_key_names() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the point check grid against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let (mut passed, mut refused) = (0, 0);
    for who in CALLERS {
        for id in LEDGERS.iter().map(|(id, _, _)| *id).chain(["e3-open"]) {
            let want = who.passes(id);
            let borrow = answer(&mut db, who, "ledger_can_open_only_for_select", Some(id));
            assert_eq!(borrow, Some(want), "the borrow, {id} as {who:?}");
            for check in ["ledger_open", "ledger_open_any"] {
                assert_eq!(answer(&mut db, who, check, Some(id)), Some(want), "{check}({id}) as {who:?}");
            }
            if want { passed += 1 } else { refused += 1 }
        }
        assert_eq!(answer(&mut db, who, "ledger_open", None), None, "no key, no answer, as {who:?}");
    }
    eprintln!("point check grid: {} cells, {passed} passed, {refused} refused", passed + refused);
    assert!(passed >= 6 && refused >= 20, "the grid both passes and refuses: {passed} and {refused}");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
