use postgres::error::SqlState;
use postgres::{Client, NoTls};
use std::collections::{BTreeMap, BTreeSet};

const ROWS: &str = "demesne_tree_rows";
const AUTH: &str = "demesne_tree_auth";
const CALLER: &str = "demesne_tree_caller";

const TABLES: &str = "
CREATE TABLE folders (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, parent_id text);
CREATE TABLE paths (ancestor_id text NOT NULL, descendant_id text NOT NULL, space_id text NOT NULL, depth integer NOT NULL, PRIMARY KEY (ancestor_id, descendant_id));
CREATE TABLE templates (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, folder_id text, body text);
CREATE TABLE atlases (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, folder_id text);
CREATE TABLE spaces (id text PRIMARY KEY, estate_id text NOT NULL, status text NOT NULL);
CREATE TABLE pages (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL);
CREATE TABLE sheets (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL);
CREATE TABLE notices (id text PRIMARY KEY, estate_id text NOT NULL, space_id text, body text);
CREATE TABLE drafts (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, visibility text);
CREATE TABLE ledgers (id text PRIMARY KEY, estate_id text NOT NULL, space_id text, amount integer);
";

const RECOMPUTED: &str = "
WITH RECURSIVE up AS (
  SELECT id AS ancestor_id, id AS descendant_id, space_id, 0 AS depth FROM folders
  UNION ALL
  SELECT f.parent_id, up.descendant_id, up.space_id, up.depth + 1 FROM up JOIN folders f ON f.id = up.ancestor_id WHERE f.parent_id IS NOT NULL
)
SELECT ancestor_id, descendant_id, space_id, depth FROM up";

type Pair = (String, String, String, i32);

fn spec() -> demesne_syntax::Spec {
    let path = format!("{}/../../examples/tree.demesne", env!("CARGO_MANIFEST_DIR"));
    let example = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{example}")).expect("the tree example parses");
    demesne_emit_sql::validate(&s).expect("the tree example validates");
    s
}

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the closure checks against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

fn install(db: &mut Client) {
    let s = spec();
    let sql = demesne_emit_sql::Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let rls = sql.emit_rls().expect("the policies compile");
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS}; {TABLES} RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), sql.triggers_sql(), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER};
         GRANT SELECT, INSERT, UPDATE, DELETE ON {ROWS}.folders, {ROWS}.templates, {ROWS}.atlases, {ROWS}.spaces, {ROWS}.pages, {ROWS}.sheets, {ROWS}.notices, {ROWS}.drafts, {ROWS}.ledgers TO {CALLER};
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER};
         SET search_path = {ROWS};"
    ))
    .expect("grants");
}

fn pairs(db: &mut Client, query: &str) -> BTreeSet<Pair> {
    db.query(query, &[]).unwrap_or_else(|e| panic!("{query}: {e}")).iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3))).collect()
}

fn closure_is_its_pointers(db: &mut Client, after: &str) -> usize {
    let held = pairs(db, "SELECT ancestor_id, descendant_id, space_id, depth FROM paths");
    let wanted = pairs(db, RECOMPUTED);
    assert_eq!(held, wanted, "after {after}: the closure is not what the parent pointers say");
    held.len()
}

const TREE: [(&str, &str, Option<&str>); 7] =
    [("a", "s1", None), ("b", "s1", Some("a")), ("c", "s1", Some("b")), ("d", "s1", Some("a")), ("e", "s1", None), ("x", "s2", None), ("y", "s2", Some("x"))];

fn plant_tree(db: &mut Client) {
    for (id, space, parent) in TREE {
        db.execute("INSERT INTO folders (id, estate_id, space_id, parent_id) VALUES ($1, 'e1', $2, $3)", &[&id, &space, &parent]).expect("a folder");
    }
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_closure_follows_its_base_and_reads_answer_in_both_directions() {
    let mut db = connect();
    install(&mut db);
    maintenance(&mut db);
    refusals(&mut db);
    locks(&mut db);
    install(&mut db);
    plant_tree(&mut db);
    path(&mut db);
    reads_and_writes(&mut db);
    two_way_reach(&mut db);
    exact_tier(&mut db);
    pinned_borrow(&mut db);
    require_terms(&mut db);
    a_caller_grows_the_tree_beneath_itself_alone(&mut db);
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}

fn maintenance(db: &mut Client) {
    assert_eq!(closure_is_its_pointers(db, "nothing"), 0);
    plant_tree(db);
    assert_eq!(closure_is_its_pointers(db, "seven inserts"), 12, "7 self pairs, a over b c d, b over c, x over y");
    let depth_of_c: i32 = db.query_one("SELECT depth FROM paths WHERE ancestor_id = 'a' AND descendant_id = 'c'", &[]).expect("a over c").get(0);
    assert_eq!(depth_of_c, 2);
    let mut sizes = Vec::new();
    for (what, stmt) in [
        ("a leaf moved beside its parent", "UPDATE folders SET parent_id = 'd' WHERE id = 'c'"),
        ("a subtree moved to another root", "UPDATE folders SET parent_id = 'e' WHERE id = 'd'"),
        ("a subtree made a root", "UPDATE folders SET parent_id = NULL WHERE id = 'd'"),
        ("a root moved beneath a leaf", "UPDATE folders SET parent_id = 'c' WHERE id = 'e'"),
        ("an update that keeps the parent", "UPDATE folders SET estate_id = 'e1' WHERE id = 'c'"),
        ("a subtree and a leaf inside it moved by one statement", "UPDATE folders SET parent_id = 'a' WHERE id IN ('d', 'e')"),
        ("a leaf deleted", "DELETE FROM folders WHERE id = 'e'"),
        ("a parent and its child inserted by one statement", "INSERT INTO folders VALUES ('f', 'e1', 's1', 'c'), ('g', 'e1', 's1', 'f')"),
        ("a chain deleted from the bottom", "DELETE FROM folders WHERE id IN ('g', 'f')"),
        ("the other space's tree deleted", "DELETE FROM folders WHERE space_id = 's2' AND id = 'y'"),
    ] {
        db.batch_execute(stmt).unwrap_or_else(|e| panic!("{what}: {e}"));
        sizes.push(closure_is_its_pointers(db, what));
    }
    assert_eq!(sizes, [12, 12, 10, 12, 12, 13, 11, 20, 11, 9], "each step leaves the pairs its tree has");
    db.batch_execute("DELETE FROM folders").expect("empty the tree");
    assert_eq!(closure_is_its_pointers(db, "every folder deleted"), 0);
}

fn refused(db: &mut Client, stmt: &str, constraint: &str) {
    let before = pairs(db, "SELECT ancestor_id, descendant_id, space_id, depth FROM paths");
    let err = db.batch_execute(stmt).expect_err(&format!("{stmt} is refused"));
    let detail = err.as_db_error().unwrap_or_else(|| panic!("{stmt}: {err}"));
    assert_eq!((detail.code(), detail.constraint(), detail.table()), (&SqlState::CHECK_VIOLATION, Some(constraint), Some("folders")), "{stmt}: {detail}");
    assert_eq!(pairs(db, "SELECT ancestor_id, descendant_id, space_id, depth FROM paths"), before, "{stmt}: a refused write leaves the closure alone");
    closure_is_its_pointers(db, stmt);
}

fn refusals(db: &mut Client) {
    plant_tree(db);
    for (stmt, constraint) in [
        ("INSERT INTO folders VALUES ('z', 'e1', 's1', 'z')", "paths_acyclic"),
        ("UPDATE folders SET parent_id = 'a' WHERE id = 'a'", "paths_acyclic"),
        ("UPDATE folders SET parent_id = 'b' WHERE id = 'a'", "paths_acyclic"),
        ("UPDATE folders SET parent_id = 'c' WHERE id = 'a'", "paths_acyclic"),
        ("INSERT INTO folders VALUES ('z', 'e1', 's1', 'nowhere')", "paths_parent_known"),
        ("INSERT INTO folders VALUES ('z', 'e1', 's1', 'x')", "paths_parent_known"),
        ("UPDATE folders SET parent_id = 'x' WHERE id = 'e'", "paths_parent_known"),
        ("INSERT INTO folders VALUES ('z2', 'e1', 's1', 'z1'), ('z1', 'e1', 's1', 'a')", "paths_parent_known"),
        ("UPDATE folders SET space_id = 's2' WHERE id = 'e'", "paths_scope_fixed"),
        ("UPDATE folders SET space_id = 's2', parent_id = 'x' WHERE id = 'e'", "paths_scope_fixed"),
    ] {
        refused(db, stmt, constraint);
    }
    db.batch_execute("UPDATE folders SET parent_id = 'e' WHERE id = 'c'").expect("a move that makes no cycle is not refused");
    closure_is_its_pointers(db, "a move beside a refused one");
}

fn lock_is_free(other: &mut Client, scope: &str) -> bool {
    let free: bool = other.query_one("SELECT pg_try_advisory_lock(hashtext('paths'), hashtext($1))", &[&scope]).expect("try the lock").get(0);
    if free {
        other.execute("SELECT pg_advisory_unlock(hashtext('paths'), hashtext($1))", &[&scope]).expect("release the lock");
    }
    free
}

fn locks(db: &mut Client) {
    let mut other = connect();
    for (what, stmt) in [
        ("an insert", "INSERT INTO folders VALUES ('k', 'e1', 's1', NULL)"),
        ("a move", "UPDATE folders SET parent_id = 'a' WHERE id = 'e'"),
        ("a delete", "DELETE FROM folders WHERE id = 'd'"),
    ] {
        let mut tx = db.transaction().expect("a transaction");
        assert!(lock_is_free(&mut other, "s1"), "{what}: the scope's lock is free before the write");
        tx.batch_execute(stmt).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(!lock_is_free(&mut other, "s1"), "{what}: the write holds its scope's lock until it commits");
        assert!(lock_is_free(&mut other, "s2"), "{what}: another scope's lock stays free");
        tx.rollback().expect("rollback");
        assert!(lock_is_free(&mut other, "s1"), "{what}: the lock goes with the transaction");
    }
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute("UPDATE folders SET estate_id = 'e1' WHERE id = 'a'").expect("an update that moves nothing");
    assert!(lock_is_free(&mut other, "s1"), "an update that keeps the parent takes no lock");
    tx.rollback().expect("rollback");
}

fn path(db: &mut Client) {
    let path_of = |db: &mut Client, node: &str| -> Vec<(String, i32)> {
        db.query(&format!("SELECT node, depth FROM {AUTH}.paths_path($1)"), &[&node]).expect("the path").iter().map(|r| (r.get(0), r.get(1))).collect()
    };
    assert_eq!(path_of(db, "c"), [("a".to_string(), 2), ("b".to_string(), 1), ("c".to_string(), 0)], "root first, each with its distance from the node");
    assert_eq!(path_of(db, "e"), [("e".to_string(), 0)]);
    assert_eq!(path_of(db, "nowhere"), []);
    let none: i64 = db.query_one(&format!("SELECT count(*) FROM {AUTH}.paths_path(NULL)"), &[]).expect("a NULL node").get(0);
    assert_eq!(none, 0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Select,
    Insert,
    Update,
    Delete,
}

const OPS: [Op; 4] = [Op::Select, Op::Insert, Op::Update, Op::Delete];

fn claims(pairs: &[(&str, Option<&str>)]) -> String {
    let fields: Vec<String> = pairs.iter().filter_map(|(k, v)| v.map(|v| format!("\"{k}\":\"{v}\""))).collect();
    format!("{{{}}}", fields.join(","))
}

fn attempt(db: &mut Client, claims: &str, table: &str, id: &str, op: Op, columns: &[(&str, Option<&str>)]) -> bool {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let done = match op {
        Op::Select => !tx.query(&format!("SELECT id FROM {table} WHERE id = $1"), &[&id]).expect("the read").is_empty(),
        Op::Update => tx.execute(&format!("UPDATE {table} SET id = id WHERE id = $1"), &[&id]).expect("the update") == 1,
        Op::Delete => tx.execute(&format!("DELETE FROM {table} WHERE id = $1"), &[&id]).expect("the delete") == 1,
        Op::Insert => {
            let names: Vec<&str> = columns.iter().map(|(c, _)| *c).collect();
            let values: Vec<String> = columns.iter().map(|(_, v)| v.map_or("NULL".to_string(), |v| format!("'{v}'"))).collect();
            let new_id = format!("new_{id}");
            match tx.execute(&format!("INSERT INTO {table} (id, {}) VALUES ($1, {})", names.join(", "), values.join(", ")), &[&new_id]) {
                Ok(n) => n == 1,
                Err(e) if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) => false,
                Err(e) => panic!("insert into {table}: {e}"),
            }
        }
    };
    tx.rollback().expect("rollback");
    done
}

fn at_or_beneath(parents: &BTreeMap<&str, Option<&str>>, node: &str, top: &str) -> bool {
    let mut at = Some(node);
    while let Some(n) = at {
        if n == top {
            return true;
        }
        at = parents.get(n).copied().flatten();
    }
    false
}

struct Row<'a> {
    table: &'a str,
    id: &'a str,
    columns: &'a [(&'a str, Option<&'a str>)],
}

#[derive(Default)]
struct Grid {
    seen: BTreeMap<Op, BTreeSet<bool>>,
    failures: Vec<String>,
}

impl Grid {
    fn attempt_each(&mut self, db: &mut Client, who: &str, row: &Row, want: [bool; 4], what: &str) {
        for (op, want) in OPS.into_iter().zip(want) {
            let got = attempt(db, who, row.table, row.id, op, row.columns);
            self.seen.entry(op).or_default().insert(got);
            if got != want {
                self.failures.push(format!("{what}, {op:?}: got {got}, want {want}"));
            }
        }
    }

    fn finish(self, name: &str) {
        assert!(self.failures.is_empty(), "{name}: {} of the grid's answers are wrong:\n{}", self.failures.len(), self.failures.join("\n"));
        for op in OPS {
            assert_eq!(self.seen.get(&op).map(BTreeSet::len), Some(2), "{name}: {op:?} was both admitted and refused somewhere in the grid: {:?}", self.seen);
        }
    }
}

fn reads_and_writes(db: &mut Client) {
    let parents: BTreeMap<&str, Option<&str>> = TREE.iter().map(|(id, _, parent)| (*id, *parent)).collect();
    let mut rows: Vec<(String, &str, Option<&str>)> = TREE.iter().map(|(id, space, _)| (format!("t_{id}"), *space, Some(*id))).collect();
    rows.push(("t_shared_s1".into(), "s1", None));
    rows.push(("t_shared_s2".into(), "s2", None));
    for (id, space, folder) in &rows {
        db.execute("INSERT INTO templates (id, estate_id, space_id, folder_id) VALUES ($1, 'e1', $2, $3)", &[id, space, folder]).expect("a template");
    }
    let mut callers: Vec<(&str, Option<&str>)> = vec![("s1", None), ("s2", None)];
    callers.extend(TREE.iter().map(|(id, space, _)| (*space, Some(*id))));
    callers.push(("s2", Some("a")));
    let mut grid = Grid::default();
    for (space, standing) in &callers {
        let who = claims(&[("estate_id", Some("e1")), ("space_id", Some(space)), ("folder_id", *standing)]);
        for (id, row_space, folder) in &rows {
            let beneath = match (standing, folder) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(s), Some(f)) => at_or_beneath(&parents, f, s),
            };
            let above = matches!((standing, folder), (Some(s), Some(f)) if at_or_beneath(&parents, s, f));
            let reads = row_space == space && (beneath || above || folder.is_none());
            let writes = row_space == space && beneath;
            let columns = [("estate_id", Some("e1")), ("space_id", Some(*row_space)), ("folder_id", *folder)];
            let what = format!("standing at {standing:?} in {space}, the template at {folder:?} in {row_space}");
            grid.attempt_each(db, &who, &Row { table: "templates", id, columns: &columns }, [reads, writes, writes, writes], &what);
        }
    }
    grid.finish("templates");
    let who = claims(&[("estate_id", Some("e1")), ("space_id", Some("s1")), ("folder_id", Some("b"))]);
    for (id, want) in [("t_a", true), ("t_b", true), ("t_c", true), ("t_d", false), ("t_e", false), ("t_shared_s1", true)] {
        assert_eq!(attempt(db, &who, "templates", id, Op::Select, &[]), want, "standing at b, reading {id}: above, at and beneath, and never beside");
    }
    for (id, want) in [("t_a", false), ("t_b", true), ("t_c", true), ("t_shared_s1", false)] {
        assert_eq!(attempt(db, &who, "templates", id, Op::Update, &[]), want, "standing at b, changing {id}: at and beneath, never above");
    }
}

fn two_way_reach(db: &mut Client) {
    let parents: BTreeMap<&str, Option<&str>> = TREE.iter().map(|(id, _, parent)| (*id, *parent)).collect();
    let mut rows: Vec<(String, &str, Option<&str>)> = TREE.iter().map(|(id, space, _)| (format!("at_{id}"), *space, Some(*id))).collect();
    rows.push(("at_shared".into(), "s1", None));
    for (id, space, folder) in &rows {
        db.execute("INSERT INTO atlases (id, estate_id, space_id, folder_id) VALUES ($1, 'e1', $2, $3)", &[id, space, folder]).expect("an atlas");
    }
    let mut callers: Vec<(&str, Option<&str>)> = vec![("s1", None)];
    callers.extend(TREE.iter().map(|(id, space, _)| (*space, Some(*id))));
    let mut seen: BTreeMap<Op, BTreeSet<bool>> = BTreeMap::new();
    let mut failures = Vec::new();
    for (space, standing) in &callers {
        let who = claims(&[("estate_id", Some("e1")), ("space_id", Some(space)), ("folder_id", *standing)]);
        for (id, row_space, folder) in &rows {
            let related = matches!((standing, folder), (Some(s), Some(f)) if at_or_beneath(&parents, f, s) || at_or_beneath(&parents, s, f));
            let reads = row_space == space && (folder.is_none() || related);
            let writes = row_space == space && folder == standing;
            for (op, want) in [(Op::Select, reads), (Op::Update, writes)] {
                let got = attempt(db, &who, "atlases", id, op, &[]);
                seen.entry(op).or_default().insert(got);
                failures.extend(
                    (got != want)
                        .then(|| format!("standing at {standing:?} in {space}, {op:?} of the atlas at {folder:?} in {row_space}: got {got}, want {want}")),
                );
            }
        }
    }
    assert!(failures.is_empty(), "{} of the grid's answers are wrong:\n{}", failures.len(), failures.join("\n"));
    assert!(seen.values().all(|outcomes| outcomes.len() == 2), "each operation was both admitted and refused: {seen:?}");
}

fn exact_tier(db: &mut Client) {
    let spaces = [None, Some("s1"), Some("s2")];
    let rows: Vec<(String, &str, Option<&str>)> =
        spaces.iter().enumerate().flat_map(|(i, space)| ["e1", "e2"].map(|estate| (format!("n_{estate}_{i}"), estate, *space))).collect();
    for (id, estate, space) in &rows {
        db.execute("INSERT INTO notices (id, estate_id, space_id) VALUES ($1, $2, $3)", &[id, estate, space]).expect("a notice");
    }
    let mut grid = Grid::default();
    for standing in spaces {
        let who = claims(&[("estate_id", Some("e1")), ("space_id", standing)]);
        for (id, estate, space) in &rows {
            let columns = [("estate_id", Some(*estate)), ("space_id", *space)];
            let what = format!("standing at {standing:?}, the {estate} notice at {space:?}");
            grid.attempt_each(db, &who, &Row { table: "notices", id, columns: &columns }, [*estate == "e1" && *space == standing; 4], &what);
        }
    }
    grid.finish("notices");
}

fn visible_and_calls(db: &mut Client, who: &str, table: &str) -> (BTreeSet<String>, i64) {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL track_functions = 'all'; SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&who]).expect("the claims");
    let counted = format!("SELECT COALESCE(pg_stat_get_xact_function_calls('{AUTH}.space_can_view(text)'::regprocedure), 0)");
    let before: i64 = tx.query_one(&counted, &[]).expect("the call count").get(0);
    let ids = tx.query(&format!("SELECT id FROM {table}"), &[]).expect("the read").iter().map(|r| r.get(0)).collect();
    let after: i64 = tx.query_one(&counted, &[]).expect("the call count").get(0);
    tx.rollback().expect("rollback");
    (ids, after - before)
}

fn pinned_borrow(db: &mut Client) {
    db.batch_execute(
        "INSERT INTO spaces VALUES ('s1', 'e1', 'open'), ('s2', 'e1', 'closed'), ('s3', 'e2', 'open');
         INSERT INTO pages VALUES ('p1', 'e1', 's1'), ('p2', 'e1', 's1'), ('p3', 'e1', 's1'), ('p4', 'e1', 's2'), ('p5', 'e2', 's3');
         INSERT INTO sheets SELECT * FROM pages;",
    )
    .expect("spaces, pages and sheets");
    let own = |ids: &[&str]| -> BTreeSet<String> { ids.iter().map(|id| (*id).to_string()).collect() };
    let cases = [
        (Some("e1"), Some("s1"), own(&["p1", "p2", "p3"]), "an open space's pages"),
        (Some("e1"), Some("s2"), own(&[]), "a closed space's pages"),
        (Some("e2"), Some("s3"), own(&["p5"]), "another estate's open space"),
        (Some("e1"), Some("s3"), own(&[]), "a space claimed under the wrong estate"),
        (Some("e1"), None, own(&[]), "no space claimed"),
        (None, Some("s1"), own(&[]), "no estate claimed"),
    ];
    for (estate, space, want, what) in cases {
        let who = claims(&[("estate_id", estate), ("space_id", space)]);
        let (pinned, pinned_calls) = visible_and_calls(db, &who, "pages");
        let (per_row, per_row_calls) = visible_and_calls(db, &who, "sheets");
        assert_eq!(pinned, want, "{what}");
        assert_eq!(pinned, per_row, "{what}: the pinned borrow admits the rows the per-row borrow admits");
        assert!(pinned_calls <= 1, "{what}: the pinned borrow was asked {pinned_calls} times in one statement");
        assert!(
            per_row_calls >= i64::try_from(want.len()).expect("a small count"),
            "{what}: the per-row borrow was asked {per_row_calls} times for {} rows",
            want.len()
        );
    }
    let who = claims(&[("estate_id", Some("e1")), ("space_id", Some("s1"))]);
    assert_eq!((visible_and_calls(db, &who, "pages").1, visible_and_calls(db, &who, "sheets").1), (1, 3), "three rows: one call pinned, three per row");
}

fn require_terms(db: &mut Client) {
    db.batch_execute(
        "INSERT INTO drafts VALUES ('open', 'e1', 's1', 'open'), ('private', 'e1', 's1', 'private'), ('unset', 'e1', 's1', NULL);
         INSERT INTO ledgers VALUES ('estate', 'e1', NULL, 1), ('space', 'e1', 's1', 1), ('other', 'e1', 's2', 1);",
    )
    .expect("drafts and ledgers");
    for (folder, readable) in [(None, ["open", "private", "unset"].as_slice()), (Some("a"), ["open", "unset"].as_slice())] {
        let who = claims(&[("estate_id", Some("e1")), ("space_id", Some("s1")), ("folder_id", folder)]);
        for id in ["open", "private", "unset"] {
            assert_eq!(attempt(db, &who, "drafts", id, Op::Select, &[]), readable.contains(&id), "confined to {folder:?}, reading the {id} draft");
        }
    }
    for (space, writable) in [(None, "estate"), (Some("s1"), "space"), (Some("s2"), "other")] {
        let who = claims(&[("estate_id", Some("e1")), ("space_id", space)]);
        for id in ["estate", "space", "other"] {
            assert!(attempt(db, &who, "ledgers", id, Op::Select, &[]), "standing at {space:?}, the {id} ledger is read across the estate");
            assert_eq!(attempt(db, &who, "ledgers", id, Op::Update, &[]), id == writable, "standing at {space:?}, changing the {id} ledger");
        }
    }
}

fn a_caller_grows_the_tree_beneath_itself_alone(db: &mut Client) {
    let who = claims(&[("estate_id", Some("e1")), ("space_id", Some("s1")), ("folder_id", Some("b"))]);
    let folder = |parent: &'static str| [("estate_id", Some("e1")), ("space_id", Some("s1")), ("parent_id", Some(parent))];
    assert!(attempt(db, &who, "folders", "under_c", Op::Insert, &folder("c")), "a folder beneath where the caller stands");
    assert!(!attempt(db, &who, "folders", "under_a", Op::Insert, &folder("a")), "a folder above where the caller stands");
    assert!(!attempt(db, &who, "folders", "under_e", Op::Insert, &folder("e")), "a folder beside where the caller stands");
    for (id, want) in [("a", true), ("b", true), ("c", true), ("d", false), ("e", false)] {
        assert_eq!(attempt(db, &who, "folders", id, Op::Select, &[]), want, "standing at b, seeing folder {id}");
    }
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&who]).expect("the claims");
    tx.batch_execute("INSERT INTO folders VALUES ('grown', 'e1', 's1', 'c')").expect("the caller's own insert");
    let reads: Vec<String> = tx.query("SELECT id FROM folders WHERE id = 'grown'", &[]).expect("read it back").iter().map(|r| r.get(0)).collect();
    assert_eq!(reads, ["grown"], "the closure rows the trigger wrote admit the new folder to its maker in the same transaction");
    let direct = tx.query("SELECT 1 FROM paths", &[]).expect_err("the caller has no privilege on the closure itself");
    assert_eq!(direct.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    tx.rollback().expect("rollback");
}
