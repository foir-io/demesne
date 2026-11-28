use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_bounds_first_rows";
const AUTH: &str = "demesne_bounds_first_auth";
const CALLER: &str = "demesne_bounds_first_caller";

fn spec() -> String {
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate level space parent estate }}\nsubject member {{ anchor space; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  permission view = owner + some r in rules_live prefix \"read.\" held rules_held clear of rules_cleared (mode visibility = \"listed\" + @claim(\"team\", \"blue\")) @rls maps select\n  permission edit = owner and not some r in rules_live prefix \"read.\" clear of rules_cleared (mode state = \"locked\" + @claim(\"team\", \"red\")) @rls maps update\n}}\n"
    )
}

const RULES: [Option<&[&str]>; 6] = [None, Some(&[]), Some(&["read.a"]), Some(&["read.a", "write.b"]), Some(&["write.b"]), Some(&["read.b"])];
const VISIBILITY: [Option<&str>; 3] = [Some("listed"), Some("private"), None];
const STATE: [Option<&str>; 3] = [Some("locked"), Some("open"), None];
const OWNERS: [&str; 2] = ["ann", "bob"];

const HELD: [Option<&[&str]>; 4] = [None, Some(&[]), Some(&["read.a"]), Some(&["read.a", "read.b"])];
const CLEARED: [Option<&[&str]>; 3] = [None, Some(&[]), Some(&["read.b"])];
const TEAMS: [Option<&str>; 3] = [None, Some("blue"), Some("red")];

struct Doc {
    id: String,
    owner: &'static str,
    visibility: Option<&'static str>,
    state: Option<&'static str>,
    rules: Option<&'static [&'static str]>,
}

struct Caller {
    who: &'static str,
    held: Option<&'static [&'static str]>,
    cleared: Option<&'static [&'static str]>,
    team: Option<&'static str>,
}

fn docs() -> Vec<Doc> {
    let shapes = RULES.into_iter().enumerate().flat_map(|(r, rules)| VISIBILITY.into_iter().enumerate().map(move |(v, visibility)| (r, rules, v, visibility)));
    shapes
        .flat_map(|(r, rules, v, visibility)| {
            STATE
                .into_iter()
                .enumerate()
                .flat_map(move |(s, state)| OWNERS.into_iter().map(move |owner| Doc { id: format!("{owner}-{r}{v}{s}"), owner, visibility, state, rules }))
        })
        .collect()
}

fn callers() -> Vec<Caller> {
    let holding = ["ann", "eve"].into_iter().flat_map(|who| HELD.into_iter().map(move |held| (who, held)));
    holding
        .flat_map(|(who, held)| CLEARED.into_iter().flat_map(move |cleared| TEAMS.into_iter().map(move |team| Caller { who, held, cleared, team })))
        .collect()
}

fn bound(d: &Doc, c: &Caller, by_held: bool) -> bool {
    d.rules
        .unwrap_or_default()
        .iter()
        .any(|e| e.starts_with("read.") && (!by_held || c.held.is_some_and(|h| h.contains(e))) && c.cleared.is_some_and(|cl| !cl.contains(e)))
}

fn or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn equals(value: Option<&str>, want: &str) -> Option<bool> {
    value.map(|v| v == want)
}

fn reads(d: &Doc, c: &Caller) -> bool {
    let body = or(equals(d.visibility, "listed"), equals(c.team, "blue"));
    d.owner == c.who || (bound(d, c, true) && body == Some(true))
}

fn edits(d: &Doc, c: &Caller) -> bool {
    let body = or(equals(d.state, "locked"), equals(c.team, "red"));
    d.owner == c.who && !(bound(d, c, false) && body != Some(false))
}

fn install(db: &mut Client, rows: &[Doc]) {
    let s = demesne_syntax::parse(&spec()).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN CREATE ROLE {CALLER} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, owner_id text, visibility text, state text, rules_live text[]);"
    ))
    .expect("fresh schemas and tables");
    for d in rows {
        let rules: Option<Vec<&str>> = d.rules.map(<[&str]>::to_vec);
        db.execute("INSERT INTO docs VALUES ($1, 'e1', 's1', $2, $3, $4, $5)", &[&d.id, &d.owner, &d.visibility, &d.state, &rules]).expect("a doc");
    }
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, UPDATE ON {ROWS}.docs TO {CALLER};")).expect("grants");
}

fn list(items: Option<&[&str]>) -> Option<String> {
    items.map(|xs| format!("[{}]", xs.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(",")))
}

fn claims(c: &Caller) -> String {
    let mut fields = vec![format!("\"sub\":\"{}\"", c.who), "\"estate_id\":\"e1\"".to_string(), "\"space_id\":\"s1\"".to_string()];
    fields.extend(list(c.held).map(|l| format!("\"rules_held\":{l}")));
    fields.extend(list(c.cleared).map(|l| format!("\"rules_cleared\":{l}")));
    fields.extend(c.team.map(|t| format!("\"team\":\"{t}\"")));
    format!("{{{}}}", fields.join(","))
}

fn answered(db: &mut Client, c: &Caller, update: bool) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims(c)]).expect("the claims");
    let sql = if update { "UPDATE docs SET id = id RETURNING id" } else { "SELECT id FROM docs" };
    let ids = tx.query(sql, &[]).expect("the statement").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_some_that_tests_its_bounds_before_its_body_answers_as_the_body_inside_the_scan_would() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the bounds-first checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    let rows = docs();
    install(&mut db, &rows);
    let mut failures = Vec::new();
    let (mut read_through_some, mut edit_refused_by_some, mut edit_refused_by_unknown) = (0, 0, 0);
    for c in callers() {
        let want: BTreeSet<String> = rows.iter().filter(|d| reads(d, &c)).map(|d| d.id.clone()).collect();
        let got = answered(&mut db, &c, false);
        if got != want {
            failures.push(format!("{} reads differently on {:?}", claims(&c), got.symmetric_difference(&want).collect::<Vec<_>>()));
        }
        read_through_some += rows.iter().filter(|d| d.owner != c.who && reads(d, &c)).count();
        let want: BTreeSet<String> = rows.iter().filter(|d| edits(d, &c)).map(|d| d.id.clone()).collect();
        let got = answered(&mut db, &c, true);
        if got != want {
            failures.push(format!("{} edits differently on {:?}", claims(&c), got.symmetric_difference(&want).collect::<Vec<_>>()));
        }
        let refused = rows.iter().filter(|d| d.owner == c.who && !edits(d, &c));
        for d in refused {
            edit_refused_by_some += 1;
            if or(equals(d.state, "locked"), equals(c.team, "red")).is_none() {
                edit_refused_by_unknown += 1;
            }
        }
    }
    assert!(failures.is_empty(), "{} wrong answers:\n{}", failures.len(), failures.join("\n"));
    assert!(read_through_some > 50, "the grid admits through the some: {read_through_some}");
    assert!(
        edit_refused_by_some > 50 && edit_refused_by_unknown > 10,
        "the grid refuses through the negated some, an unknown body among them: {edit_refused_by_some}, {edit_refused_by_unknown}"
    );
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
