use postgres::{Client, NoTls};
use std::collections::BTreeSet;
use std::fmt::Write as _;

const CALLER: &str = "demesne_cond_caller";
const RADIUS_KM: f64 = 6371.0;

#[derive(Debug, Clone, Default)]
struct Stored {
    num: Option<f64>,
    txt: Option<&'static str>,
    at: Option<i64>,
    list: Option<&'static [&'static str]>,
    point: Option<(f64, f64)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Missing,
    Num(f64),
    Txt(&'static str),
    List(&'static [Value]),
    Point(f64, f64),
}

fn instant(seconds: i64) -> String {
    format!("2026-03-01T00:00:{seconds:02}Z")
}

fn parsed(text: &str) -> Option<i64> {
    (0..60).find(|s| instant(*s) == text)
}

fn json(v: &Value) -> Option<String> {
    Some(match v {
        Value::Missing => return None,
        Value::Num(n) => format!("{n}"),
        Value::Txt(t) => format!("\"{t}\""),
        Value::List(items) => format!("[{}]", items.iter().filter_map(json).collect::<Vec<_>>().join(",")),
        Value::Point(lat, lng) => format!("{{\"lat\":{lat},\"lng\":{lng}}}"),
    })
}

fn haversine_km((lat1, lng1): (f64, f64), (lat2, lng2): (f64, f64)) -> f64 {
    let a =
        ((lat2 - lat1).to_radians() / 2.0).sin().powi(2) + lat1.to_radians().cos() * lat2.to_radians().cos() * ((lng2 - lng1).to_radians() / 2.0).sin().powi(2);
    RADIUS_KM * 2.0 * a.min(1.0).sqrt().atan2((1.0 - a).max(0.0).sqrt())
}

fn in_range((lat, lng): (f64, f64)) -> bool {
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lng)
}

fn ordering(s: &Stored, v: &Value, with_text: bool) -> Option<std::cmp::Ordering> {
    match (s.num, s.at, s.txt, v) {
        (Some(n), _, _, Value::Num(c)) => n.partial_cmp(c),
        (None, Some(at), _, Value::Txt(c)) => parsed(c).map(|c| at.cmp(&c)),
        (None, None, Some(t), Value::Txt(c)) if with_text => Some(t.cmp(c)),
        _ => None,
    }
}

fn text_test(name: &str, s: &Stored, v: &Value) -> Option<bool> {
    let (Some(stored), Value::Txt(caller)) = (s.txt, v) else { return None };
    Some(match name {
        "contains" => stored.contains(caller),
        "prefix" => stored.starts_with(caller),
        "suffix" => stored.ends_with(caller),
        "caller_contains" => caller.contains(stored),
        "caller_prefix" => caller.starts_with(stored),
        "caller_suffix" => caller.ends_with(stored),
        _ => return None,
    })
}

fn holds(op: &str, s: &Stored, v: &Value) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let among = |items: &[Value]| {
        items.iter().any(|i| {
            matches!((i, s.num, s.txt), (Value::Num(c), Some(n), _) if c.partial_cmp(&n) == Some(Equal))
                || matches!((i, s.txt), (Value::Txt(c), Some(t)) if *c == t)
        })
    };
    let scalar = match v {
        Value::Num(n) => Some(format!("{n}")),
        Value::Txt(t) => Some((*t).to_string()),
        _ => None,
    };
    let listed = || s.list.zip(scalar.as_ref()).map(|(list, c)| list.contains(&c.as_str()));
    let answer = match op {
        "eq" => ordering(s, v, true).map(|o| o == Equal),
        "ne" => ordering(s, v, true).map(|o| o != Equal),
        "lt" => ordering(s, v, false).map(|o| o == Less),
        "le" => ordering(s, v, false).map(|o| o != Greater),
        "gt" => ordering(s, v, false).map(|o| o == Greater),
        "ge" => ordering(s, v, false).map(|o| o != Less),
        "in" => {
            if let Value::List(items) = v {
                Some(among(items))
            } else {
                None
            }
        }
        "not_in" => {
            if let Value::List(items) = v {
                Some(!among(items))
            } else {
                None
            }
        }
        "includes" => listed(),
        "not_includes" => listed().map(|b| !b),
        "not_before" => s.at.map(|at| at <= 30),
        "not_after" => s.at.map(|at| at >= 30),
        "within_km" => match (s.point, s.num, v) {
            (Some(p), Some(r), Value::Point(lat, lng)) if in_range(p) && in_range((*lat, *lng)) && r >= 0.0 => Some(haversine_km(p, (*lat, *lng)) <= r),
            _ => None,
        },
        negated if negated.starts_with("not_") => text_test(&negated[4..], s, v).map(|b| !b),
        positive => text_test(positive, s, v),
    };
    answer == Some(true)
}

const OPS: [&str; 29] = [
    "eq",
    "ne",
    "lt",
    "le",
    "gt",
    "ge",
    "in",
    "not_in",
    "includes",
    "not_includes",
    "contains",
    "not_contains",
    "prefix",
    "not_prefix",
    "suffix",
    "not_suffix",
    "caller_contains",
    "not_caller_contains",
    "caller_prefix",
    "not_caller_prefix",
    "caller_suffix",
    "not_caller_suffix",
    "not_before",
    "not_after",
    "within_km",
    "unknown_operator",
    "EQ",
    "",
    "matches",
];

fn stored_values() -> Vec<Stored> {
    vec![
        Stored { num: Some(5.0), ..Default::default() },
        Stored { num: Some(-0.5), ..Default::default() },
        Stored { txt: Some("alpha"), ..Default::default() },
        Stored { txt: Some("Alpha"), ..Default::default() },
        Stored { txt: Some(""), ..Default::default() },
        Stored { at: Some(10), ..Default::default() },
        Stored { at: Some(50), ..Default::default() },
        Stored { list: Some(&["alpha", "5", "beta"]), ..Default::default() },
        Stored { list: Some(&[]), ..Default::default() },
        Stored { num: Some(111.2), point: Some((0.0, 0.0)), ..Default::default() },
        Stored { num: Some(111.19), point: Some((0.0, 0.0)), ..Default::default() },
        Stored { num: Some(112.0), point: Some((0.0, 179.5)), ..Default::default() },
        Stored { num: Some(0.0), point: Some((51.5, -0.12)), ..Default::default() },
        Stored { num: Some(100.0), point: Some((91.0, 0.0)), ..Default::default() },
        Stored::default(),
    ]
}

const LIST_A: [Value; 3] = [Value::Num(5.0), Value::Txt("alpha"), Value::Txt("zeta")];
const LIST_B: [Value; 1] = [Value::Num(6.0)];

fn caller_values() -> Vec<Value> {
    vec![
        Value::Missing,
        Value::Num(5.0),
        Value::Num(6.0),
        Value::Num(-0.5),
        Value::Txt("alpha"),
        Value::Txt("alphabet"),
        Value::Txt("ph"),
        Value::Txt(""),
        Value::Txt("5"),
        Value::Txt("2026-03-01T00:00:10Z"),
        Value::Txt("2026-03-01T00:00:20Z"),
        Value::Txt("2026-13-41T00:00:10Z"),
        Value::Txt("yesterday"),
        Value::List(&LIST_A),
        Value::List(&LIST_B),
        Value::List(&[]),
        Value::Point(1.0, 0.0),
        Value::Point(0.0, -179.5),
        Value::Point(51.5, -0.12),
        Value::Point(0.0, 181.0),
    ]
}

fn install(db: &mut Client, schema: &str, extension: &str) -> usize {
    let (rows, auth) = (format!("{schema}_rows"), format!("{schema}_auth"));
    let spec = format!(
        "{extension}definers schema \"{auth}\"\ntables schema \"{rows}\"\ntopology {{ level estate }}\nsubject member {{ anchor estate; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate\n  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation fits: member via conditions doc_terms(object_id, term, op) values (num, txt, at, list, lat, lng) on id from claim facts\n  relation matches: member via conditions rule_terms(object_id, term, op) values (num, txt, at) key rule_id on id from claim facts\n  permission view = owner + (@kind(\"member\") and fits) + some r in rules_live (named and matches) @rls maps select\n}}\n"
    );
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    let mut setup = format!(
        "DROP SCHEMA IF EXISTS {rows} CASCADE; DROP SCHEMA IF EXISTS {auth} CASCADE; CREATE SCHEMA {rows}; CREATE SCHEMA {auth};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {rows}, public;
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, owner_id text, rules_live text[]);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text);
         CREATE TABLE doc_terms (object_id text, term text, op text, num double precision, txt text, at timestamptz, list text[], lat double precision, lng double precision);
         CREATE TABLE rule_terms (object_id text, rule_id text, term text, op text, num double precision, txt text, at timestamptz);\n"
    );
    let stored = stored_values();
    for (i, s) in stored.iter().enumerate() {
        for op in OPS {
            let or_null = |v: Option<String>| v.unwrap_or_else(|| "NULL".into());
            let list = s.list.map(|l| format!("ARRAY[{}]::text[]", l.iter().map(|x| format!("'{x}'")).collect::<Vec<_>>().join(",")));
            writeln!(
                setup,
                "INSERT INTO docs VALUES ('{op}:{i}', 'e1', 'ann', NULL); INSERT INTO doc_terms VALUES ('{op}:{i}', 'fact', '{op}', {}, {}, {}, {}, {}, {});",
                or_null(s.num.map(|n| format!("{n}"))),
                or_null(s.txt.map(|t| format!("'{t}'"))),
                or_null(s.at.map(|a| if op.starts_with("not_before") || op.starts_with("not_after") {
                    format!("now() + interval '{} hours'", a - 30)
                } else {
                    format!("'{}'", instant(a))
                })),
                or_null(list),
                or_null(s.point.map(|p| format!("{}", p.0))),
                or_null(s.point.map(|p| format!("{}", p.1)))
            )
            .expect("fmt::Write for String never fails");
        }
    }
    db.batch_execute(&setup).expect("fresh schemas, tables and rows");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {rows}, {auth} TO {CALLER}; GRANT SELECT ON {rows}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {auth} TO {CALLER};")).expect("grants");
    stored.len()
}

fn visible(db: &mut Client, who: &str, facts: &str) -> BTreeSet<String> {
    visible_as(db, who, "member", facts)
}

fn visible_as(db: &mut Client, who: &str, kind: &str, facts: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"kind\":\"{kind}\"{facts}}}")])
        .expect("the claims");
    let ids = tx.query("SELECT id FROM docs", &[]).expect("the read").iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    ids
}

fn connect() -> Client {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the stored-condition checks against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn every_operator_answers_as_the_oracle_does_and_undecidable_is_false() {
    let mut db = connect();
    install(&mut db, "demesne_cond", "");
    let stored = stored_values();
    let mut failures = Vec::new();
    let mut seen: std::collections::BTreeMap<&str, BTreeSet<bool>> = std::collections::BTreeMap::new();
    for v in caller_values() {
        let facts = json(&v).map(|j| format!(",\"facts\":{{\"fact\":{j}}}")).unwrap_or_default();
        let got = visible(&mut db, "bob", &facts);
        for (i, s) in stored.iter().enumerate() {
            for op in OPS {
                let (want, answer) = (holds(op, s, &v), got.contains(&format!("{op}:{i}")));
                seen.entry(op).or_default().insert(answer);
                failures.extend((want != answer).then(|| format!("{op} with {s:?} stored and {v:?} claimed: got {answer}, want {want}")));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} answers are wrong:\n{}",
        failures.len(),
        stored.len() * OPS.len() * caller_values().len(),
        failures[..failures.len().min(40)].join("\n")
    );
    for op in &OPS[..25] {
        assert_eq!(seen[op].len(), 2, "{op} both held and failed somewhere in the grid");
    }
    for op in &OPS[25..] {
        assert_eq!(seen[op], BTreeSet::from([false]), "{op} is no operator, so it never holds");
    }
    assert_eq!(visible(&mut db, "ann", "").len(), stored.len() * OPS.len(), "the owner needs no condition");
    db.batch_execute("INSERT INTO docs VALUES ('free', 'e1', 'ann', NULL)").expect("a row with no condition");
    assert!(visible(&mut db, "bob", "").contains("free"), "a row that stores no condition is held back by none");
    db.batch_execute("RESET search_path; DROP SCHEMA demesne_cond_rows CASCADE; DROP SCHEMA demesne_cond_auth CASCADE;").expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn keyed_conditions_are_those_of_the_bound_element_and_all_of_them() {
    let mut db = connect();
    install(&mut db, "demesne_condk", "");
    db.batch_execute(
        "INSERT INTO docs VALUES ('keyed', 'e1', 'ann', ARRAY['r1', 'r2']);
         INSERT INTO doc_edges VALUES ('bob', 'keyed', 'r1'), ('bob', 'keyed', 'r2');
         INSERT INTO rule_terms VALUES ('keyed', 'r1', 'level', 'le', 3, NULL, NULL), ('keyed', 'r1', 'team', 'eq', NULL, 'blue', NULL), ('keyed', 'r2', 'level', 'le', 9, NULL, NULL), ('keyed', 'r2', 'team', 'eq', NULL, 'red', NULL);",
    )
    .expect("a keyed row");
    for (facts, want, why) in [
        ("{\"level\":5,\"team\":\"blue\"}", true, "every condition of r1"),
        ("{\"level\":5,\"team\":\"red\"}", false, "one condition of each element"),
        ("{\"level\":9,\"team\":\"red\"}", true, "every condition of r2"),
        ("{\"level\":2,\"team\":\"blue\"}", false, "r1's level bound fails"),
        ("{\"team\":\"blue\"}", false, "a condition whose term the caller lacks"),
    ] {
        assert_eq!(visible_as(&mut db, "bob", "guest", &format!(",\"facts\":{facts}")).contains("keyed"), want, "{facts}: {why}");
    }
    db.batch_execute("RESET search_path; DROP SCHEMA demesne_condk_rows CASCADE; DROP SCHEMA demesne_condk_auth CASCADE;").expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL on a database that has PostGIS; run with -- --ignored"]
fn with_postgis_declared_within_km_measures_on_the_spheroid() {
    let mut db = connect();
    db.batch_execute("CREATE EXTENSION IF NOT EXISTS postgis")
        .expect("the database $DEMESNE_PG_URL names must have PostGIS available to check the spheroid emitter");
    install(&mut db, "demesne_condg", "extension postgis\n");
    let stored = stored_values();
    let geo: Vec<usize> = stored.iter().enumerate().filter(|(_, s)| s.point.is_some()).map(|(i, _)| i).collect();
    let mut both = BTreeSet::new();
    for v in caller_values().into_iter().filter(|v| matches!(v, Value::Point(..) | Value::Missing | Value::Num(_))) {
        let facts = json(&v).map(|j| format!(",\"facts\":{{\"fact\":{j}}}")).unwrap_or_default();
        let got = visible(&mut db, "bob", &facts);
        for &i in &geo {
            let s = &stored[i];
            let sphere = holds("within_km", s, &v);
            let near_the_edge = matches!((s.point, s.num, &v), (Some(p), Some(r), Value::Point(lat, lng)) if in_range(p) && in_range((*lat, *lng)) && (haversine_km(p, (*lat, *lng)) - r).abs() <= 0.006 * r.max(1.0));
            let answer = got.contains(&format!("within_km:{i}"));
            both.insert(answer);
            assert!(
                near_the_edge || answer == sphere,
                "{s:?} stored and {v:?} claimed: the spheroid says {answer}, the sphere {sphere}, and they are not within 0.5% of the radius"
            );
        }
    }
    assert_eq!(both.len(), 2, "the spheroid both admits and refuses");
    db.batch_execute("RESET search_path; DROP SCHEMA demesne_condg_rows CASCADE; DROP SCHEMA demesne_condg_auth CASCADE;").expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn an_exception_whose_condition_cannot_be_decided_bars() {
    let mut db = connect();
    let (rows, auth) = ("demesne_condx_rows", "demesne_condx_auth");
    let spec = format!(
        "definers schema \"{auth}\"\ntables schema \"{rows}\"\ntopology {{ level estate }}\nsubject member {{ anchor estate; reach self; identifies sub; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate\n  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation barred: member via edge doc_bars(principal_id, object_id) key rule_id slot slot\n  relation bar_terms: member via conditions bar_terms(object_id, term, op) values (num, txt, at) key rule_id on id from claim facts\n  permission view = owner + some r in rules_live (named and none s in rule_slots(rule_id) (barred and bar_terms)) @rls maps select\n}}\n"
    );
    let s = demesne_syntax::parse(&spec).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {rows} CASCADE; DROP SCHEMA IF EXISTS {auth} CASCADE; CREATE SCHEMA {rows}; CREATE SCHEMA {auth};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {rows};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, owner_id text, rules_live text[]);
         CREATE TABLE doc_edges (principal_id text, object_id text, rule_id text);
         CREATE TABLE doc_bars (principal_id text, object_id text, rule_id text, slot text);
         CREATE TABLE rule_slots (rule_id text, slot text);
         CREATE TABLE bar_terms (object_id text, rule_id text, term text, op text, num double precision, txt text, at timestamptz);
         INSERT INTO docs VALUES ('d', 'e1', 'ann', ARRAY['r1']);
         INSERT INTO doc_edges VALUES ('bob', 'd', 'r1'), ('cat', 'd', 'r1');
         INSERT INTO rule_slots VALUES ('r1', '1');
         INSERT INTO doc_bars VALUES ('bob', 'd', 'r1', '1');
         INSERT INTO bar_terms VALUES ('d', 'r1', 'level', 'ge', 5, NULL, NULL);"
    ))
    .expect("fresh schemas, tables and rows");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!("GRANT USAGE ON SCHEMA {rows}, {auth} TO {CALLER}; GRANT SELECT ON {rows}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {auth} TO {CALLER};")).expect("grants");
    for (who, facts, reads, why) in [
        ("bob", ",\"facts\":{\"level\":3}", false, "the exception's edge and its condition both hold, so it bars"),
        ("bob", ",\"facts\":{\"level\":9}", true, "the exception's condition is decided false, so it does not bar"),
        ("bob", "", false, "the caller carries no level, so the exception's condition cannot be decided, and it bars"),
        ("bob", ",\"facts\":{\"level\":\"high\"}", false, "a level of the wrong type cannot be decided either"),
        ("cat", "", true, "no exception edge for this caller, whatever the condition"),
        ("cat", ",\"facts\":{\"level\":3}", true, "no exception edge for this caller"),
    ] {
        assert_eq!(visible(&mut db, who, facts).contains("d"), reads, "{who} with {facts:?}: {why}");
    }
    let answers: Vec<Option<bool>> = ["{\"level\":3}", "{\"level\":9}", "{}", "{\"level\":\"high\"}"]
        .iter()
        .map(|facts| db.query_one(&format!("SELECT {auth}.doc_bar_terms_hold('d', 'r1', $1::text::jsonb)"), &[facts]).expect("the function").get(0))
        .collect();
    assert_eq!(answers, [Some(true), Some(false), None, None], "true and false when decided, NULL when not");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {rows} CASCADE; DROP SCHEMA {auth} CASCADE;")).expect("drop the schemas");
}
