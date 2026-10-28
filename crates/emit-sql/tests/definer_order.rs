use demesne_emit_sql::{Object, Sql, objects, validate};

mod common;
use common::corpus;

fn first_use(sql: &str, name: &str) -> Option<usize> {
    let call = format!("{name}(");
    sql.match_indices(&call).map(|(k, _)| k).find(|&k| sql[..k].chars().next_back().is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_')))
}

fn created_at(sql: &str, name: &str) -> usize {
    ["CREATE OR REPLACE FUNCTION", "CREATE FUNCTION"]
        .iter()
        .filter_map(|create| sql.find(&format!("{create} {name}(")).map(|k| k + create.len() + 1))
        .min()
        .unwrap_or_else(|| panic!("the manifest names {name}, which the SQL never creates"))
}

fn called_before_created(sql: &str) -> Vec<String> {
    let mut early = Vec::new();
    for (o, _) in objects(sql).expect("the SQL has a manifest") {
        let Object::Function(sig) = o else { continue };
        let name = sig.split('(').next().expect("a signature starts with its name");
        if first_use(sql, name).is_some_and(|k| k < created_at(sql, name)) {
            early.push(name.to_string());
        }
    }
    early
}

#[test]
fn every_generated_function_is_created_before_anything_calls_it() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for p in corpus() {
        let src = std::fs::read_to_string(&p).expect("the spec reads");
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if validate(&s).is_err() {
            continue;
        }
        let mut sql = String::new();
        if Sql::new(&s).write_all_sql(&mut sql).is_err() {
            continue;
        }
        let early = called_before_created(&sql);
        if !early.is_empty() {
            failures.push(format!("{}: {early:?}", p.display()));
        }
        checked += 1;
    }
    assert!(failures.is_empty(), "{} specs call a function before creating it:\n{}", failures.len(), failures.join("\n"));
    assert!(checked > 100, "only {checked} corpus specs emitted");
}
