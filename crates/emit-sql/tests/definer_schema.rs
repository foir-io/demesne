use demesne_emit_sql::{Object, Sql, objects, validate};
use std::collections::BTreeSet;

mod common;
use common::corpus;

fn calls_elsewhere(sql: &str, schema: &str) -> Vec<String> {
    let created: BTreeSet<String> = objects(sql)
        .expect("the SQL has a manifest")
        .into_iter()
        .filter_map(
            |(o, _)| if let Object::Function(sig) = o { sig.split('(').next().and_then(|n| n.rsplit_once('.')).map(|(_, n)| n.to_string()) } else { None },
        )
        .collect();
    let mut wrong = BTreeSet::new();
    for name in &created {
        let call = format!(".{name}(");
        let mut from = 0;
        while let Some(k) = sql[from..].find(&call).map(|k| from + k) {
            let start = sql[..k].rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |s| s + 1);
            if &sql[start..k] != schema {
                wrong.insert(format!("{}.{name}", &sql[start..k]));
            }
            from = k + call.len();
        }
    }
    wrong.into_iter().collect()
}

#[test]
fn every_call_to_a_generated_function_names_the_definer_schema() {
    let mut checked = 0;
    for p in corpus() {
        let src = std::fs::read_to_string(&p).expect("the spec reads");
        if src.contains("definers schema") {
            continue;
        }
        let Ok(s) = demesne_syntax::parse(&format!("definers schema \"zz_auth\"\n{src}")) else { continue };
        if validate(&s).is_err() {
            continue;
        }
        let mut sql = String::new();
        if Sql::new(&s).write_all_sql(&mut sql).is_err() {
            continue;
        }
        let wrong = calls_elsewhere(&sql, "zz_auth");
        assert!(wrong.is_empty(), "{}: calls {wrong:?}, but the SQL creates them in zz_auth", p.display());
        checked += 1;
    }
    assert!(checked > 100, "only {checked} corpus specs emitted");
}
