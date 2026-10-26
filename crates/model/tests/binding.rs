use demesne_model::{Schema, table_coverage, validate_against};
use std::collections::BTreeSet;

const SPECS: [&str; 5] = [
    "examples/example.demesne",
    "examples/require.demesne",
    "examples/planes.demesne",
    "testdata/corpus/fixtures/00210470d043a9fd.demesne",
    "testdata/corpus/fixtures/1ff083d6edb9f814.demesne",
];

fn spec(path: &str) -> demesne_syntax::Spec {
    let src = std::fs::read_to_string(format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))).expect("the spec reads");
    demesne_syntax::parse(&src).expect("the spec parses")
}

fn refusals(s: &demesne_syntax::Spec, sc: &Schema) -> Vec<String> {
    validate_against(s, sc).err().map(|e| e.findings().iter().map(ToString::to_string).collect()).unwrap_or_default()
}

fn tables_without_columns(tables: &BTreeSet<String>) -> Schema {
    let mut sc = Schema::new();
    for t in tables {
        sc.add_column(t, "placeholder", "text", true);
    }
    sc
}

fn required_tables(s: &demesne_syntax::Spec) -> BTreeSet<String> {
    let mut tables = BTreeSet::new();
    loop {
        let missing: BTreeSet<String> = refusals(s, &tables_without_columns(&tables))
            .iter()
            .filter(|m| m.ends_with("not found in the database"))
            .filter_map(|m| m.split_once("table \"").and_then(|(_, rest)| rest.split_once('"')).map(|(t, _)| t.to_string()))
            .collect();
        if missing.is_subset(&tables) {
            return tables;
        }
        tables.extend(missing);
    }
}

#[test]
fn an_empty_database_lacks_every_table_the_spec_names() {
    for path in SPECS {
        insta::assert_snapshot!(format!("tables__{}", path.rsplit('/').next().unwrap_or(path)), refusals(&spec(path), &Schema::new()).join("\n"));
    }
}

#[test]
fn tables_without_columns_lack_every_column_the_spec_binds() {
    for path in SPECS {
        let s = spec(path);
        let sc = tables_without_columns(&required_tables(&s));
        insta::assert_snapshot!(format!("columns__{}", path.rsplit('/').next().unwrap_or(path)), refusals(&s, &sc).join("\n"));
    }
}

#[test]
fn coverage_sorts_the_databases_tables_by_what_the_spec_does_with_them() {
    for fixture in ["00210470d043a9fd", "31d37e1a0a70ec66"] {
        let s = spec(&format!("testdata/corpus/fixtures/{fixture}.demesne"));
        let mut db: Vec<String> = required_tables(&s).into_iter().collect();
        db.push("unrelated_log".into());
        insta::assert_debug_snapshot!(format!("coverage__{fixture}"), table_coverage(&s, &db));
    }
}

#[test]
fn an_export_binds_every_column_its_requirements_read() {
    let src = std::fs::read_to_string(format!("{}/../../examples/require.demesne", env!("CARGO_MANIFEST_DIR"))).expect("the spec reads");
    let s = demesne_syntax::parse(&src.replace("  require create =", "  export create as may_create(tenant_id text)\n  require create ="))
        .expect("the spec parses");
    let demesne_model::Structure::Errors(findings) = demesne_model::validate_structure(&s) else { panic!("the topology is sound") };
    let messages: Vec<String> = findings.iter().map(|f| f.message().to_string()).collect();
    assert_eq!(messages, ["export \"may_create\" reads row column \"project_ids\", which no parameter binds"]);
}
