use demesne_emit_sql::validate;

fn refusal(name: &str) -> String {
    let path = format!("{}/../../testdata/gaps/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    validate(&s).expect_err("the accessors cannot be enumerated").to_string()
}

#[test]
fn an_accessor_refusal_names_the_definer_schema() {
    let err = refusal("quirk-accessors-schema.demesne");
    assert!(err.contains("cannot soundly enumerate accessors (app_auth.docs_accessors would under-report)"), "{err}");
}

#[test]
fn a_structural_accessor_refusal_names_the_definer_schema() {
    let err = refusal("quirk-structural-schema.demesne");
    assert!(err.contains("cannot soundly enumerate structural accessors (app_auth.assets_accessors would under-report)"), "{err}");
}
