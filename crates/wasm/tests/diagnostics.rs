use demesne_wasm::{diagnostics, diagnostics_files};

fn spec(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../testdata/gaps/{name}", env!("CARGO_MANIFEST_DIR"))).expect("the fixture reads")
}

#[test]
fn a_valid_spec_has_no_findings() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/example.demesne")).expect("example spec");
    assert_eq!(diagnostics(&src), "[]");
}

#[test]
fn each_validation_error_carries_its_line() {
    let got = diagnostics(&spec("d37-wider-write.demesne"));
    assert!(
        got.starts_with(r#"[{"severity":"error","line":24,"message":"permission note.remove maps delete, and its term `grantee:write` admits callers"#),
        "{got}"
    );
    assert!(got.contains(r#"{"severity":"error","line":25,"message":"permission note.edit maps update"#), "{got}");
}

#[test]
fn a_blind_write_is_a_warning_on_its_line() {
    let src = spec("d37-wider-write.demesne").replace("@rls maps delete", "@rls maps delete blind").replace("@rls maps update", "@rls maps update blind");
    let got = diagnostics(&src);
    assert!(got.starts_with(r#"[{"severity":"warning","line":24,"message":"permission note.remove maps delete"#), "{got}");
    assert!(!got.contains(r#""severity":"error""#), "{got}");
}

#[test]
fn a_parse_error_and_an_unplaced_error_keep_their_text() {
    assert_eq!(diagnostics("topology {"), r#"[{"severity":"error","line":1,"message":"expected }, got EOF \"\""}]"#);
    let got = diagnostics(&spec("quirk-accessors-schema.demesne"));
    assert!(
        got.contains(
            r#"{"severity":"error","line":null,"message":"definer closure (V11): kernel does not emit: object \"doc\": cannot soundly enumerate accessors"#
        ),
        "{got}"
    );
}

#[test]
fn a_finding_in_a_spec_of_several_files_names_its_file() {
    let base = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/multi/base.demesne")).expect("the fixture reads");
    let bad = "\nobject stray {\n  table strays\n  scoped tenant > workspace\n  relation owner: member via owner_id\n  permission view = nobody @rls maps select\n}\n";
    let got = diagnostics_files(vec!["base.demesne".into(), "bad.demesne".into()], vec![base.clone(), bad.into()]);
    assert!(got.starts_with(r#"[{"severity":"error","file":"bad.demesne","line":6,"message":"permission stray.view references unknown relation"#), "{got}");
    assert_eq!(diagnostics_files(vec!["base.demesne".into()], vec![base]), "[]");
}
