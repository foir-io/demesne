use demesne_wasm::diagnostics;

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
