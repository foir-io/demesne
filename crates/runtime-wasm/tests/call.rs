use demesne_runtime_wasm::call;

#[test]
fn an_operation_answers_in_the_ok_envelope() {
    assert_eq!(call("holds.scopeContains", r#"{"assignment":["t1",""],"query":["t1","w1"]}"#), r#"{"ok":true}"#);
    assert_eq!(call("pdp.composeCan", r#"{"pointGoverned":true,"pointAllow":false,"pdp":"allow"}"#), r#"{"ok":"deny"}"#);
}

#[test]
fn a_failure_answers_in_the_error_envelope() {
    assert_eq!(call("holds.nope", "{}"), r#"{"error":"demesne runtime: no operation \"holds.nope\""}"#);
    assert!(call("claims.mint", "{").starts_with(r#"{"error":"demesne runtime: claims.mint: "#));
    assert_eq!(
        call("claims.mint", r#"{"claims":{"contract":["sub"]},"values":{"zeta":"1"}}"#),
        r#"{"error":"MintClaims: key(s) not in the claims contract: [zeta]"}"#
    );
}
