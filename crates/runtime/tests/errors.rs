use demesne_gocompat::json::Value;
use demesne_runtime::{Error, Principal, ResourceAccessSurface, Vocabulary, Zookie, build_claims, capability_gate_err, owned, projection};
use std::collections::BTreeMap;

fn kinds(e: &Error) -> [bool; 6] {
    [e.is_claims(), e.is_consistency(), e.is_vocabulary(), e.is_access(), e.is_capability_gate(), e.is_input()]
}

#[test]
fn each_refusal_says_which_kind_it_is() {
    let principal = Principal { subject: "nobody".into(), id: String::new(), scopes: BTreeMap::default() };
    let claims = build_claims(&[], &[], &principal).expect_err("no such subject");
    assert_eq!(kinds(&claims), [true, false, false, false, false, false], "{claims}");

    let consistency = Zookie::parse("+1").expect_err("a leading plus is refused");
    assert_eq!(kinds(&consistency), [false, true, false, false, false, false], "{consistency}");

    let vocab = Vocabulary { name: owned("v"), ..Vocabulary::default() };
    let vocabulary = vocab.preset_permissions("missing").expect_err("no such preset");
    assert_eq!(kinds(&vocabulary), [false, false, true, false, false, false], "{vocabulary}");

    let surface = ResourceAccessSurface { conditional: true, ..ResourceAccessSurface::default() };
    let access = surface.require_unconditional("doc").expect_err("a conditional surface");
    assert_eq!(kinds(&access), [false, false, false, true, false, false], "{access}");

    assert_eq!(kinds(&capability_gate_err("doc", "publish")), [false, false, false, false, true, false]);

    let input = projection::principal(&Value::Null).expect_err("null is not a principal");
    assert_eq!(kinds(&input), [false, false, false, false, false, true], "{input}");
}
