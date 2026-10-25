use demesne_runtime::{LevelClaim, Principal, SubjectIdentity, build_claims, owned};
use std::collections::BTreeMap;

fn subjects() -> Vec<SubjectIdentity> {
    vec![SubjectIdentity { name: owned("member"), identifies: owned("member_id") }, SubjectIdentity { name: owned("svc"), identifies: owned("") }]
}

fn levels() -> Vec<LevelClaim> {
    vec![
        LevelClaim { name: owned("platform"), claim_key: owned(""), is_virtual: true },
        LevelClaim { name: owned("tenant"), claim_key: owned("tenant_id"), is_virtual: false },
        LevelClaim { name: owned("workspace"), claim_key: owned("ws"), is_virtual: false },
    ]
}

fn principal(subject: &str, id: &str, scopes: &[(&str, &str)]) -> Principal {
    Principal { subject: subject.into(), id: id.into(), scopes: scopes.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect() }
}

#[test]
fn a_principal_becomes_its_identity_and_scope_claims() {
    let got = build_claims(&subjects(), &levels(), &principal("member", "m1", &[("workspace", "w1"), ("tenant", "t1")])).expect("claims");
    let want: BTreeMap<String, String> = [("member_id", "m1"), ("tenant_id", "t1"), ("ws", "w1")].into_iter().map(|(k, v)| (k.into(), v.into())).collect();
    assert_eq!(got, want);
    assert_eq!(build_claims(&subjects(), &levels(), &principal("svc", "", &[])), Ok(BTreeMap::new()));
}

#[test]
fn a_principal_the_claims_cannot_carry_is_refused_in_go_s_words() {
    let err = |p: Principal| build_claims(&subjects(), &levels(), &p).expect_err("refused").message().to_string();
    assert_eq!(err(principal("nobody", "x", &[])), r#"BuildClaims: no subject "nobody" in the spec"#);
    assert_eq!(err(principal("svc", "x", &[])), r#"BuildClaims: subject "svc" has no identity key (`identifies`) but an id was supplied"#);
    assert_eq!(err(principal("member", "m1", &[("galaxy", "g")])), r#"BuildClaims: subject "member" presents a scope for unknown level "galaxy""#);
    assert_eq!(err(principal("member", "m1", &[("platform", "p")])), r#"BuildClaims: level "platform" is virtual (no scope claim) — it cannot carry a scope id"#);
}
