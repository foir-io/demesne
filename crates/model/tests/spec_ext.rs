use demesne_model::{Principal, SpecExt, SurfaceExt};
use std::collections::BTreeMap;

fn spec(path: &str) -> demesne_syntax::Spec {
    let src = std::fs::read_to_string(format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))).expect("the spec reads");
    demesne_syntax::parse(&src).expect("the spec parses")
}

#[test]
fn a_principal_becomes_claims_and_a_minted_token_payload() {
    let s = spec("examples/example.demesne");
    let staff =
        Principal { subject: "staff".into(), id: "u1".into(), scopes: BTreeMap::from([("tenant".into(), "t1".into()), ("workspace".into(), "w1".into())]) };
    insta::assert_debug_snapshot!("claims_for_staff", s.build_claims(&staff));
    insta::assert_snapshot!("minted_for_staff", s.mint_claims_for(&staff).expect("the claims mint"));
    let values = BTreeMap::from([("sub".to_string(), "u1".to_string()), ("tenant_id".to_string(), "t1".to_string())]);
    insta::assert_snapshot!("minted_values", s.mint_claims(&values).expect("the values mint"));
    let subject = s.subjects.iter().find(|x| x.name == "staff").expect("a staff subject");
    insta::assert_debug_snapshot!("free_columns_staff", s.free_columns(subject));
    let member = s.subjects.iter().find(|x| x.name == "member").expect("a member subject");
    assert_eq!(s.free_columns(member).expect("a self-reach subject has none"), [] as [String; 0]);
}

#[test]
fn a_held_permission_names_its_rolestore() {
    let none = spec("examples/reach.demesne").holds_role_store("docs:read").map(|rs| rs.name.clone()).expect_err("no rolestore");
    assert_eq!(none.to_string(), "the spec declares no rolestore");
    let one = spec("examples/example.demesne");
    assert_eq!(one.holds_role_store("anything:at_all").map(|rs| rs.name.clone()), Ok("staff".to_string()));
    let two = spec("examples/planes.demesne");
    assert_eq!(two.holds_role_store("platform:manage").map(|rs| rs.name.clone()), Ok("platform".to_string()));
    assert_eq!(two.holds_role_store("content:read").map(|rs| rs.name.clone()), Ok("admin".to_string()));
    let src = std::fs::read_to_string(format!("{}/../../examples/planes.demesne", env!("CARGO_MANIFEST_DIR"))).expect("the spec reads");
    let unbacked = demesne_syntax::parse(&format!("{src}\nvocabulary extra {{ permission extra:read }}\n")).expect("the spec parses");
    let err = unbacked.holds_role_store("extra:read").map(|rs| rs.name.clone()).expect_err("no rolestore uses extra");
    assert_eq!(err.to_string(), "permission \"extra:read\" belongs to vocabulary \"extra\", which backs no rolestore");
}

#[test]
fn a_point_check_needs_a_single_column_key() {
    let s = spec("examples/example.demesne");
    insta::assert_snapshot!("point_check_doc", s.point_check_sql("doc").expect("doc has a single-column key"));
    let composite = spec("testdata/corpus/fixtures/5ae0f8e8ad3d6aee.demesne");
    insta::assert_snapshot!("point_check_composite", composite.point_check_sql("acl").expect_err("acl's key has three columns").to_string());
}

#[test]
fn surfaces_list_presets_access_and_async_tokens() {
    let s = spec("examples/example.demesne");
    insta::assert_debug_snapshot!("expanded_presets_staff", s.expanded_presets("staff"));
    insta::assert_debug_snapshot!(
        "resource_access_doc",
        s.resource_access_surface("doc").map(|r| (r.table, r.accessor_fn, r.scope_cols)).map_err(|e| e.to_string())
    );
    insta::assert_debug_snapshot!("async_tokens", spec("testdata/corpus/fixtures/38555e21822ea082.demesne").async_surface_tokens());
}
