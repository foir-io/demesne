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

const TWO_STORES: &str = r"topology {
  level platform virtual
  level tenant   parent platform
}

vocabulary app { permission docs:read }

rolestore one {
  assignments one_grants
  subject     grantee_id
  scope       tenant_id
  rolejoin    role_id roles id key
}

rolestore two {
  assignments two_grants
  subject     grantee_id
  scope       tenant_id
  rolejoin    role_id roles id key
}

subject admin { anchor tenant; reach descendants; identifies sub; roles configurable app; binds admin }
";

#[test]
fn a_vocabulary_backing_two_rolestores_names_neither() {
    let s = demesne_syntax::parse(TWO_STORES).expect("the spec parses");
    let err = s.holds_role_store("docs:read").map(|rs| rs.name.clone()).expect_err("app backs both rolestores");
    assert_eq!(err.to_string(), r#"permission "docs:read" belongs to vocabulary "app", which backs more than one rolestore (one, two)"#);
}

#[test]
fn reach_grants_name_each_edge_its_grantee_and_its_granularity() {
    let src = r"topology {
  level platform virtual
  level tenant   parent platform
}
grant support at tenant via edge support_grants(helper_id, tenant_id)
subject helper { anchor platform; reach via grant support; identifies sub; roles none }
subject member { anchor tenant; reach descendants; identifies sub; roles none; binds owner }
object doc {
  table  docs
  scoped tenant
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = grantee:read @rls maps select
}
";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    let got: Vec<(String, String, &str)> =
        s.reach_grants().iter().map(|g| (g.edge_table().to_string(), g.grantee_column().to_string(), g.granularity())).collect();
    assert_eq!(got, [("support_grants".into(), "helper_id".into(), "level"), ("doc_acl".into(), "principal_id".into(), "row")]);
}

#[test]
fn a_grant_no_subject_reaches_is_enumerated_unless_another_reach_selects_it() {
    let src = r"topology { level control virtual level estate parent control level space parent estate level folder parent space }

grant descendants at folder via edge paths(ancestor_id, descendant_id) confers select
grant ancestors at folder via edge paths(descendant_id, ancestor_id) named paths_up confers select
grant spare at folder via edge spares(holder_id, folder_id)

subject viewer { anchor folder; reach via grant descendants; identifies folder_id; roles none }

object asset {
  table assets
  scoped estate > space > folder wildcard confers select
  permission view = @scoped @rls maps select
}

object blueprint {
  table blueprints
  scoped estate > space > folder wildcard confers select
  reach descendants via ancestors for select
  permission view = @scoped @rls maps select
}
";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    let enumerated = |object: &str, grant: &str| {
        let o = s.objects.iter().find(|o| o.name == object).expect("the object exists");
        let g = s.grants.iter().find(|g| g.name == grant).expect("the grant exists");
        s.enumerated_grant(o, g).map(|g| g.name.clone())
    };
    assert_eq!(enumerated("asset", "spare"), Some("spare".into()));
    assert_eq!(enumerated("asset", "ancestors"), None);
    assert_eq!(enumerated("blueprint", "descendants"), Some("ancestors".into()));
}
