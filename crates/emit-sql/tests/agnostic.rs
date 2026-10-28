use demesne_emit_sql::{RlsResult, Sql};
use demesne_model::{Nullability, Schema, SpecExt, SurfaceExt, validate_against};

fn agnostic() -> demesne_syntax::Spec {
    let src = std::fs::read_to_string(format!("{}/../../examples/agnostic.demesne", env!("CARGO_MANIFEST_DIR"))).expect("the agnostic example reads");
    demesne_syntax::parse(&src).expect("the agnostic example parses")
}

fn using<'a>(res: &'a RlsResult, policy: &str) -> &'a str {
    &res.policies.iter().find(|p| p.name == policy).unwrap_or_else(|| panic!("no policy {policy}: {res:#?}")).using
}

#[test]
fn custom_scope_columns_and_claims_replace_the_conventional_ones() {
    let s = agnostic();
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the agnostic example emits");
    let asset = using(&res, "assets_select");
    let wanted = [
        format!("tenant_ref = {}", sql.claim("tnt")),
        format!("space_ref = {}", sql.claim("spc")),
        format!("holder_ref = {}", sql.claim("member_ref")),
        format!("{} IS NULL", sql.claim("spc")),
    ];
    for frag in wanted {
        assert!(asset.contains(&frag), "assets_select lacks {frag:?}:\n{asset}");
    }
    for conventional in ["tenant_id", "space_id", "tenant_ref"] {
        assert!(!asset.contains(&sql.claim(conventional)), "assets_select reads the claim {conventional:?}:\n{asset}");
    }
    let space = using(&res, "spaces_select");
    for frag in [format!("space_pk = {}", sql.claim("spc")), format!("tenant_ref = {}", sql.claim("tnt")), "tenant_ref, space_pk)".to_string()] {
        assert!(space.contains(&frag), "spaces_select lacks {frag:?}:\n{space}");
    }
    let contract = s.claims_contract().expect("the claims contract builds");
    for key in ["tnt", "spc", "sub", "member_ref"] {
        assert!(contract.iter().any(|c| c == key), "the claims contract lacks {key:?}: {contract:?}");
    }
    for key in ["tenant_id", "space_id", "tenant_ref", "space_ref", "platform_id"] {
        assert!(!contract.iter().any(|c| c == key), "the claims contract names {key:?}: {contract:?}");
    }
}

#[test]
fn a_declared_primary_key_replaces_id_everywhere() {
    let s = agnostic();
    let sql = Sql::new(&s);
    assert_eq!(s.point_check_sql("asset").expect("asset has a single-column key"), "SELECT EXISTS (SELECT 1 FROM assets WHERE asset_pk = $1)");
    let res = sql.emit_rls().expect("the agnostic example emits");
    let asset = using(&res, "assets_select");
    assert!(asset.contains("assets.asset_pk, 'read')"), "the grant branch doesn't read assets.asset_pk:\n{asset}");
    let definers = sql.emit_definers().expect("the agnostic example's definers emit");
    let kernel = definers.iter().find(|d| d.name == "member_can_access_asset").unwrap_or_else(|| panic!("no member_can_access_asset: {definers:#?}"));
    assert!(kernel.body.contains("r.asset_pk = p_asset_id"), "the kernel gate doesn't match on asset_pk:\n{}", kernel.body);
    assert!(!kernel.body.contains("r.id = "), "the kernel gate assumes an id key:\n{}", kernel.body);
    let surface = s.conditional_resource_access_surface("asset").expect("asset has an access surface");
    assert!(surface.mode_sql().ends_with("WHERE asset_pk = $1"), "{}", surface.mode_sql());
    assert!(surface.set_visibility_sql().ends_with("WHERE asset_pk = $2"), "{}", surface.set_visibility_sql());
    assert_eq!(surface.scope_cols.as_ref(), ["tenant_ref", "space_ref"]);
}

fn custom_named(depth: usize, virtual_root: bool) -> String {
    let levels: Vec<String> = (0..depth)
        .map(|i| match (i, virtual_root) {
            (0, true) => "  level l0 virtual".to_string(),
            (0, false) => "  level l0 col l0_fk claim l0_k".to_string(),
            _ => format!("  level l{i} parent l{} col l{i}_fk claim l{i}_k", i - 1),
        })
        .collect();
    let subjects: Vec<String> = (0..depth)
        .flat_map(|i| ["self", "descendants"].map(|reach| format!("subject s{i}_{reach} {{ anchor l{i}; reach {reach}; identifies sub; roles none }}")))
        .collect();
    let scoped: Vec<String> = (usize::from(virtual_root)..depth).map(|i| format!("l{i}")).collect();
    format!(
        "topology {{\n{}\n}}\n{}\nobject row {{\n  table  rows\n  pk     row_pk\n  scoped {}\n  permission view = @scoped @rls maps select\n}}\n",
        levels.join("\n"),
        subjects.join("\n"),
        scoped.join(" > ")
    )
}

#[test]
fn every_custom_named_level_pins_its_own_claim_and_column() {
    for (depth, virtual_root) in (2..=4).flat_map(|depth| [(depth, false), (depth, true)]) {
        let src = custom_named(depth, virtual_root);
        let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}:\n{src}"));
        for sub in &s.subjects {
            let (cols, virtual_anchor) = s.pinned_columns(sub).unwrap_or_else(|e| panic!("{e}:\n{src}"));
            let anchor_claim = (!virtual_anchor).then(|| format!("{}_k", sub.anchor()));
            assert_eq!(cols.last().cloned(), anchor_claim, "{} pins {cols:?}:\n{src}", sub.name);
        }
        let sql = Sql::new(&s);
        let res = sql.emit_rls().unwrap_or_else(|e| panic!("{e}:\n{src}"));
        let rows = using(&res, "rows_select");
        for i in usize::from(virtual_root)..depth {
            let want = format!("l{i}_fk = {}", sql.claim(&format!("l{i}_k")));
            assert!(rows.contains(&want), "rows_select lacks {want:?}:\n{rows}\n{src}");
        }
    }
}

fn agnostic_schema(without: &str) -> Schema {
    let mut sc = Schema::new();
    let tables: [(&str, &[&str], &[&str]); 6] = [
        ("assets", &["asset_pk", "tenant_ref", "space_ref", "holder_ref", "share"], &["share"]),
        ("spaces", &["space_pk", "tenant_ref"], &[]),
        ("crew_grants", &["member_kind", "member_ref", "role_ref", "killed_at", "tenant_ref", "space_ref"], &["killed_at"]),
        ("crew_roles", &["row_id", "slug"], &[]),
        ("asset_acl", &["asset_ref", "grantee_kind", "grantee_ref", "perm"], &[]),
        ("ops_users", &["user_ref", "state"], &[]),
    ];
    for (table, cols, nullable) in tables {
        for col in cols.iter().filter(|c| **c != without) {
            sc.add_column(table, col, "text", if nullable.contains(col) { Nullability::Nullable } else { Nullability::NotNull });
        }
    }
    sc.add_column("ops_users", "is_ops", "boolean", Nullability::NotNull);
    sc
}

#[test]
fn the_spec_binds_to_a_schema_with_its_own_column_names() {
    let s = agnostic();
    assert_eq!(validate_against(&s, &agnostic_schema("")).map_err(|e| e.to_string()), Ok(()));
    let err = validate_against(&s, &agnostic_schema("asset_pk")).expect_err("a schema without asset_pk doesn't bind").to_string();
    assert!(err.contains(r#"no column "asset_pk""#), "{err}");
}

#[test]
fn an_undeclared_column_claim_and_key_default_to_the_conventional_names() {
    let src = "topology { level tenant level project parent tenant }
subject admin { anchor tenant reach descendants identifies sub roles none }
object doc { table docs scoped tenant > project
  relation t: tenant via tenant_id
  permission view = @scoped @rls maps select }";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    let sql = Sql::new(&s);
    let docs = sql.emit_rls().expect("the spec emits");
    let docs = using(&docs, "docs_select");
    assert!(docs.contains(&format!("project_id = {}", sql.claim("project_id"))), "{docs}");
    assert_eq!(s.point_check_sql("doc").expect("doc has a single-column key"), "SELECT EXISTS (SELECT 1 FROM docs WHERE id = $1)");
}
