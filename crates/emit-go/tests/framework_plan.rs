use demesne_emit_go::{Package, emit_framework_go};
use demesne_model::framework::{orphan_pdp_verbs, vocab_caps_tree};

const BASE: &str = r#"
topology {
  level tenant
}

vocabulary api {
  permission docs:read
  permission docs:publish
  preset viewer @ tenant = docs:read
  preset editor @ tenant = viewer + docs:publish
}

vocabulary loose {
  permission x:go
}

rolestore api {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id
  rolejoin    role_id roles id key
}

subject staff { anchor tenant; reach self; identifies sub; roles configurable api }

object doc {
  table  docs
  scoped tenant
  relation tenant: tenant via tenant_id
  permission view    = @session      @rls maps select
  permission publish = docs:publish  @pdp
}
"#;

const SECOND: &str = r"
vocabulary ops {
  permission site:manage
}

rolestore ops {
  assignments ops_grants
  subject     grantee_id
  scope       tenant_id
  rolejoin    role_id roles id key
}
";

fn spec(src: &str) -> demesne_syntax::Spec {
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("the spec parses: {e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("the spec validates: {e}\n{src}"));
    s
}

fn framework(src: &str) -> Result<String, String> {
    let s = spec(src);
    let go = emit_framework_go(&s, &Package::new("authz").expect("authz is a package name")).map_err(|e| e.to_string());
    let ts = demesne_emit_ts::emit_framework_ts(&s).map_err(|e| e.to_string());
    assert_eq!(go.is_ok(), ts.is_ok(), "the Go and TypeScript emitters agree on {src}: {go:?} {ts:?}");
    go
}

fn renamed(src: &str, object: &str) -> String {
    src.replace("object doc {", &format!("object {object} {{"))
}

#[test]
fn the_base_spec_emits() {
    let out = framework(BASE).expect("the base spec emits");
    assert!(out.contains("\tDoc DocAccess\n"), "{out}");
}

#[test]
fn an_object_named_after_a_framework_helper_is_refused() {
    for helper in
        ["check", "check_handler", "claims", "mint", "decision", "holds", "resolve_held", "caps", "cap_set", "role_tiers", "role_set", "assignments_sql"]
    {
        let err = framework(&renamed(BASE, helper)).expect_err(helper);
        assert!(err.contains("collides with a generated framework helper"), "{helper}: {err}");
    }
}

#[test]
fn a_rolestore_suffix_reserves_its_names_only_beside_another_rolestore() {
    framework(&renamed(BASE, "holds_ops")).expect("one rolestore takes no suffix");
    let two = format!("{BASE}{SECOND}");
    framework(&two).expect("two rolestores emit");
    for helper in ["holds_ops", "holds_api", "caps_ops", "role_tiers_api", "site_caps_ops"] {
        let err = framework(&renamed(&two, helper)).expect_err(helper);
        assert!(err.contains("collides with a generated framework helper"), "{helper}: {err}");
    }
}

#[test]
fn a_caps_domain_reserves_its_name() {
    let err = framework(&renamed(BASE, "docs_caps")).expect_err("DocsCaps is the docs domain's caps type");
    assert!(err.contains("collides with a generated framework helper"), "{err}");
}

#[test]
fn two_presets_exporting_to_one_role_tier_are_refused() {
    let src = BASE.replace(
        "  preset editor @ tenant = viewer + docs:publish\n",
        "  preset editor @ tenant = viewer + docs:publish\n  preset Viewer @ tenant = docs:read\n",
    );
    let err = framework(&src).expect_err("viewer and Viewer both export as Viewer");
    assert!(err.contains("collides on field Viewer"), "{err}");
}

#[test]
fn caps_group_permissions_by_domain_and_set_aside_the_parameterized() {
    let perms: Vec<String> = ["docs:read", "docs:write", "site:manage", "docs:read:*", "bare", "empty:"].map(String::from).into();
    let (domains, skipped) = vocab_caps_tree(&perms).expect("the permissions group");
    let shape: Vec<(&str, Vec<(&str, &str)>)> =
        domains.iter().map(|d| (d.exp.as_str(), d.fields.iter().map(|f| (f.exp.as_str(), f.perm.as_str())).collect())).collect();
    assert_eq!(shape, [("Docs", vec![("Read", "docs:read"), ("Write", "docs:write")]), ("Site", vec![("Manage", "site:manage")])]);
    assert_eq!(skipped, ["docs:read:*", "bare", "empty:"]);
    let clash: Vec<String> = ["docs:read_x", "docs:readX"].map(String::from).into();
    let err = vocab_caps_tree(&clash).expect_err("read_x and readX both export as ReadX");
    assert!(err.to_string().contains("collides on Docs.ReadX"), "{err}");
}

#[test]
fn a_capability_verb_no_rolestore_covers_is_named() {
    assert_eq!(orphan_pdp_verbs(&spec(BASE)), [] as [String; 0]);
    let src = BASE.replace("permission publish = docs:publish  @pdp", "permission publish = x:go  @pdp");
    assert_eq!(orphan_pdp_verbs(&spec(&src)), ["doc.publish (needs \"x:go\")"]);
    let out = framework(&src).expect("an orphan verb still emits");
    assert!(out.contains("//   - doc.publish (needs \"x:go\")\n"), "{out}");
}

#[test]
fn a_preset_two_vocabularies_share_is_one_role_tier() {
    let src = BASE
        .replace("topology {\n  level tenant\n}", "topology {\n  level platform virtual\n  level tenant   parent platform\n}")
        .replace("  preset viewer @ tenant = docs:read\n", "  preset viewer @ tenant = docs:read\n  preset root @ platform = docs:read\n")
        .replace("  permission x:go\n", "  permission x:go\n  preset root @ platform = x:go\n");
    let out = framework(&src).expect("a shared preset name is one tier");
    let set = &out[out.find("type RoleSet struct {").expect("a role set")..];
    let set = &set[..set.find("}\n").expect("the role set ends")];
    assert_eq!(set.matches("\tRoot ").count(), 1, "{set}");
}
