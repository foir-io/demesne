use demesne_gocompat::json;
use demesne_runtime::projection::{levels, pdp, principal, role_assignments, subjects, vocabulary};
use demesne_runtime::{LevelClaim, RoleAssignment, SubjectIdentity, owned, resolve_roles, scope_all_empty};

fn value(src: &str) -> json::Value {
    json::parse(src).expect("the test JSON parses")
}

#[test]
fn projections_read_each_field_of_their_json() {
    let claims = value(
        r#"{"subjects": [{"name": "member", "identifies": "member_id"}, {"name": "svc", "identifies": ""}],
            "levels": [{"name": "platform", "claimKey": "", "virtual": true}, {"name": "tenant", "claimKey": "tenant_id"}]}"#,
    );
    assert_eq!(
        subjects(&claims),
        [SubjectIdentity { name: owned("member"), identifies: owned("member_id") }, SubjectIdentity { name: owned("svc"), identifies: owned("") }]
    );
    assert_eq!(
        levels(&claims),
        [
            LevelClaim { name: owned("platform"), claim_key: owned(""), is_virtual: true },
            LevelClaim { name: owned("tenant"), claim_key: owned("tenant_id"), is_virtual: false }
        ]
    );
    let p = principal(&value(r#"{"subject": "member", "id": "m1", "scopes": {"tenant": "t1", "ws": 7}}"#));
    assert_eq!((p.subject.as_str(), p.id.as_str()), ("member", "m1"));
    assert_eq!(p.scopes, [("tenant".to_string(), "t1".to_string())].into_iter().collect());
    let d = pdp(&value(r#"{"emitSite": "staff", "policy": {"b.v1.S/B": "x:write", "a.v1.S/A": "x:read"}, "ungoverned": {"c.v1.S/C": "health"}}"#));
    assert_eq!(d.emit_site, "staff");
    assert_eq!(d.policy.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect::<Vec<_>>(), [("a.v1.S/A", "x:read"), ("b.v1.S/B", "x:write")]);
    assert_eq!(d.ungoverned.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect::<Vec<_>>(), [("c.v1.S/C", "health")]);
    assert_eq!(
        role_assignments(&value(r#"[{"scope": ["t1", ""], "roleKey": "viewer", "permissions": ["x:read"]}]"#)),
        [RoleAssignment { scope: vec!["t1".into(), String::new()], role_key: "viewer".into(), permissions: vec!["x:read".into()] }]
    );
}

#[test]
fn roles_come_only_from_assignments_that_contain_the_scope() {
    let a =
        |scope: &[&str], key: &str| RoleAssignment { scope: scope.iter().map(|s| (*s).to_string()).collect(), role_key: key.into(), permissions: Vec::new() };
    let assignments =
        [a(&["", ""], "staff"), a(&["t1", ""], "tenant_admin"), a(&["t2", ""], "other_tenant"), a(&["t1", "p9"], "other_project"), a(&["t1", "p1"], "")];
    let roles = resolve_roles(&assignments, &["t1".into(), "p1".into()]);
    assert_eq!(roles.roles(), ["staff", "tenant_admin"]);
    assert!(scope_all_empty(&[String::new(), String::new()]));
    assert!(!scope_all_empty(&[String::new(), "p1".into()]));
}

#[test]
fn a_vocabulary_ranks_and_caps_delegation_and_refuses_a_preset_naming_nothing() {
    let v = vocabulary(&value(
        r#"{"name": "app", "permissions": ["docs:read", "docs:write", "docs:delete"],
            "presets": [{"name": "owner", "set": ["editor", "docs:delete"]}, {"name": "editor", "set": ["docs:read", "docs:write"]}, {"name": "broken", "set": ["docs:share"]}],
            "rank": ["owner", "editor", "viewer"]}"#,
    ));
    assert_eq!(v.presets_at_or_above("editor"), ["owner", "editor"]);
    assert_eq!(v.presets_at_or_above("nobody"), [] as [String; 0]);
    assert_eq!(v.preset_permissions("owner").expect("owner expands"), ["docs:delete", "docs:read", "docs:write"]);
    let err = v.preset_permissions("broken").expect_err("docs:share is not in the vocabulary");
    assert!(err.is_vocabulary(), "{err}");
    assert_eq!(err.message(), r#"vocabulary "app": preset "broken" references "docs:share", which is neither a permission nor a preset in this vocabulary"#);
    let held = ["docs:read".to_string(), "docs:write".to_string()];
    let ok = v.cap_grant(&held, &["docs:read".into()]);
    assert!(ok.allowed && ok.unknown.is_empty() && ok.excess.is_empty(), "{ok:?}");
    let capped = v.cap_grant(&held, &["docs:share".into(), "docs:delete".into(), "docs:delete".into(), "docs:read".into(), "docs:admin".into()]);
    assert!(!capped.allowed, "{capped:?}");
    assert_eq!(capped.unknown, ["docs:admin", "docs:share"]);
    assert_eq!(capped.excess, ["docs:delete"]);
}
