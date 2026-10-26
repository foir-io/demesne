use demesne_gocompat::json;
use demesne_runtime::projection::{holds_resolver, levels, pdp, principal, role_assignments, subjects, vocabulary};
use demesne_runtime::{HoldsResolver, LevelClaim, RoleAssignment, SubjectIdentity, owned, owned_list, resolve_roles, scope_all_empty};

fn value(src: &str) -> json::Value {
    json::parse(src).expect("the test JSON parses")
}

#[test]
fn projections_read_each_field_of_their_json() {
    let claims = value(
        r#"{"subjects": [{"name": "member", "identifies": "member_id"}, {"name": "svc", "identifies": ""}],
            "levels": [{"name": "platform", "claimKey": "", "virtual": true}, {"name": "tenant", "claimKey": "tenant_id", "virtual": false}]}"#,
    );
    assert_eq!(
        subjects(&claims).expect("the subjects decode"),
        [SubjectIdentity { name: owned("member"), identifies: owned("member_id") }, SubjectIdentity { name: owned("svc"), identifies: owned("") }]
    );
    assert_eq!(
        levels(&claims).expect("the levels decode"),
        [
            LevelClaim { name: owned("platform"), claim_key: owned(""), is_virtual: true },
            LevelClaim { name: owned("tenant"), claim_key: owned("tenant_id"), is_virtual: false }
        ]
    );
    let p = principal(&value(r#"{"subject": "member", "id": "m1", "scopes": {"tenant": "t1"}}"#)).expect("the principal decodes");
    assert_eq!((p.subject.as_str(), p.id.as_str()), ("member", "m1"));
    assert_eq!(p.scopes, [("tenant".to_string(), "t1".to_string())].into_iter().collect());
    let d = pdp(&value(r#"{"emitSite": "staff", "policy": {"b.v1.S/B": "x:write", "a.v1.S/A": "x:read"}, "ungoverned": {"c.v1.S/C": "health"}}"#))
        .expect("the PDP decodes");
    assert_eq!(d.emit_site, "staff");
    assert_eq!(d.policy.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect::<Vec<_>>(), [("a.v1.S/A", "x:read"), ("b.v1.S/B", "x:write")]);
    assert_eq!(d.ungoverned.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect::<Vec<_>>(), [("c.v1.S/C", "health")]);
    assert_eq!(
        role_assignments(&value(r#"[{"scope": ["t1", ""], "roleKey": "viewer", "permissions": ["x:read"]}]"#)).expect("the assignments decode"),
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
            "presets": [{"name": "owner", "star": false, "set": ["editor", "docs:delete"]}, {"name": "editor", "star": false, "set": ["docs:read", "docs:write"]}, {"name": "broken", "star": false, "set": ["docs:share"]}],
            "rank": ["owner", "editor", "viewer"]}"#,
    ))
    .expect("the vocabulary decodes");
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

type Decode = fn(&json::Value) -> Result<(), demesne_runtime::Error>;

#[test]
fn a_projection_with_a_field_missing_or_of_the_wrong_type_is_refused() {
    let cases: [(&str, Decode, &str); 7] = [
        (r#"{"levels": [{"name": "tenant", "claimKey": "tenant_id"}]}"#, |v| levels(v).map(drop), "claims.levels[0].virtual must be a boolean"),
        (
            r#"{"subject": "member", "id": "m1", "scopes": {"tenant": "t1", "ws": 7}}"#,
            |v| principal(v).map(drop),
            "principal.scopes must be an object of strings",
        ),
        (r#"{"subject": "member", "scopes": {}}"#, |v| principal(v).map(drop), "principal.id must be a string"),
        (r#"{"emitSite": "staff", "policy": {"a.v1.S/A": 1}, "ungoverned": {}}"#, |v| pdp(v).map(drop), "pdp.policy must be an object of strings"),
        (
            r#"[{"scope": ["t1", null], "roleKey": "viewer", "permissions": []}]"#,
            |v| role_assignments(v).map(drop),
            "assignments[0].scope must be an array of strings",
        ),
        (
            r#"{"name": "app", "permissions": [], "presets": [{"name": "owner", "set": []}], "rank": []}"#,
            |v| vocabulary(v).map(drop),
            "vocabulary.presets[0].star must be a boolean",
        ),
        ("null", |v| holds_resolver(v).map(drop), "holdsResolver must be an object"),
    ];
    for (src, decode, want) in cases {
        let err = decode(&value(src)).expect_err(src);
        assert!(err.is_input(), "{err}");
        assert_eq!(err.message(), want, "{src}");
    }
}

#[test]
fn an_optional_projection_field_may_be_absent_or_null() {
    let v = vocabulary(&value(r#"{"name": "app", "permissions": ["docs:read"], "implications": null, "presets": [{"name": "viewer", "star": false, "set": ["docs:read"]}], "rank": []}"#))
        .expect("a vocabulary without implications or preset levels decodes");
    assert_eq!((v.implications.len(), v.presets[0].level.as_ref()), (0, ""));
}

#[test]
fn a_resolver_reads_a_plane_depth_only_beside_its_plane() {
    let resolver = |plane: &str| {
        value(&format!(
            r#"{{"assignments": "role_grants", "kindCol": "", "kindVal": "", "subjectCol": "grantee_id", "scopeCols": ["tenant_id", "project_id"],
                "revokedCol": "", {plane} "roleCol": "role_id", "rolesTable": "roles", "rolesId": "id", "keyCol": "key", "permsCol": "perms",
                "vocab": {{"name": "app", "permissions": [], "presets": [], "rank": []}}}}"#
        ))
    };
    let flat = holds_resolver(&resolver("")).expect("a resolver without a plane decodes");
    assert_eq!(flat.plane_depth(), 2);
    let planed = holds_resolver(&resolver(r#""plane": "tenant", "planeDepth": 1,"#)).expect("a resolver with a plane decodes");
    assert_eq!(planed.plane_depth(), 1);
    let err = holds_resolver(&resolver(r#""plane": "tenant","#)).expect_err("a plane without its depth");
    assert_eq!(err.message(), "holdsResolver.planeDepth must be an integer");
}

#[test]
fn the_global_assignment_read_selects_root_level_rows_of_the_rolestores_kind() {
    let r = HoldsResolver {
        assignments: owned("role_grants"),
        kind_col: owned("grantee_kind"),
        kind_val: owned("o'staff"),
        subject_col: owned("grantee_id"),
        scope_cols: owned_list(["tenant_id", "project_id"]),
        revoked_col: owned("revoked_at"),
        role_col: owned("role_id"),
        roles_table: owned("roles"),
        roles_id: owned("id"),
        key_col: owned("key"),
        ..HoldsResolver::default()
    };
    assert_eq!(
        r.global_assignments_sql(),
        "SELECT ra.grantee_id, r.key, ra.tenant_id, ra.project_id FROM role_grants ra JOIN roles r ON r.id = ra.role_id WHERE ra.grantee_kind = 'o''staff' AND ra.revoked_at IS NULL AND ra.tenant_id IS NULL ORDER BY 1, 2"
    );
    let unkinded = HoldsResolver { kind_col: owned(""), revoked_col: owned(""), ..r.clone() };
    assert_eq!(
        unkinded.global_assignments_sql(),
        "SELECT ra.grantee_id, r.key, ra.tenant_id, ra.project_id FROM role_grants ra JOIN roles r ON r.id = ra.role_id WHERE ra.tenant_id IS NULL ORDER BY 1, 2"
    );
    assert_eq!(HoldsResolver { scope_cols: owned_list(Vec::<String>::new()), ..r }.global_assignments_sql(), "");
}

#[test]
fn a_claims_projection_names_its_own_setting_cast_and_role() {
    let s = demesne_runtime::projection::session(&value(r#"{"setting": "app.claims", "cast": "jsonb", "role": "app_user"}"#)).expect("the session decodes");
    assert_eq!((s.setting.as_ref(), s.cast.as_ref(), s.role.as_ref()), ("app.claims", "jsonb", "app_user"));
    assert_eq!(s.session_setup_sql(demesne_runtime::SettingLifetime::Transaction), ["SET LOCAL ROLE app_user", "SELECT set_config('app.claims', $1, true)"]);
}
