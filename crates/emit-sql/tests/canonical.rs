use demesne_emit_sql::{GenFn, Policy, RlsResult, Sql};
use demesne_model::analysis::{CostClass, cost_class};
use demesne_syntax::Spec;

fn canonical(name: &str) -> Spec {
    let path = format!("{}/../../examples/canonical/{name}.demesne", env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{name}: {e}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{name}: {e}"));
    s
}

fn policy<'a>(res: &'a RlsResult, name: &str) -> &'a Policy {
    res.policies.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no {name} policy (unsupported: {:?})", res.unsupported))
}

fn definer<'a>(defs: &'a [GenFn], name: &str) -> &'a GenFn {
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} definer: {:?}", defs.iter().map(|d| &d.name).collect::<Vec<_>>()))
}

#[test]
fn rbac_gates_reads_on_any_role_and_writes_on_the_permission() {
    let s = canonical("rbac");
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the rbac example emits");
    let sub = sql.claim("sub");
    let sel = policy(&res, "resources_select");
    assert!(sel.using.contains(&format!("auth.staff_has_resource_role({sub}, tenant_id, project_id)")), "{}", sel.using);
    let upd = policy(&res, "resources_update");
    assert!(upd.using.contains(&format!("auth.staff_has_perm({sub}, tenant_id, project_id, 'resource:write')")), "{}", upd.using);
    assert!(!upd.using.contains("staff_has_resource_role"), "{}", upd.using);
    for p in [sel, upd] {
        assert!(
            p.using.contains("tenant_id = (current_setting") && p.using.contains("project_id = (current_setting"),
            "{} dropped tenancy:\n{}",
            p.name,
            p.using
        );
    }
    let defs = sql.emit_definers().expect("the rbac example's definers emit");
    let any_role = definer(&defs, "staff_has_resource_role").create_sql();
    for frag in [
        "SECURITY DEFINER",
        "FROM role_grants ra JOIN roles r ON r.id = ra.role_id",
        "ra.grantee_kind = 'staff'",
        "ra.grantee_id = user_id",
        "ra.revoked_at IS NULL",
        "r.key IN ('editor', 'viewer')",
    ] {
        assert!(any_role.contains(frag), "staff_has_resource_role lacks {frag:?}:\n{any_role}");
    }
    let perm = definer(&defs, "staff_has_perm").create_sql();
    assert!(perm.contains("p_perm = ANY(r.permissions)") && !perm.contains("r.key IN"), "{perm}");
}

#[test]
fn boolean_intersects_and_excludes_without_widening() {
    let s = canonical("boolean");
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the boolean example emits");
    let sel = policy(&res, "resources_select");
    let pred = format!("{}{}", sel.using, sel.check);
    let uid = sql.claim("uid");
    let (viewer, member, banned) = (format!("viewer_id = {uid}"), format!("member_id = {uid}"), format!("(banned_id = {uid}) IS NOT TRUE"));
    assert!(pred.contains(&format!("({viewer}) AND ({member}) AND ({banned})")), "{pred}");
    assert!(!pred.contains(&format!("OR banned_id = {uid}")), "{pred}");
}

#[test]
fn groups_reach_through_the_transitive_closure_inside_tenancy() {
    let s = canonical("groups");
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the groups example emits");
    let doc = policy(&res, "docs_select");
    let member = sql.claim("member_id");
    assert!(doc.using.contains(&format!("auth.group_closure_member(audience_group, {member})")), "{}", doc.using);
    assert!(doc.using.contains(&format!("owner_id = {member} OR ")), "{}", doc.using);
    assert!(doc.using.contains(&format!("tenant_id = {} AND workspace_id = {}", sql.claim("tenant_id"), sql.claim("workspace_id"))), "{}", doc.using);
    let defs = sql.emit_definers().expect("the groups example's definers emit");
    let closure = definer(&defs, "group_closure_member");
    assert!(closure.body.contains("EXISTS (SELECT 1 FROM group_closure WHERE grp = p_group AND mem = p_member)"), "{}", closure.body);
    let triggers = sql.triggers_sql();
    for frag in [
        "WITH RECURSIVE tc AS (",
        "SELECT group_id AS grp, member_id AS mem FROM group_memberships",
        "SELECT tc.grp, e.member_id FROM tc JOIN group_memberships e ON e.group_id = tc.mem",
        "INSERT INTO group_closure (grp, mem)",
    ] {
        assert!(triggers.contains(frag), "the closure rebuild lacks {frag:?}:\n{triggers}");
    }
}

#[test]
fn inheritance_reaches_documents_through_unbounded_folder_ancestry() {
    let s = canonical("inheritance");
    let rel = s.objects[0].relations.iter().find(|r| r.name == "in_folder").expect("an in_folder relation");
    assert_eq!(cost_class(rel), CostClass::Closure);
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the inheritance example emits");
    let sel = policy(&res, "documents_select");
    assert!(sel.using.contains(&format!("auth.folder_closure_reachable({}, folder_id)", sql.claim("viewer_folder"))), "{}", sel.using);
    for key in ["org_id", "workspace_id"] {
        assert!(sel.using.contains(&format!("{key} = {}", sql.claim(key))), "{key}:\n{}", sel.using);
    }
    let defs = sql.emit_definers().expect("the inheritance example's definers emit");
    let reach = definer(&defs, "folder_closure_reachable");
    assert_eq!(reach.body, "EXISTS (SELECT 1 FROM folder_closure WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant)");
    assert!(reach.create_sql().contains("SECURITY DEFINER"), "{}", reach.create_sql());
    let triggers = sql.emit_triggers();
    assert_eq!(triggers.iter().map(|t| (t.closure.as_str(), t.base.as_str())).collect::<Vec<_>>(), [("folder_closure", "folders")]);
    let maintain = triggers[0].function_sql();
    for frag in ["VALUES (NEW.id, NEW.id)", "WHERE c.descendant_id = NEW.parent_id", "NEW.parent_id IS DISTINCT FROM OLD.parent_id"] {
        assert!(maintain.contains(frag), "closure maintenance lacks {frag:?}:\n{maintain}");
    }
}
