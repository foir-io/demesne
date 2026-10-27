use demesne_emit_sql::{GenFn, Sql, validate};

fn d36() -> String {
    std::fs::read_to_string(format!("{}/../../testdata/gaps/d36-holds.demesne", env!("CARGO_MANIFEST_DIR"))).expect("the fixture reads")
}

fn swap(src: &str, pairs: &[(&str, &str)]) -> String {
    pairs.iter().fold(src.to_string(), |s, (from, to)| {
        assert!(s.contains(from), "the spec has no {from:?}");
        s.replacen(from, to, 1)
    })
}

fn definers(src: &str) -> Vec<GenFn> {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    validate(&s).expect("the spec validates");
    Sql::new(&s).emit_definers().expect("the definers compile")
}

fn accessor(src: &str, name: &str) -> String {
    let defs = definers(src);
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} among {:?}", defs.iter().map(|d| &d.name).collect::<Vec<_>>())).text()
}

fn holds_branch(src: &str, name: &str) -> String {
    let text = accessor(src, name);
    let start = text.find("SELECT 'holds'::text").unwrap_or_else(|| panic!("{name} lists no holds readers:\n{text}"));
    text[start..].split("UNION").next().unwrap_or_default().to_string()
}

const DOC_VIEW: &str = "permission view = owner + @holds(docs:read) + grantee:read @rls maps select";

#[test]
fn a_rolestore_plane_pins_every_level_below_it_null() {
    let branch = holds_branch(&swap(&d36(), &[("  permissions permissions\n", "  permissions permissions\n  plane       tenant\n")]), "docs_accessors");
    assert!(branch.contains("(ra.tenant_id IS NULL OR ra.tenant_id = e.tenant_id)"), "{branch}");
    assert!(branch.contains("ra.workspace_id IS NULL AND"), "{branch}");
    assert!(!branch.contains("ra.workspace_id = e."), "{branch}");
}

#[test]
fn a_level_the_object_is_not_scoped_at_is_pinned_null() {
    let src = format!(
        "{}\nobject memo {{\n  table  memos\n  scoped tenant\n  relation tenant: tenant via tenant_id\n  relation grantee: member via grant memo_acl(memo_id, principal_kind, principal_id, access)\n  permission view = @holds(docs:read) + grantee:read @rls maps select\n}}\n",
        d36()
    );
    let branch = holds_branch(&src, "memos_accessors");
    assert!(branch.contains("(ra.tenant_id IS NULL OR ra.tenant_id = e.tenant_id)"), "{branch}");
    assert!(branch.contains("ra.workspace_id IS NULL AND"), "{branch}");
    assert!(!branch.contains("ra.workspace_id = e."), "{branch}");
}

#[test]
fn a_vocabulary_with_implications_checks_held_permissions_through_them() {
    let plain = holds_branch(&d36(), "docs_accessors");
    assert!(plain.contains("'docs:read' = ANY(ro.permissions)"), "{plain}");
    let implied = holds_branch(&swap(&d36(), &[("  permission docs:write\n", "  permission docs:write implies docs:read\n")]), "docs_accessors");
    assert!(implied.contains("ro.permissions::text[] && auth.staff_perm_implied_by('docs:read')"), "{implied}");
}

#[test]
fn a_platform_role_lists_the_holders_of_its_own_levels_presets() {
    let src = swap(
        &d36(),
        &[
            ("  preset owner  @ tenant    = *\n", "  preset owner  @ tenant    = *\n  preset root   @ org       = *\n"),
            ("subject member {", "subject platform_staff { anchor org; reach descendants; identifies sub; roles configurable staff }\nsubject member {"),
            ("  relation editor:  staff via role\n", "  relation editor:  staff via role\n  relation ops:     platform_staff via role\n"),
            (DOC_VIEW, "permission view = owner + ops + grantee:read @rls maps select"),
        ],
    );
    let text = accessor(&src, "docs_accessors");
    assert!(text.contains("ra.tenant_id IS NULL AND ra.workspace_id IS NULL JOIN roles rr ON rr.id = ra.role_id AND rr.key IN ('root')"), "{text}");
}

#[test]
fn a_walk_from_a_role_relation_lists_none_of_the_roles_holders() {
    let src =
        swap(&d36(), &[(DOC_VIEW, "permission view = owner + editor->view @kernel maps select\n  permission list = owner + grantee:read @rls maps select")]);
    let text = accessor(&src, "docs_accessors");
    assert!(text.contains("SELECT 'owner'::text"), "{text}");
    assert!(!text.contains("'role'::text"), "{text}");
}

fn with_borrow(view: &str) -> String {
    swap(
        &d36(),
        &[
            (
                "  permission view = staffer + @session @rls maps select\n",
                "  relation guest:   member via grant ws_acl(workspace_id, principal_kind, principal_id, access)\n  permission view = staffer + guest:read @rls maps select\n  permission edit = staffer @rls maps update\n",
            ),
            ("on workspace_id\n", "on workspace_id\n  relation wsed:    workspace via object workspace->edit on workspace_id\n"),
            (DOC_VIEW, view),
        ],
    )
}

#[test]
fn a_borrowed_read_inside_a_conjunction_lists_the_borrowed_objects_readers() {
    let text = accessor(&with_borrow("permission view = ws and grantee:read @rls maps select"), "docs_accessors");
    assert!(text.contains("JOIN LATERAL auth.workspaces_accessors(t.workspace_id) a ON true"), "{text}");
    assert!(text.contains("WHERE (a.principal_kind, a.principal_id) IN (SELECT b.principal_kind, b.principal_id FROM"), "{text}");
}

#[test]
fn a_borrow_of_a_verb_other_than_select_cannot_be_listed() {
    let s = demesne_syntax::parse(&with_borrow("permission view = wsed and grantee:read @rls maps select")).expect("the spec parses");
    let err = validate(&s).expect_err("an edit borrow has no reverse").to_string();
    assert!(err.contains("relation \"wsed\" borrows workspace->edit, not soundly enumerable"), "{err}");
    assert!(err.contains("only a read borrow is reversible (\"edit\" is not \"workspace\"'s select verb)"), "{err}");
}

const TEAM_VIEW: &str = "permission view = grantee:read @rls maps select";

fn borrowed_arm() -> String {
    format!(
        "topology {{ level tenant }}
vocabulary v {{ permission team:read }}
subject member {{ anchor tenant reach self identifies member_id roles configurable v binds owner }}
object team {{
  table  teams
  scoped tenant
  relation grantee: member via grant team_acl(team_id, principal_kind, principal_id, access)
  {TEAM_VIEW}
  admit select = @kind(\"service\")
}}
object doc {{
  table  docs
  scoped tenant
  relation in_team: team via object team->view on team_id
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = in_team + grantee:read @rls maps select
}}
"
    )
}

#[test]
fn a_borrow_of_an_object_with_a_select_arm_lists_the_borrowed_permissions_readers() {
    let src = borrowed_arm();
    let names: Vec<String> = definers(&src).into_iter().map(|d| d.name).collect();
    assert!(!names.iter().any(|n| n == "teams_accessors"), "{names:?}");
    let docs = accessor(&src, "docs_accessors");
    assert!(docs.contains("JOIN LATERAL auth.teams_view_accessors(t.team_id) a ON true"), "{docs}");
    let readers = accessor(&src, "teams_view_accessors");
    assert!(readers.contains("FROM team_acl WHERE team_id = p_id"), "{readers}");
    assert!(!readers.contains("'admit'"), "{readers}");
    let listing = accessor(&src, "teams_accessors_conditional");
    assert!(listing.contains("FROM auth.teams_view_accessors(p_id) p"), "{listing}");
    assert!(listing.contains("SELECT 'admit'::text"), "{listing}");
}

#[test]
fn a_borrow_of_a_permission_that_lists_conditionally_is_refused() {
    let src = swap(&borrowed_arm(), &[(TEAM_VIEW, "permission view = grantee:read + @kind(\"auditor\") @rls maps select")]);
    let s = demesne_syntax::parse(&src).expect("the spec parses");
    let err = validate(&s).expect_err("a conditional permission has no plain reader listing to borrow").to_string();
    assert!(err.contains("relation \"in_team\" borrows team->view, not soundly enumerable (borrowed permission team.view admits readers"), "{err}");
    assert!(!err.contains("admit kind"), "{err}");
}

#[test]
fn a_materialized_group_lists_its_resources_only_when_an_owner_names_the_caller() {
    let src = "topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access)
  relation team:    customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = grantee:read + team @rls maps select
}
";
    let names = |src: &str| definers(src).into_iter().map(|d| d.name).filter(|n| n.starts_with("docs_team_flat")).collect::<Vec<_>>();
    assert_eq!(names(src), ["docs_team_flat_member", "docs_team_flat_resources"]);
    let unowned = swap(src, &[(" binds owner", ""), ("grantee:read + team @rls", "grantee:read @rls")]);
    assert_eq!(names(&unowned), ["docs_team_flat_member"]);
}

#[test]
fn a_session_on_a_role_relation_lists_that_roles_holders() {
    let role_rows = |view: &str| {
        let text = accessor(&swap(&d36(), &[(DOC_VIEW, view)]), "docs_accessors");
        let start = text.find("SELECT 'role'::text").unwrap_or_else(|| panic!("no role readers:\n{text}"));
        text[start..].to_string()
    };
    let session = role_rows("permission view = owner + @session(editor) + grantee:read @rls maps select");
    assert!(session.contains("rr.key IN ('viewer')"), "{session}");
    assert_eq!(session, role_rows("permission view = owner + editor + grantee:read @rls maps select"));
}
