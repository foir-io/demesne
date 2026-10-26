use demesne_emit_sql::{validate, validate_warnings};
use std::path::Path;

const HEADER: &str = r"
topology {
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}

vocabulary app { permission self:read }

subject member {
  anchor workspace
  reach  self
  identifies member_ref
  roles  none
  binds  owner
}
";

fn note(body: &str) -> String {
    format!(
        "{HEADER}
object note {{
  table  notes
  pk     note_pk
  scoped org > workspace
  relation owner:   member via owner_ref
  relation grantee: member via grant note_acl(note_ref, grantee_kind, grantee_ref, perm)
{body}
}}
"
    )
}

fn check(src: &str) -> (Result<(), String>, Vec<String>) {
    let s = demesne_syntax::parse(src).expect("the test spec parses");
    (validate(&s).map_err(|e| e.to_string()), validate_warnings(&s).iter().map(ToString::to_string).collect())
}

fn errors(src: &str) -> Vec<String> {
    match check(src).0 {
        Ok(()) => Vec::new(),
        Err(e) => e.lines().map(str::to_string).collect(),
    }
}

#[test]
fn a_write_term_select_cannot_reach_is_refused() {
    let errs = errors(&note(
        "  permission view   = owner @rls maps select
  permission edit   = owner + grantee:write @rls maps update
  permission remove = owner + grantee:delete @rls maps delete",
    ));
    assert_eq!(errs.len(), 2, "{errs:#?}");
    assert!(errs[0].contains("permission note.edit maps update, and its term `grantee:write` admits callers the select permission note.view does not reach"));
    assert!(errs[0].contains("Postgres applies an UPDATE only to rows the SELECT policy shows"));
    assert!(errs[1].contains("permission note.remove maps delete, and its term `grantee:delete`"));
    assert!(errs[1].contains("Postgres applies a DELETE only"));
}

#[test]
fn a_write_select_reaches_validates_without_warnings() {
    let (res, warnings) = check(&note(
        "  permission view   = owner + grantee:read + grantee:write + grantee:delete @rls maps select
  permission edit   = owner + grantee:write @rls maps update
  permission remove = owner + grantee:delete @rls maps delete",
    ));
    assert_eq!(res, Ok(()));
    assert!(warnings.is_empty(), "{warnings:#?}");
}

#[test]
fn a_blind_write_is_a_warning_not_an_error() {
    let (res, warnings) = check(&note(
        "  permission view = owner @rls maps select
  permission edit = owner + grantee:write @rls maps update blind",
    ));
    assert_eq!(res, Ok(()));
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(warnings[0].contains("its term `grantee:write`"));
    assert!(warnings[0].contains("kept as a warning because the permission is marked `blind`"));
}

#[test]
fn only_a_write_can_be_blind() {
    let errs = errors(&note("  permission view = owner @rls maps select blind"));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission note.view is marked `blind` but does not map update or delete under @rls"));
}

#[test]
fn a_requirement_select_needs_is_reported_once_for_every_term_it_refuses() {
    let errs = errors(&note(
        "  permission view = owner + grantee:read @rls maps select
  permission edit = owner + grantee:read @rls maps update
  require view = @self(created_by)",
    ));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("its terms `owner`, `grantee:read` admit callers that note's `require view` refuses"));
    assert!(errs[0].contains("make `require edit` imply `require view`"));
}

#[test]
fn a_write_requirement_that_matches_the_select_requirement_validates() {
    let (res, _) = check(&note(
        "  permission view = owner + grantee:read @rls maps select
  permission edit = owner + grantee:read @rls maps update
  require view = @self(created_by)
  require edit = @self(created_by)",
    ));
    assert_eq!(res, Ok(()));
}

#[test]
fn a_requirement_that_is_also_a_write_term_is_not_mistaken_for_an_escape() {
    let (res, _) = check(&note(
        "  relation sender: member via created_by
  permission view = owner + sender @rls maps select
  permission edit = owner + sender @rls maps update
  require edit = @self(created_by)",
    ));
    assert_eq!(res, Ok(()));
}

#[test]
fn an_admit_arm_select_cannot_reach_is_refused() {
    let errs = errors(&note(
        r#"  permission view = owner @rls maps select
  permission edit = owner @rls maps update
  admit update = @claim("support", "on")"#,
    ));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains(r#"its admit arm `@claim("support", "on")`"#));
}

fn two_objects(parent_edit: &str) -> String {
    format!(
        "{HEADER}
object folder {{
  table  folders
  pk     folder_pk
  scoped org > workspace
  relation owner:   member via owner_ref
  relation grantee: member via grant folder_acl(folder_ref, grantee_kind, grantee_ref, perm)
  permission view = owner @rls maps select
  permission edit = {parent_edit} @rls maps update
}}

object doc {{
  table  docs
  pk     doc_pk
  scoped org > workspace
  relation in_folder:   folder via object folder->view on folder_ref
  relation edit_folder: folder via object folder->edit on folder_ref
  permission view = in_folder @rls maps select
  permission edit = edit_folder @rls maps update
}}
"
    )
}

#[test]
fn borrowing_a_write_verb_is_within_borrowing_the_select_verb() {
    let (res, _) = check(&two_objects("owner"));
    assert_eq!(res, Ok(()));
}

#[test]
fn a_wider_borrowed_verb_is_reported_on_its_own_object_only() {
    let errs = errors(&two_objects("owner + grantee:write"));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission folder.edit maps update, and its term `grantee:write`"));
}

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn manage(view: &str, implication: &str) -> String {
    let src = std::fs::read_to_string(root().join("examples/manage.demesne")).expect("the manage example exists");
    src.replace("  permission view = @holds(records:read) + @holds(records:write)  @rls maps select", &format!("  permission view = {view}  @rls maps select"))
        .replace("  permission records:write\n", &format!("  permission records:write{implication}\n"))
}

#[test]
fn a_held_permission_is_within_any_permission_the_vocabulary_says_it_implies() {
    let errs = errors(&manage("@holds(records:read)", ""));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("its term `@holds(records:write)`"));
    let (res, _) = check(&manage("@holds(records:read)", " implies records:read"));
    assert_eq!(res, Ok(()));
}

#[test]
fn every_example_validates_without_warnings() {
    let mut checked = 0;
    let mut dirs = vec![root().join("examples")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("the examples directory is readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "demesne") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("an example is readable");
            let (res, warnings) = check(&src);
            assert_eq!(res, Ok(()), "{}", path.display());
            assert!(warnings.is_empty(), "{}: {warnings:#?}", path.display());
            checked += 1;
        }
    }
    assert_eq!(checked, 12, "the example count changed; update the test if that was deliberate");
}

#[test]
fn a_select_exclusion_the_write_term_lacks_is_an_escape() {
    let errs = errors(&note(
        r#"  permission view = owner and not @row(state, "archived") @rls maps select
  permission edit = owner @rls maps update"#,
    ));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission note.edit maps update, and its term `owner`"));
    let (res, _) = check(&note(
        r#"  permission view = owner and not @row(state, "archived") @rls maps select
  permission edit = owner and not @row(state, "archived") @rls maps update"#,
    ));
    assert_eq!(res, Ok(()));
}

#[test]
fn a_composition_write_arm_is_within_its_read_arm() {
    let composed = |edit: &str| {
        note(&format!(
            "  relation part_of: note via composition note_links(child_ref, parent_ref)
  permission view = owner + part_of @rls maps select
  permission edit = {edit} @rls maps update"
        ))
    };
    let (res, _) = check(&composed("owner + part_of"));
    assert_eq!(res, Ok(()));
    let errs = errors(&composed("owner + grantee:write + part_of"));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("its term `grantee:write`"));
}

#[test]
fn a_blind_write_breaks_the_composition_arm_implication() {
    let (res, warnings) = check(&note(
        "  relation part_of: note via composition note_links(child_ref, parent_ref)
  permission view = owner + part_of @rls maps select
  permission edit = owner + grantee:write + part_of @rls maps update blind",
    ));
    assert_eq!(res, Ok(()));
    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(warnings.iter().any(|w| w.contains("its term `grantee:write`")));
    assert!(warnings.iter().any(|w| w.contains("its term `part_of`")));
}

fn impersonated(edit_suffix: &str) -> String {
    impersonation(&format!("permission edit = @session(admin) @rls maps update{edit_suffix}"))
}

fn impersonation(perms: &str) -> String {
    format!(
        r#"
topology {{
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}}

vocabulary admin {{
  permission content:read
  preset project_viewer @ project = content:read
}}

rolestore admin {{
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}}

grant impersonation at tenant
  via edge impersonation_grants(grantee_id, tenant_id)

subject operator {{ anchor platform; reach via grant impersonation; identifies sub; roles none }}
subject admin    {{ anchor tenant;   reach descendants; identifies sub; roles configurable admin; binds admin }}

object project {{
  table  projects
  level  project
  scoped tenant > project
  relation admin: admin via role
  {perms}
}}
"#
    )
}

#[test]
fn a_subjects_own_reach_past_select_is_refused() {
    let errs = errors(&impersonated(""));
    assert!(errs.iter().any(|e| e.contains("permission project.edit maps update, and a subject's own reach on this object admits callers")), "{errs:#?}");
}

#[test]
fn a_blind_write_keeps_its_subjects_own_reach_as_a_warning() {
    let (res, warnings) = check(&impersonated(" blind"));
    assert_eq!(res, Ok(()));
    assert!(warnings.iter().any(|w| w.contains("a subject's own reach on this object") && w.contains("kept as a warning")), "{warnings:#?}");
}

#[test]
fn a_literal_holding_a_parenthesis_is_one_term() {
    let lit = r#"@row(label, "a (b")"#;
    let (res, warnings) =
        check(&note(&format!("  permission view = grantee:read + owner and {lit} @rls maps select\n  permission edit = owner and {lit} @rls maps update")));
    assert_eq!(res, Ok(()));
    assert_eq!(warnings, [] as [String; 0]);
}

#[test]
fn a_write_term_that_is_a_subjects_own_reach_is_reported_once_as_that_reach() {
    let errs = errors(&impersonation("permission edit = via grant impersonation @rls maps update"));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission project.edit maps update, and a subject's own reach on this object admits callers"), "{errs:#?}");
}

#[test]
fn a_write_term_of_one_condition_past_select_is_refused() {
    let errs = errors(&impersonation("permission view = @session(admin) @rls maps select\n  permission edit = @self(actor_col) @rls maps update"));
    assert!(errs.iter().any(|e| e.contains("permission project.edit maps update, and its term `@self(actor_col)` admits callers")), "{errs:#?}");
}

#[test]
fn an_admit_arm_for_one_write_does_not_check_the_other() {
    let errs = errors(&impersonation("permission edit = @session(admin) @rls maps update\n  admit update = @session(admin)"));
    assert!(errs.iter().any(|e| e.contains("project.admit maps update, and its admit arm")), "{errs:#?}");
    assert!(!errs.iter().any(|e| e.contains("maps delete")), "{errs:#?}");
}
