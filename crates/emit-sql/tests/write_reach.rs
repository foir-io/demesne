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

fn supported(edit_suffix: &str) -> String {
    support(&format!("permission edit = @session(admin) @rls maps update{edit_suffix}"))
}

fn support(perms: &str) -> String {
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

grant support at tenant
  via edge support_grants(grantee_id, tenant_id)

subject operator {{ anchor platform; reach via grant support; identifies sub; roles none }}
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
    let errs = errors(&supported(""));
    assert!(errs.iter().any(|e| e.contains("permission project.edit maps update, and a subject's own reach on this object admits callers")), "{errs:#?}");
}

#[test]
fn a_blind_write_keeps_its_subjects_own_reach_as_a_warning() {
    let (res, warnings) = check(&supported(" blind"));
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
    let errs = errors(&support("permission edit = via grant support @rls maps update"));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission project.edit maps update, and a subject's own reach on this object admits callers"), "{errs:#?}");
}

#[test]
fn a_write_term_of_one_condition_past_select_is_refused() {
    let errs = errors(&support("permission view = @session(admin) @rls maps select\n  permission edit = @self(actor_col) @rls maps update"));
    assert!(errs.iter().any(|e| e.contains("permission project.edit maps update, and its term `@self(actor_col)` admits callers")), "{errs:#?}");
}

#[test]
fn an_admit_arm_for_one_write_does_not_check_the_other() {
    let errs = errors(&support("permission edit = @session(admin) @rls maps update\n  admit update = @session(admin)"));
    assert!(errs.iter().any(|e| e.contains("project.admit maps update, and its admit arm")), "{errs:#?}");
    assert!(!errs.iter().any(|e| e.contains("maps delete")), "{errs:#?}");
}

#[test]
fn an_admit_arm_for_delete_is_checked_against_select() {
    let errs = errors(&note(
        r#"  permission view   = owner @rls maps select
  permission remove = owner @rls maps delete
  admit delete = @claim("support", "on")"#,
    ));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains(r#"permission note.admit maps delete, and its admit arm `@claim("support", "on")`"#), "{errs:#?}");
}

#[test]
fn a_kernel_write_is_not_held_to_the_select_policy() {
    let (res, warnings) = check(&note(
        "  relation sender: member via created_by
  permission view = owner @rls maps select
  permission edit = owner + sender @kernel maps update",
    ));
    assert_eq!(res, Ok(()));
    assert!(warnings.is_empty(), "{warnings:#?}");
}

fn borrowing(folder_perm: &str, verb: &str) -> String {
    format!(
        "{HEADER}
object folder {{
  table  folders
  pk     folder_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner @rls maps select
  {folder_perm}
}}

object doc {{
  table  docs
  pk     doc_pk
  scoped org > workspace
  relation in_folder: folder via object folder->view on folder_ref
  relation borrowed:  folder via object folder->{verb} on folder_ref
  permission view = in_folder @rls maps select
  permission edit = borrowed @rls maps update
}}
"
    )
}

#[test]
fn only_a_seeing_write_verb_is_within_borrowing_the_select_verb() {
    assert_eq!(check(&borrowing("permission edit = owner @rls maps update", "edit")).0, Ok(()));
    for (folder_perm, verb) in [("permission create = owner @rls maps insert", "create"), ("permission edit = owner @rls maps update blind", "edit")] {
        let errs = errors(&borrowing(folder_perm, verb));
        assert_eq!(errs.len(), 1, "{folder_perm}: {errs:#?}");
        assert!(errs[0].contains("permission doc.edit maps update, and its term `borrowed`"), "{folder_perm}: {errs:#?}");
    }
}

fn alternatives(pairs: usize) -> String {
    (0..pairs).map(|i| format!(r#"((owner and @row(s{i}, "a")) + (owner and @row(s{i}, "b")))"#)).collect::<Vec<_>>().join(" and ")
}

const PAST_LIMIT: &str = "expands past 512 conjunctions, too many to check that the SELECT policy shows every row it lets a caller update";

#[test]
fn a_write_at_the_conjunction_limit_is_checked_and_one_past_it_is_refused() {
    let edit = |pairs, blind| {
        note(&format!("  permission view = owner @rls maps select\n  permission edit = owner and {} @rls maps update{blind}", alternatives(pairs)))
    };
    assert_eq!(check(&edit(9, "")), (Ok(()), Vec::new()));
    let errs = errors(&edit(10, ""));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(
        errs[0].contains(&format!(
            "permission note.edit maps update, but its predicate {PAST_LIMIT}: write its predicate with fewer alternatives, or mark the permission `blind`"
        )),
        "{errs:#?}"
    );
    let (res, warnings) = check(&edit(10, " blind"));
    assert_eq!(res, Ok(()));
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(warnings[0].contains(&format!("its predicate {PAST_LIMIT}: kept as a warning because the permission is marked `blind`")), "{warnings:#?}");
}

#[test]
fn a_select_permission_or_requirement_past_the_limit_refuses_every_write_it_would_check() {
    let errs = errors(&note(&format!(
        "  permission view = owner and {} @rls maps select\n  permission edit = owner @rls maps update\n  admit update = owner",
        alternatives(10)
    )));
    assert_eq!(errs.len(), 2, "{errs:#?}");
    assert!(errs[0].contains(&format!("permission note.edit maps update, but the select permission note.view {PAST_LIMIT}")), "{errs:#?}");
    assert!(errs[1].contains(&format!("permission note.admit maps update, but the select permission note.view {PAST_LIMIT}")), "{errs:#?}");
    let (res, warnings) =
        check(&note(&format!("  permission view = owner and {} @rls maps select\n  permission edit = owner @rls maps update blind", alternatives(10))));
    assert_eq!(res, Ok(()));
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(warnings[0].contains("the select permission note.view expands past 512 conjunctions"), "{warnings:#?}");
    let errs = errors(&note(&format!(
        "  permission view = owner @rls maps select\n  permission edit = owner @rls maps update\n  require edit = {}",
        alternatives(10)
    )));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains(&format!("permission note.edit maps update, but `require edit` {PAST_LIMIT}")), "{errs:#?}");
}

#[test]
fn an_admit_arm_past_the_limit_is_refused() {
    let errs = errors(&note(&format!(
        "  permission view = owner @rls maps select\n  permission edit = owner @rls maps update\n  admit update = owner and {}",
        alternatives(10)
    )));
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].contains("permission note.admit maps update, but its admit arm `owner and "), "{errs:#?}");
    assert!(errs[0].contains(PAST_LIMIT), "{errs:#?}");
}

#[test]
fn a_subjects_own_reach_past_the_limit_with_its_requirement_is_refused() {
    let require = (0..9).map(|i| format!(r#"(@kind("a{i}") + @kind("b{i}"))"#)).collect::<Vec<_>>().join(" and ");
    let second = "subject auditor  { anchor platform; reach via grant support; identifies aud; roles none }\nsubject admin ";
    let errs = errors(&supported(&format!("\n  require edit = {require}")).replacen("subject admin ", second, 1));
    assert!(
        errs.iter().any(|e| e.contains(&format!("permission project.edit maps update, but a subject's own reach on this object {PAST_LIMIT}"))),
        "{errs:#?}"
    );
}
