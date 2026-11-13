use demesne_emit_sql::Sql;
use demesne_syntax::{Repr, Spec};

const HEAD: &str = "topology { level estate level space parent estate level folder parent space }\nsubject member { anchor space; reach self; identifies sub; roles none }\nobject space {\n  table spaces\n  level space\n  scoped estate > space\n  permission view = @scoped and @row(status, \"open\") @rls maps select\n}\n";

fn page(more: &str, scoped: &str, on: &str, rules: &str) -> String {
    format!("{HEAD}{more}object page {{\n  table pages\n  scoped {scoped}\n  relation open_space: member via object space->view on {on}\n{rules}\n}}\n")
}

const VIEW: &str = "  permission view = @scoped and open_space @rls maps select";

fn compile(src: &str) -> Result<Spec, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

fn select_policy(src: &str) -> String {
    let s = compile(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let res = Sql::new(&s).emit_rls().expect("the policies compile");
    res.policies.iter().find(|p| p.name == "pages_select").expect("a select policy").using.clone()
}

#[test]
fn the_marker_parses_after_the_column_and_after_a_borrowed_operation() {
    let pinned = |on: &str| -> (bool, Option<String>) {
        let s = demesne_syntax::parse(&page("", "estate > space", on, VIEW)).unwrap_or_else(|e| panic!("{on:?}: {e}"));
        let page = s.objects.iter().find(|o| o.name == "page").expect("the page object");
        match &page.relations[0].repr {
            Repr::Object(vo) => (vo.pinned, vo.op.clone()),
            other => panic!("not a borrow: {other:?}"),
        }
    };
    assert_eq!(pinned("space_id"), (false, None));
    assert_eq!(pinned("space_id pinned"), (true, None));
    assert_eq!(pinned("space_id for select pinned"), (true, Some("select".into())));
    assert!(demesne_syntax::parse(&page("", "estate > space", "space_id pinned for select", VIEW)).is_err(), "`for` comes before `pinned`");
}

#[test]
fn a_pinned_borrow_is_asked_once_at_the_claim_and_an_unpinned_one_at_each_row() {
    let s = compile(&page("", "estate > space", "space_id", VIEW)).expect("compiles");
    let claim = Sql::new(&s).claim("space_id");
    let contained = format!("space_id = {claim} AND ");
    let per_row = select_policy(&page("", "estate > space", "space_id", VIEW));
    assert!(per_row.contains(&contained) && per_row.ends_with("AND ((auth.space_can_view(space_id))))"), "{per_row}");
    let once = select_policy(&page("", "estate > space", "space_id pinned", VIEW));
    assert!(once.contains(&contained) && once.ends_with(&format!("AND (((SELECT auth.space_can_view({claim})))))")), "{once}");
    assert_eq!(
        once.replace(&format!("(SELECT auth.space_can_view({claim}))"), "auth.space_can_view(space_id)"),
        per_row,
        "the marker changes the borrow's call and nothing else"
    );
}

#[test]
fn a_pinned_borrow_reads_the_claim_of_its_own_level_not_the_objects_deepest() {
    let deep = select_policy(&page("", "estate > space > folder", "space_id pinned", VIEW));
    let s = compile(&page("", "estate > space", "space_id", VIEW)).expect("compiles");
    let sql = Sql::new(&s);
    assert!(deep.contains(&format!("(SELECT auth.space_can_view({}))", sql.claim("space_id"))), "{deep}");
    assert!(!deep.contains(&format!("auth.space_can_view({})", sql.claim("folder_id"))), "{deep}");
}

#[test]
fn a_pinned_borrow_keeps_its_place_in_an_admit_arm_and_a_point_check() {
    let src = page("", "estate > space", "space_id pinned", &format!("{VIEW}\n  admit select = @kind(\"robot\") and open_space"));
    let s = compile(&src).expect("compiles");
    let sql = Sql::new(&s);
    let call = format!("(SELECT auth.space_can_view({}))", sql.claim("space_id"));
    let res = sql.emit_rls().expect("the policies compile");
    let using = &res.policies.iter().find(|p| p.name == "pages_select").expect("a select policy").using;
    assert_eq!(using.matches(&call).count(), 2, "once in the permission, once in the arm:\n{using}");
    assert!(!using.contains("space_can_view(space_id)"), "{using}");
    let defs = sql.emit_definers().expect("the definers compile");
    assert_eq!(defs.iter().filter(|d| d.name == "space_can_view").count(), 1, "the borrowed function is the one an unpinned borrow calls");
}

#[test]
fn a_borrow_is_pinned_only_where_containment_holds_its_column_to_the_claim() {
    let reach = "grant descendants at folder via edge paths(ancestor_id, descendant_id) confers select\nsubject viewer { anchor folder; reach via grant descendants; identifies folder_id; roles none }\nobject shelf {\n  table shelves\n  level folder\n  scoped estate > space > folder\n  permission view = @scoped @rls maps select\n}\n";
    let on_folder = |scoped: &str, rules: &str| {
        format!(
            "{HEAD}{reach}object page {{\n  table pages\n  scoped {scoped}\n  relation open_shelf: member via object shelf->view on folder_id pinned\n{rules}\n}}\n"
        )
    };
    let cases = [
        ("a plain column", page("", "estate > space", "parent_id pinned", VIEW), "that is not a column object \"page\" is contained by"),
        ("a wildcard level", page("", "estate > space wildcard", "space_id pinned", VIEW), "level \"space\" admits a NULL column there"),
        ("an exact level", page("", "estate > space exact", "space_id pinned", VIEW), "level \"space\" admits a NULL column there"),
        (
            "a level a grant reaches across",
            on_folder("estate > space > folder", "  permission view = @scoped and open_shelf @rls maps select"),
            "a grant reaches rows at other values of \"folder\" for this operation",
        ),
        (
            "inside a require",
            page("", "estate > space", "space_id pinned", "  permission view = @scoped @rls maps select\n  require view = open_space"),
            "relation \"open_space\" is `pinned` — a pinned borrow is asked at the caller's claim",
        ),
    ];
    for (name, src, want) in cases {
        let err = compile(&src).expect_err(&format!("{name}: compiles"));
        assert!(err.contains(want), "{name}: {err}");
    }
    let update_only =
        on_folder("estate > space > folder", "  permission view = @scoped @rls maps select\n  permission edit = @scoped and open_shelf @rls maps update");
    let s = compile(&update_only).expect("the grant confers select alone, so the update's folder is the claim's");
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the policies compile");
    let edit = &res.policies.iter().find(|p| p.name == "pages_update").expect("an update policy").using;
    assert!(edit.contains(&format!("(SELECT auth.shelf_can_view({}))", sql.claim("folder_id"))), "{edit}");
}
