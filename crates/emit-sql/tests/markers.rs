use demesne_emit_sql::{GenFn, Policy, Sql};

const HEAD: &str = "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none }\n";

fn spec(markers: &str, note: &str) -> String {
    format!(
        "{HEAD}closure paths(anc, des) base spaces(id, parent_id)\nobject space {{\n  table spaces\n  level space\n  scoped estate > space\n{markers}\n  permission view = @scoped @rls maps select\n  permission edit = @scoped @rls maps update\n}}\nobject note {{\n  table notes\n  scoped estate > space wildcard confers select\n  permission view = @scoped @rls maps select\n  permission add = @scoped @rls maps insert\n  permission edit = @scoped @rls maps update\n  permission remove = @scoped @rls maps delete\n{note}\n}}\n"
    )
}

fn compiled(src: &str) -> Result<(Vec<Policy>, Vec<GenFn>), String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    let sql = Sql::new(&s);
    let rls = sql.emit_rls().map_err(|e| e.to_string())?;
    if let Some(u) = rls.unsupported.first() {
        return Err(u.clone());
    }
    Ok((rls.policies, sql.emit_definers().map_err(|e| e.to_string())?))
}

fn policies(src: &str) -> Vec<Policy> {
    compiled(src).unwrap_or_else(|e| panic!("{e}\n{src}")).0
}

fn named<'a>(pols: &'a [Policy], name: &str) -> &'a Policy {
    pols.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no policy {name}"))
}

fn claim(src: &str, key: &str) -> String {
    Sql::new(&demesne_syntax::parse(src).expect("parses")).claim(key)
}

const MADE_BY: &str = "  marker made_by from claim job_id confines insert, update, delete";

#[test]
fn a_marker_adds_a_restrictive_condition_to_every_other_object_at_the_level_for_the_named_operations() {
    let src = spec(MADE_BY, "");
    let pols = policies(&src);
    let cond = format!("(space_id IS NULL OR auth.spaces_made_by_marker_admits(space_id, {}))", claim(&src, "job_id"));
    for (name, using, check) in
        [("notes_insert_require", "", cond.as_str()), ("notes_update_require", cond.as_str(), cond.as_str()), ("notes_delete_require", cond.as_str(), "")]
    {
        let p = named(&pols, name);
        assert_eq!((p.restrictive, p.using.as_str(), p.check.as_str()), (true, using, check), "{name}");
    }
    assert!(!pols.iter().any(|p| p.name == "notes_select_require"), "a read is confined only when `select` is named");
    assert!(!pols.iter().any(|p| p.name.starts_with("spaces_") && p.name.ends_with("_require")), "the container's own row keeps its own rule");
}

#[test]
fn the_marker_condition_joins_the_objects_own_require_and_each_marker_adds_its_own() {
    let two = format!("{MADE_BY}\n  marker held_for from claim hold_id confines update");
    let src = spec(&two, "  require edit = @row(locked_at, null)");
    let pols = policies(&src);
    let made = format!("(space_id IS NULL OR auth.spaces_made_by_marker_admits(space_id, {}))", claim(&src, "job_id"));
    let held = format!("(space_id IS NULL OR auth.spaces_held_for_marker_admits(space_id, {}))", claim(&src, "hold_id"));
    assert_eq!(named(&pols, "notes_update_require").using, format!("(locked_at IS NULL) AND {made} AND {held}"));
    assert_eq!(named(&pols, "notes_delete_require").using, made);
}

#[test]
fn the_definer_reads_the_container_whoever_asks_and_fails_closed() {
    let (_, defs) = compiled(&spec(MADE_BY, "")).expect("compiles");
    let f = defs.iter().find(|d| d.name == "spaces_made_by_marker_admits").expect("the definer");
    assert_eq!((f.sig.as_str(), f.strict), ("p_container text, p_claim text", false));
    assert_eq!(f.body, "EXISTS (SELECT 1 FROM spaces m WHERE m.id = p_container AND (m.made_by IS NULL OR m.made_by::text = p_claim))");
}

#[test]
fn through_a_closure_every_marked_container_above_confines_too() {
    let src = spec(&format!("{MADE_BY} through closure paths"), "");
    let (_, defs) = compiled(&src).expect("compiles");
    let f = defs.iter().find(|d| d.name == "spaces_made_by_marker_admits").expect("the definer");
    assert_eq!(
        f.body,
        "EXISTS (SELECT 1 FROM spaces m WHERE m.id = p_container AND (m.made_by IS NULL OR m.made_by::text = p_claim)) AND NOT EXISTS (SELECT 1 FROM paths c JOIN spaces m ON m.id = c.anc WHERE c.des = p_container AND m.made_by IS NOT NULL AND m.made_by::text IS DISTINCT FROM p_claim)"
    );
}

#[test]
fn a_spec_with_no_marker_emits_what_it_did() {
    let pols = policies(&spec("", ""));
    assert!(!pols.iter().any(|p| p.name.ends_with("_require")));
    let (_, defs) = compiled(&spec("", "")).expect("compiles");
    assert!(!defs.iter().any(|d| d.name.contains("marker")));
}

#[test]
fn a_marker_is_refused_where_it_could_confine_nothing_or_reads_what_is_not_declared() {
    let off_level = format!("{HEAD}object note {{\n  table notes\n  scoped estate > space\n{MADE_BY}\n  permission view = @scoped @rls maps select\n}}\n");
    let cases = [
        ("an object that declares no level", off_level, "declares no `level`"),
        ("one column twice", spec(&format!("{MADE_BY}\n  marker made_by from claim other_id confines delete"), ""), "marker \"made_by\" is declared twice"),
        ("an unknown operation", spec("  marker made_by from claim job_id confines truncate", ""), "confines \"truncate\", which is no table operation"),
        ("no operation twice", spec("  marker made_by from claim job_id confines update, update", ""), "confines \"update\" twice"),
        ("an undeclared closure", spec(&format!("{MADE_BY} through closure trails"), ""), "reads closure \"trails\", which the spec does not declare"),
        (
            "a closure over another table",
            format!("closure trails(up, down) base shelves(id, parent_id)\n{}", spec(&format!("{MADE_BY} through closure trails"), "")),
            "reads closure \"trails\", whose base is not table \"spaces\"",
        ),
    ];
    for (what, src, want) in cases {
        let err = compiled(&src).map(|(p, _)| p.len()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}
