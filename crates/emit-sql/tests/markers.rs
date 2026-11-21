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
fn the_definer_answers_only_for_a_container_the_caller_holds_and_fails_closed() {
    let (_, defs) = compiled(&spec(MADE_BY, "")).expect("compiles");
    let f = defs.iter().find(|d| d.name == "spaces_made_by_marker_admits").expect("the definer");
    assert_eq!((f.sig().as_str(), f.strict), ("p_container text, p_claim text", false));
    assert_eq!(
        f.body,
        "p_claim IS NOT DISTINCT FROM (SELECT current_setting('request.jwt.claims', true)::json ->> 'job_id') AND EXISTS (SELECT 1 FROM spaces m WHERE m.id = p_container AND ((estate_id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'estate_id')) AND id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'space_id')) AND (m.made_by IS NULL OR m.made_by::text = p_claim))",
        "the value compared is the caller's own claim, and the container is one the caller's estate and space claims hold"
    );
}

#[test]
fn through_a_closure_every_marked_container_above_confines_too() {
    let src = spec(&format!("{MADE_BY} through closure paths"), "");
    let (_, defs) = compiled(&src).expect("compiles");
    let f = defs.iter().find(|d| d.name == "spaces_made_by_marker_admits").expect("the definer");
    assert_eq!(
        f.body,
        "p_claim IS NOT DISTINCT FROM (SELECT current_setting('request.jwt.claims', true)::json ->> 'job_id') AND EXISTS (SELECT 1 FROM spaces m WHERE m.id = p_container AND ((estate_id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'estate_id')) AND id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'space_id')) AND (m.made_by IS NULL OR m.made_by::text = p_claim)) AND NOT EXISTS (SELECT 1 FROM paths c JOIN spaces m ON m.id = c.anc WHERE c.des = p_container AND m.made_by IS NOT NULL AND m.made_by::text IS DISTINCT FROM p_claim)"
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

const ABOVE_HEAD: &str = "topology { level root virtual level estate parent root level space parent estate }\nvocabulary staff { permission spaces:read permission spaces:write implies spaces:read preset keeper @ estate = spaces:write }\nrolestore staff {\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n}\ngrant visit at estate via edge visits(guest_id, estate_id)\nsubject staff { anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }\nsubject operator { anchor root; reach descendants; identifies op_id via membership operators(user_id, is_op); roles none }\nsubject guest { anchor estate; reach via grant visit; identifies guest_id; roles none }\n";

fn above(declared: &str, markers: &str) -> String {
    format!(
        "{ABOVE_HEAD}object estate {{\n  table estates\n  level estate\n  scoped estate\n  permission view = @scoped @rls maps select\n}}\nobject space {{\n  table spaces\n{declared}  scoped estate\n{markers}\n  relation member: staff via role\n  permission view = member + @holds(spaces:read) @rls maps select\n  permission edit = @holds(spaces:write) @rls maps update\n  permission add = @scoped @rls maps insert\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  permission view = @scoped @rls maps select\n  permission add = @scoped @rls maps insert\n  permission edit = @scoped @rls maps update\n  permission remove = @scoped @rls maps delete\n}}\n"
    )
}

const LEVEL: &str = "  level space\n";

fn own(pols: &[Policy], table: &str) -> Vec<(String, bool, String, String)> {
    pols.iter().filter(|p| p.name.starts_with(&format!("{table}_"))).map(|p| (p.name.clone(), p.restrictive, p.using.clone(), p.check.clone())).collect()
}

fn bodies(defs: &[GenFn]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = defs.iter().map(|d| (d.name.clone(), d.body.clone())).collect();
    out.sort();
    out
}

#[test]
fn a_level_whose_object_is_scoped_only_above_it_takes_a_marker_that_confines_the_rows_beneath() {
    let src = above(LEVEL, MADE_BY);
    let pols = policies(&src);
    let cond = format!("(space_id IS NULL OR auth.spaces_made_by_marker_admits(space_id, {}))", claim(&src, "job_id"));
    for (name, using, check) in
        [("notes_insert_require", "", cond.as_str()), ("notes_update_require", cond.as_str(), cond.as_str()), ("notes_delete_require", cond.as_str(), "")]
    {
        let p = named(&pols, name);
        assert_eq!((p.restrictive, p.using.as_str(), p.check.as_str()), (true, using, check), "{name}");
    }
}

#[test]
fn a_container_scoped_only_above_its_level_is_held_by_whoever_the_levels_above_contain_or_reach() {
    let src = above(LEVEL, MADE_BY);
    let (_, defs) = compiled(&src).expect("compiles");
    let f = defs.iter().find(|d| d.name == "spaces_made_by_marker_admits").expect("the definer");
    let estate = claim(&src, "estate_id");
    let guest = claim(&src, "guest_id");
    let held = format!("((estate_id = {estate} OR estate_id IN (SELECT auth.visits_reach_set({guest}))))");
    assert!(f.body.contains(&held), "the caller's estate, or a grant reaching it, holds every space of it: {}", f.body);
    assert!(!f.body.contains(&format!("id = {}", claim(&src, "space_id"))), "no space claim is asked of the container: {}", f.body);
    assert!(f.body.contains("auth.is_op("), "a claim-only branch holds every container: {}", f.body);
}

#[test]
fn declaring_a_level_it_is_scoped_only_above_leaves_the_objects_own_rules_as_they_were() {
    let (plain_pols, plain_defs) = compiled(&above("", "")).expect("compiles without the level");
    let (level_pols, level_defs) = compiled(&above(LEVEL, "")).expect("compiles with the level");
    assert_eq!(own(&level_pols, "spaces"), own(&plain_pols, "spaces"));
    assert_eq!(bodies(&level_defs), bodies(&plain_defs));
    let (marked_pols, marked_defs) = compiled(&above(LEVEL, MADE_BY)).expect("compiles with the marker");
    assert_eq!(own(&marked_pols, "spaces"), own(&plain_pols, "spaces"));
    assert_eq!(own(&marked_pols, "estates"), own(&plain_pols, "estates"));
    let added: Vec<String> = bodies(&marked_defs).into_iter().filter(|d| !bodies(&plain_defs).contains(d)).map(|(name, _)| name).collect();
    assert_eq!(added, ["spaces_made_by_marker_admits"]);
}

#[test]
fn a_level_is_refused_on_an_object_scoped_neither_at_it_nor_at_exactly_the_levels_above_it() {
    let deep =
        "topology { level estate level space parent estate level room parent space }\nsubject member { anchor room; reach self; identifies sub; roles none }\n";
    let object = |scoped: &str, level: &str| {
        format!("{deep}object thing {{\n  table things\n  level {level}\n  scoped {scoped}\n  permission view = @scoped @rls maps select\n}}\n")
    };
    let cases = [
        ("a level two beneath the deepest scoped", object("estate", "room")),
        ("a level above the deepest scoped", object("estate > space", "estate")),
        ("the root level, which has none above", object("estate", "estate").replace("level estate\n  scoped estate", "level estate\n  scoped space")),
    ];
    for (what, src) in cases {
        let err = compiled(&src).map(|(p, _)| p.len()).expect_err(what);
        assert!(err.contains("must be its deepest scoped level, or the object must be scoped at exactly the levels above"), "{what}: {err}");
    }
    compiled(&object("estate > space", "room")).expect("the level directly beneath the levels the object is scoped at");
}
