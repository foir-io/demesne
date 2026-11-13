use demesne_emit_sql::Sql;

const HEAD: &str = "topology { level estate }\nsubject member { anchor estate; reach self; identifies sub; roles none; binds owner }\n";

fn cascade(view: &str) -> String {
    let src = format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate\n  relation owner: member via owner_id\n  relation parent: member via composition docs(id, parent_id)\n  permission view = {view} @rls maps select\n}}\n"
    );
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let arm = defs.iter().find(|d| d.name == "doc_composition_parent").expect("the cascade").arms[0].body.clone();
    let contained = format!("docs.id = e.parent_id AND ((estate_id = {} AND (", sql.claim("estate_id"));
    let at = arm.find(&contained).unwrap_or_else(|| panic!("the parent's own predicate: {arm}")) + contained.len();
    arm[at..].replace(&sql.claim("sub"), "SUB").replace(&sql.claim("kind"), "KIND").trim_end_matches(')').to_string()
}

#[test]
fn the_parent_is_judged_without_any_branch_that_needs_a_composition() {
    for (view, parent_judged_by) in [
        ("owner + parent", "owner_id = SUB"),
        ("owner + (@kind(\"auditor\") and parent)", "owner_id = SUB"),
        ("owner + (parent and @kind(\"auditor\"))", "owner_id = SUB"),
        ("owner + (@kind(\"auditor\") and not parent)", "owner_id = SUB"),
        ("owner + (@kind(\"auditor\") and (parent + @kind(\"clerk\")))", "owner_id = SUB OR (KIND = 'auditor') AND (KIND = 'clerk'"),
        ("(owner + parent) and @kind(\"auditor\")", "(owner_id = SUB) AND (KIND = 'auditor'"),
        ("owner + (@kind(\"auditor\") and not (parent and @kind(\"clerk\")))", "owner_id = SUB OR (KIND = 'auditor') AND (((KIND = 'clerk')) IS NOT TRUE"),
    ] {
        assert_eq!(cascade(view), parent_judged_by, "{view}");
    }
}
