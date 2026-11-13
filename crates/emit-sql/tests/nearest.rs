use demesne_emit_sql::{Execute, GenFn, Sql};

const HEAD: &str = "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none }\n";

fn spec(closure: &str, nearest: &str) -> String {
    format!("{HEAD}{closure}\nobject theme {{\n  table themes\n  scoped estate > space\n{nearest}\n  permission view = @scoped @rls maps select\n}}\n")
}

fn definers(src: &str) -> Result<Vec<GenFn>, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Sql::new(&s).emit_definers().map_err(|e| e.to_string())
}

const NEAREST: &str = "  nearest theme_color(color text) via closure paths on folder_id";

fn lookup(closure: &str) -> GenFn {
    let src = spec(closure, NEAREST);
    definers(&src).unwrap_or_else(|e| panic!("{e}\n{src}")).into_iter().find(|d| d.name == "theme_color").expect("the lookup")
}

const ABOVE: &str = "SELECT t.color AS v, c.hops AS d FROM paths c JOIN themes t ON t.folder_id = c.anc WHERE c.des = p_node AND t.color IS NOT NULL";

#[test]
fn the_lookup_takes_the_nearest_row_above_that_sets_the_value() {
    let f = lookup("closure paths(anc, des) depth hops");
    assert_eq!((f.sig.as_str(), f.returns.as_str(), f.strict, f.execute), ("p_node text", "text", true, Execute::Granted));
    assert_eq!(f.body, format!("  SELECT x.v FROM (\n    {ABOVE}\n  ) x ORDER BY x.d NULLS LAST, x.v::text LIMIT 1;"));
    assert!(
        f.create_sql().ends_with("REVOKE EXECUTE ON FUNCTION auth.theme_color(text) FROM PUBLIC;"),
        "it returns a row's value for any node, so nobody runs it until granted"
    );
}

#[test]
fn a_scoped_closure_falls_back_to_the_row_that_names_no_node_in_the_nodes_scope() {
    let f = lookup("closure paths(anc, des) base folders(id, parent_id) scope space_id depth hops");
    let fallback = "SELECT t.color, NULL FROM themes t WHERE t.folder_id IS NULL AND t.color IS NOT NULL AND t.space_id = (SELECT s.space_id FROM paths s WHERE s.anc = p_node AND s.des = p_node)";
    assert_eq!(f.body, format!("  SELECT x.v FROM (\n    {ABOVE}\n    UNION ALL\n    {fallback}\n  ) x ORDER BY x.d NULLS LAST, x.v::text LIMIT 1;"));
    let other_scope = lookup("closure paths(anc, des) base folders(id, parent_id) scope shelf_id depth hops");
    assert!(
        !other_scope.body.contains("UNION ALL"),
        "the object is not scoped by the closure's scope column, so no row of it is a fallback:\n{}",
        other_scope.body
    );
}

#[test]
fn the_lookup_is_refused_without_a_declared_depth_or_under_a_taken_name() {
    let cases = [
        ("an undeclared closure", spec("", NEAREST), "reads closure \"paths\", which the spec does not declare"),
        ("a closure with no depth", spec("closure paths(anc, des)", NEAREST), "reads closure \"paths\", which declares no `depth` column"),
        (
            "an unsupported type",
            spec("closure paths(anc, des) depth hops", "  nearest theme_color(color varchar) via closure paths on folder_id"),
            "returns unsupported type \"varchar\"",
        ),
        (
            "one column for both",
            spec("closure paths(anc, des) depth hops", "  nearest theme_color(folder_id text) via closure paths on folder_id"),
            "names \"folder_id\" as both its value and its node column",
        ),
        (
            "a name a probe has",
            spec("closure paths(anc, des) depth hops", &format!("  probe theme_color(color text)\n{NEAREST}")),
            "nearest \"theme_color\" shares its name",
        ),
        (
            "a name the closure's own functions have",
            spec("closure paths(anc, des) depth hops", "  nearest paths_path(color text) via closure paths on folder_id"),
            "nearest \"paths_path\" collides with a generated function",
        ),
    ];
    for (what, src, want) in cases {
        let err = definers(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}
