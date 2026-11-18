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
    assert_eq!((f.sig().as_str(), f.returns.as_str(), f.strict, f.execute), ("p_node text", "text", true, Execute::Grantable));
    assert_eq!(f.body, format!("  SELECT x.v FROM (\n    {ABOVE}\n  ) x ORDER BY x.d NULLS LAST, x.v::text LIMIT 1;"));
    assert!(
        f.create_sql().ends_with("REVOKE EXECUTE ON FUNCTION auth.theme_color(text) FROM PUBLIC, authenticated;"),
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

const LIVE: &str = "  nearest live_theme(id text) via closure paths on folder_id where status = \"live\"";
const SCOPED: &str = "closure paths(anc, des) base folders(id, parent_id) scope space_id depth hops";

fn banners(require: &str) -> String {
    format!(
        "{}object banner {{\n  table banners\n  scoped estate > space\n  permission view = @scoped {require}\n}}\n",
        spec(SCOPED, LIVE).replace("@scoped @rls maps select", "@scoped @rls maps select\n")
    )
}

#[test]
fn a_row_filter_counts_only_the_rows_that_hold_the_value() {
    let src = spec(SCOPED, LIVE);
    let f = definers(&src).unwrap_or_else(|e| panic!("{e}\n{src}")).into_iter().find(|d| d.name == "live_theme").expect("the lookup");
    let above =
        "SELECT t.id AS v, c.hops AS d FROM paths c JOIN themes t ON t.folder_id = c.anc WHERE c.des = p_node AND t.id IS NOT NULL AND t.status = 'live'";
    let fallback = "SELECT t.id, NULL FROM themes t WHERE t.folder_id IS NULL AND t.id IS NOT NULL AND t.status = 'live' AND t.space_id = (SELECT s.space_id FROM paths s WHERE s.anc = p_node AND s.des = p_node)";
    assert_eq!(f.body, format!("  SELECT x.v FROM (\n    {above}\n    UNION ALL\n    {fallback}\n  ) x ORDER BY x.d NULLS LAST, x.v::text LIMIT 1;"));
    let quoted = spec(SCOPED, &LIVE.replace("\"live\"", "\"li've\""));
    let body = definers(&quoted).expect("a quote in the value compiles").into_iter().find(|d| d.name == "live_theme").expect("the lookup").body;
    assert!(body.contains("t.status = 'li''ve'"), "the value reaches SQL as a literal:\n{body}");
}

#[test]
fn a_require_compares_a_column_with_the_nearest_value_at_the_callers_own_node() {
    let src = banners("@rls maps select\n  require view = @claim(\"folder_id\", null) + @nearest(live_theme, theme_id from claim folder_id)");
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let rls = sql.emit_rls().expect("the policies compile");
    let floor = &rls.policies.iter().find(|p| p.name == "banners_select_require").expect("the floor").using;
    let claim = sql.claim("folder_id");
    assert_eq!(floor, &format!("{claim} IS NULL OR theme_id = (SELECT auth.live_theme_own({claim}))"));
    let defs = sql.emit_definers().expect("the definers compile");
    let own = defs.iter().find(|d| d.name == "live_theme_own").expect("the claim-bound form");
    assert_eq!((own.sig().as_str(), own.returns.as_str(), own.strict, own.execute), ("p_node text", "text", true, Execute::Public));
    assert_eq!(
        own.body,
        format!("  SELECT auth.live_theme(p_node) WHERE p_node = {};", sql.session_claim("folder_id")),
        "it answers at the caller's own node and nowhere else"
    );
    let unused = definers(&spec(SCOPED, LIVE)).expect("the definers compile");
    assert!(!unused.iter().any(|d| d.name == "live_theme_own"), "no term asks, so no claim-bound form is emitted");
}

#[test]
fn the_comparison_is_refused_outside_a_require_or_of_a_lookup_the_spec_lacks() {
    let cases = [
        ("in a permission", banners("and @nearest(live_theme, theme_id from claim folder_id) @rls maps select"), "may appear only in a `require` clause"),
        (
            "an undeclared lookup",
            banners("@rls maps select\n  require view = @nearest(dead_theme, theme_id from claim folder_id)"),
            "names no `nearest dead_theme(…)` lookup",
        ),
        (
            "a name its claim-bound form would share",
            banners("@rls maps select\n  probe live_theme_own(id text)\n  require view = @nearest(live_theme, theme_id from claim folder_id)"),
            "its claim-bound form \"live_theme_own\" collides with a generated function",
        ),
        ("no claim", banners("@rls maps select\n  require view = @nearest(live_theme, theme_id)"), "from"),
    ];
    for (what, src, want) in cases {
        let err = definers(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}

#[test]
fn each_lookup_is_bound_to_the_claims_its_own_terms_name() {
    let two = format!("{LIVE}\n  nearest any_theme(id text) via closure paths on folder_id");
    let src = format!(
        "{}object banner {{\n  table banners\n  scoped estate > space\n  permission view = @scoped @rls maps select\n  require view = @nearest(live_theme, theme_id from claim folder_id) + @nearest(any_theme, theme_id from claim desk_id) + @nearest(any_theme, theme_id from claim room_id)\n}}\n",
        spec(SCOPED, &two)
    );
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let body = |name: &str| defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}")).body.clone();
    assert_eq!(body("live_theme_own"), format!("  SELECT auth.live_theme(p_node) WHERE p_node = {};", sql.session_claim("folder_id")));
    assert_eq!(
        body("any_theme_own"),
        format!("  SELECT auth.any_theme(p_node) WHERE p_node IN ({}, {});", sql.session_claim("desk_id"), sql.session_claim("room_id"))
    );
}
