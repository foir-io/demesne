use demesne_model::closure::{self, Direction};
use demesne_model::{Structure, validate_structure};
use std::fmt::Write as _;

const HEAD: &str =
    "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\n";

fn object(scoped: &str, body: &str) -> String {
    format!("object doc {{\n  table docs\n  scoped {scoped}\n{body}\n}}\n")
}

fn messages(src: &str) -> Vec<String> {
    match validate_structure(&demesne_syntax::parse(src).unwrap_or_else(|e| panic!("the spec parses: {e}\n{src}"))) {
        Structure::Fatal(e) => panic!("the topology is sound: {e}"),
        Structure::Errors(f) => f.iter().map(|f| f.message().to_string()).collect(),
    }
}

fn spec(closures: &str, relations: &[&str]) -> String {
    let mut body = String::new();
    for (i, r) in relations.iter().enumerate() {
        writeln!(body, "  relation r{i}: member via closure {r}").expect("fmt::Write for String never fails");
    }
    body.push_str("  permission view = @scoped @rls maps select");
    format!("{HEAD}{closures}\n{}", object("estate > space", &body))
}

fn check(cases: &[(&str, String, &str, bool)]) {
    for (name, src, want, present) in cases {
        let found = messages(src);
        assert_eq!(
            found.iter().any(|m| m.contains(want)),
            *present,
            "{name}: expected {want:?} to be {}: {found:#?}",
            if *present { "reported" } else { "absent" }
        );
    }
}

const DOWN: &str = "paths(anc, des) on folder_id from claim folder_id missing allow";
const UP: &str = "paths(des, anc) on folder_id from claim folder_id missing deny";
const NO_EDGE: &str = "matches no edge of the closure, which is (anc, des)";

#[test]
fn a_relation_reads_the_closures_edge_in_one_of_its_two_directions_or_is_refused() {
    check(&[
        ("both directions, undeclared", spec("", &[DOWN, UP]), NO_EDGE, false),
        ("both directions, declared", spec("closure paths(anc, des)", &[UP, DOWN]), NO_EDGE, false),
        ("an unknown column", spec("", &[DOWN, "paths(anc, other) on folder_id from claim folder_id missing deny"]), NO_EDGE, true),
        ("two unknown columns", spec("closure paths(anc, des)", &["paths(x, y) on folder_id from claim folder_id missing deny"]), NO_EDGE, true),
        (
            "one column twice",
            spec("closure paths(anc, des)", &["paths(anc, anc) on folder_id from claim folder_id missing deny"]),
            "names \"anc\" as both of its columns",
            true,
        ),
        (
            "one column twice, undeclared and first",
            spec("", &["paths(anc, anc) on folder_id from claim folder_id missing deny"]),
            "names \"anc\" as both of its columns",
            true,
        ),
        ("two columns", spec("", &[DOWN]), "as both of its columns", false),
        ("the declaration decides, not the first relation", spec("closure paths(des, anc)", &[DOWN, UP]), NO_EDGE, false),
    ]);
    let all: Vec<String> = messages(&spec("closure paths(anc, des)", &["paths(x, y) on folder_id from claim folder_id missing deny"]));
    assert!(
        all.iter().any(|m| m.contains("closure paths(x, y)") && m.contains("ancestor first to reach beneath the caller, descendant first to reach above")),
        "{all:#?}"
    );
}

#[test]
fn the_edge_and_each_relations_direction_come_from_the_declaration_or_the_first_relation() {
    let direction_of = |closures: &str, relations: &[&str]| -> Vec<Option<Direction>> {
        let s = demesne_syntax::parse(&spec(closures, relations)).expect("parses");
        let edge = closure::edge(&s, "paths").expect("the closure has an edge");
        closure::relations_over(&s, "paths").map(|r| edge.relation_direction(r)).collect()
    };
    assert_eq!(direction_of("", &[DOWN, UP]), [Some(Direction::Down), Some(Direction::Up)]);
    assert_eq!(direction_of("", &[UP, DOWN]), [Some(Direction::Down), Some(Direction::Up)], "undeclared, the first relation is the downward one");
    assert_eq!(direction_of("closure paths(anc, des)", &[UP, DOWN]), [Some(Direction::Up), Some(Direction::Down)]);
    assert_eq!(direction_of("closure paths(des, anc)", &[UP, DOWN]), [Some(Direction::Down), Some(Direction::Up)]);

    let s = demesne_syntax::parse(&spec("closure other(a, b) named tree\nclosure paths(anc, des)", &[UP])).expect("parses");
    let tables: Vec<(&str, &str)> = closure::edges(&s).iter().map(|e| (e.table, e.definer_base())).collect();
    assert_eq!(tables, [("paths", "paths"), ("other", "tree")], "a closure a relation reads comes first, a declared-only one after");
    assert!(closure::edge(&s, "absent").is_none());
}

#[test]
fn a_closure_has_one_base() {
    let owner = |base: &str| format!("paths(anc, des){base} on folder_id");
    check(&[
        ("an owner-keyed closure with no base", spec("", &[&owner("")]), "a closure keyed on the owner needs `base <table>(id, parent)`", true),
        ("the relation's base", spec("", &[&owner(" base folders(id, parent_id)")]), "needs `base", false),
        ("the declaration's base", spec("closure paths(anc, des) base folders(id, parent_id)", &[&owner("")]), "needs `base", false),
        ("a declaration without a base", spec("closure paths(anc, des)", &[&owner("")]), "needs `base", true),
        (
            "two relations, two bases",
            spec("", &[&owner(" base folders(id, parent_id)"), &owner(" base shelves(id, parent_id)")]),
            "closure paths is maintained from folders(id, parent_id), not shelves(id, parent_id) — a closure has one base",
            true,
        ),
        (
            "a relation against its declaration",
            spec("closure paths(anc, des) base folders(id, parent_id)", &[&owner(" base folders(id, above_id)")]),
            "closure paths is maintained from folders(id, parent_id), not folders(id, above_id)",
            true,
        ),
        (
            "a relation repeating its declaration",
            spec("closure paths(anc, des) base folders(id, parent_id)", &[&owner(" base folders(id, parent_id)")]),
            "a closure has one base",
            false,
        ),
    ]);
}

#[test]
fn a_closure_declaration_is_checked() {
    check(&[
        ("declared twice", spec("closure paths(anc, des)\nclosure paths(anc, des)", &[]), "closure \"paths\" is declared more than once", true),
        (
            "two closures, one name",
            spec("closure paths(anc, des) named tree\nclosure limbs(anc, des) named tree", &[]),
            "closure \"limbs\" and closure \"paths\" both name their functions tree_… — give one its own name with `named`",
            true,
        ),
        ("two closures, two names", spec("closure paths(anc, des)\nclosure limbs(anc, des)", &[]), "both name their functions", false),
        ("one column for both ends", spec("closure paths(anc, anc)", &[]), "names \"anc\" as both its ancestor and its descendant column", true),
        ("a scope with no base", spec("closure paths(anc, des) scope space_id", &[]), "declares `scope` with no `base`", true),
        ("a scope with a base", spec("closure paths(anc, des) base folders(id, parent_id) scope space_id", &[]), "declares `scope` with no `base`", false),
        ("a depth with no base", spec("closure paths(anc, des) depth hops", &[]), "closure \"paths\"", false),
        ("a base whose id is its parent", spec("closure paths(anc, des) base folders(id, id)", &[]), "names \"id\" as both its id and its parent column", true),
        ("its own base", spec("closure paths(anc, des) base paths(anc, des)", &[]), "names itself as its base", true),
    ]);
}

fn with_object(scoped: &str, body: &str) -> String {
    format!("{HEAD}{}", object(scoped, body))
}

#[test]
fn an_exact_level_is_one_whose_column_can_be_null() {
    let view = "  permission view = @scoped @rls maps select";
    check(&[
        ("an exact level", with_object("estate > space exact", view), "exact", false),
        (
            "on the object's own level",
            format!("{HEAD}object space {{\n  table spaces\n  level space\n  scoped estate > space exact\n{view}\n}}\n"),
            "declares `space exact`, but \"space\" is its own level, whose scope column is the primary key \"id\"",
            true,
        ),
        (
            "on a virtual level",
            format!("topology {{ level root virtual level estate parent root }}\n{}", object("root exact", view)),
            "declares `root exact`, but \"root\" is a virtual level",
            true,
        ),
    ]);
}

#[test]
fn a_claim_absent_or_exact_level_test_belongs_in_a_require() {
    let perm = |term: &str| with_object("estate > space", &format!("  permission view = @scoped and {term} @rls maps select"));
    let admit =
        |term: &str| with_object("estate > space", &format!("  permission view = @scoped @rls maps select\n  admit select = @kind(\"robot\") and {term}"));
    let require = |expr: &str| with_object("estate > space", &format!("  permission view = @scoped @rls maps select\n  require view = {expr}"));
    check(&[
        (
            "claim absent in a permission",
            perm("@claim(\"folder_id\", null)"),
            "uses @claim(\"folder_id\", null) — a test that a claim is absent names nobody",
            true,
        ),
        ("claim absent in an admit arm", admit("@claim(\"folder_id\", null)"), "may appear only in a `require` clause", true),
        ("claim absent in a require", require("@claim(\"folder_id\", null)"), "require", false),
        (
            "exact level in a permission",
            perm("@within(space exact)"),
            "uses @within(space exact) — an exact level test admits a request that names no space",
            true,
        ),
        ("exact level in a require", require("@within(space exact)"), "require", false),
        ("exact level naming no level", require("@within(shelf exact)"), "require doc.view uses @within(\"shelf\") which is not a topology level", true),
        ("a valued claim still needs its value", perm("@claim(\"tier\", \"\")"), "uses @claim with an empty key or value", true),
        ("a null row test in a permission's conjunction", perm("@row(folder_id, null)"), "@row", false),
        (
            "a null row test admitting by itself",
            with_object("estate > space", "  permission view = @scoped + @row(folder_id, null) @rls maps select"),
            "uses @row(folder_id, null) where it would admit a caller by itself",
            true,
        ),
        ("a valued row test still needs its value", perm("@row(folder_id, \"\")"), "uses @row with an empty column or value", true),
    ]);
}

#[test]
fn a_require_takes_a_row_test_as_a_branch_and_still_refuses_what_widens() {
    let require = |expr: &str| {
        with_object("estate > space", &format!("  relation owner: member via owner_id\n  permission view = @scoped @rls maps select\n  require view = {expr}"))
    };
    let positive = "is not positively gated";
    check(&[
        ("a row test alone", require("@row(kind, \"note\")"), "require doc.view", false),
        ("a null row test as a branch", require("owner + @row(folder_id, null)"), "require doc.view", false),
        ("a negated row test as a branch", require("owner + not @row(kind, \"private\")"), "require doc.view", false),
        ("a negated null row test alone", require("not @row(folder_id, null)"), "require doc.view", false),
        ("a negated relation as a branch", require("@row(kind, \"note\") + not owner"), positive, true),
        ("a negated relation alone", require("not owner"), positive, true),
        ("a negated claim-absent test alone", require("not @claim(\"folder_id\", null)"), positive, true),
        ("a negated claim-absent test in a conjunction", require("owner and not @claim(\"folder_id\", null)"), "require doc.view", false),
        ("a widening term", require("@row(kind, \"note\") + @scoped"), "uses widening term @scoped", true),
    ]);
}

#[test]
fn a_declared_closure_binds_its_tables_and_columns_against_the_database() {
    use demesne_model::{Nullability, Schema, table_coverage, validate_against};
    let s = demesne_syntax::parse(&format!("{HEAD}closure paths(anc, des) base folders(id, parent_id) scope space_id depth hops\n")).expect("parses");
    let refusals =
        |sc: &Schema| -> Vec<String> { validate_against(&s, sc).err().map(|e| e.findings().iter().map(ToString::to_string).collect()).unwrap_or_default() };
    assert_eq!(
        refusals(&Schema::new()),
        ["closure paths base: table \"folders\" not found in the database", "closure paths: table \"paths\" not found in the database"]
    );
    let mut sc = Schema::new();
    for (table, col) in [("paths", "anc"), ("folders", "id")] {
        sc.add_column(table, col, "text", Nullability::NotNull);
    }
    assert_eq!(
        refusals(&sc),
        [
            "closure paths base: table \"folders\" has no column \"parent_id\"",
            "closure paths base: table \"folders\" has no column \"space_id\"",
            "closure paths: table \"paths\" has no column \"des\"",
            "closure paths: table \"paths\" has no column \"hops\"",
            "closure paths: table \"paths\" has no column \"space_id\"",
        ]
    );
    for (table, col) in [("paths", "des"), ("paths", "hops"), ("paths", "space_id"), ("folders", "parent_id"), ("folders", "space_id")] {
        sc.add_column(table, col, "text", Nullability::NotNull);
    }
    assert_eq!(refusals(&sc), [] as [String; 0]);
    let cov = table_coverage(&s, &["folders".to_string(), "paths".to_string(), "stray".to_string()]);
    assert_eq!((cov.referenced, cov.ungoverned), (vec!["folders".to_string(), "paths".to_string()], vec!["stray".to_string()]));
}

#[test]
fn a_reach_use_through_several_grants_names_edge_grants_at_the_level_each_once() {
    let src = |reach: &str| {
        format!(
            "topology {{ level estate level folder parent estate }}\ngrant down at folder via edge paths(anc, des) confers select\ngrant up at folder via edge paths(des, anc) named paths_up confers select\ngrant writers at folder via edge paths(anc, des) named paths_w confers update\ngrant tier at folder via claim tier = \"all\" confers select\ngrant estates at estate via edge holders(holder_id, estate_id) confers select\nsubject viewer {{ anchor folder; reach via grant down; identifies folder_id; roles none }}\n{}",
            object("estate > folder wildcard confers select", &format!("  reach down {reach}\n  permission view = @scoped @rls maps select"))
        )
    };
    check(&[
        ("itself and another", src("via down, up for select"), "reach down via", false),
        ("another alone", src("via up for select"), "reach down via", false),
        ("itself alone", src("via down for select"), "reach down via down: the replacement must be another edge grant at \"folder\"", true),
        ("one grant twice", src("via up, up for select"), "reach down names up twice after `via`", true),
        (
            "a claim grant in the list",
            src("via down, tier for select"),
            "reach down via tier: each grant it reads through must be an edge grant at \"folder\"",
            true,
        ),
        (
            "a grant at another level",
            src("via down, estates for select"),
            "reach down via estates: each grant it reads through must be an edge grant at \"folder\"",
            true,
        ),
        ("an unknown grant", src("via down, nothing for select"), "reach down via nothing: each grant it reads through must be an edge grant", true),
        ("a grant that does not confer the operation", src("via down, writers for select"), "reach down via writers: \"writers\" does not confer select", true),
    ]);
}
