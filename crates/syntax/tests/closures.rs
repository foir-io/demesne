use demesne_syntax::{Builtin, Closure, ClosureBase, PermNode, TermKind, parse, parse_files};

fn closure(decl: &str) -> Closure {
    let s = parse(decl).unwrap_or_else(|e| panic!("{decl:?} doesn't parse: {e}"));
    assert_eq!(s.closures.len(), 1, "{decl:?}");
    s.closures[0].clone()
}

fn refusal(src: &str) -> String {
    parse(src).expect_err(&format!("{src:?} parses")).to_string()
}

#[test]
fn a_closure_declaration_names_its_edge_and_each_option_once() {
    let bare = closure("closure paths(ancestor_id, descendant_id)");
    assert_eq!((bare.table.as_str(), bare.ancestor_col.as_str(), bare.descendant_col.as_str()), ("paths", "ancestor_id", "descendant_id"));
    assert_eq!((&bare.base, &bare.scope_col, &bare.depth_col, &bare.named), (&None, &None, &None, &None));
    assert_eq!(bare.definer_base(), "paths");

    let full = closure("closure paths(up, down)\n  named tree depth hops\n  scope space_id base folders(id, parent_id)");
    assert_eq!(full.base, Some(ClosureBase { table: "folders".into(), id_col: "id".into(), parent_col: "parent_id".into() }));
    assert_eq!((full.scope_col.as_deref(), full.depth_col.as_deref(), full.named.as_deref()), (Some("space_id"), Some("hops"), Some("tree")));
    assert_eq!(full.definer_base(), "tree");
}

#[test]
fn a_closure_declaration_that_is_malformed_is_refused() {
    for (src, want) in [
        ("closure paths(a)", "closure paths needs 2 columns (ancestor, descendant), got 1"),
        ("closure paths(a, b, c)", "closure paths needs 2 columns (ancestor, descendant), got 3"),
        ("closure paths(a, b) base folders(id)", "closure paths base needs 2 columns (id, parent), got 1"),
        ("closure paths(a, b) scope x scope y", "closure paths says `scope` twice"),
        ("closure paths(a, b) depth x depth y", "closure paths says `depth` twice"),
        ("closure paths(a, b) named x named y", "closure paths says `named` twice"),
        ("closure paths(a, b) base f(id, p) base g(id, p)", "closure paths says `base` twice"),
    ] {
        let got = refusal(src);
        assert!(got.ends_with(want), "{src:?}: {got}");
    }
}

#[test]
fn a_later_file_replaces_a_closure_by_its_table() {
    let first = "closure paths(a, b) depth hops\n";
    let files =
        parse_files([("one.demesne", first.as_bytes()), ("two.demesne", "replace closure paths(a, b) named tree\n".as_bytes())]).expect("the files parse");
    let merged = files.spec();
    assert_eq!(merged.closures.len(), 1);
    assert_eq!((merged.closures[0].named.as_deref(), merged.closures[0].depth_col.as_deref()), (Some("tree"), None));

    let err = parse_files([("one.demesne", first.as_bytes()), ("two.demesne", "replace closure other(a, b)\n".as_bytes())]).expect_err("nothing to replace");
    assert!(err.to_string().contains("replace closure \"other\": no earlier file declares it"), "{err}");
}

fn object(scoped: &str, body: &str) -> String {
    format!("object doc {{\n  table docs\n  scoped {scoped}\n{body}\n}}\n")
}

#[test]
fn a_scope_level_is_plain_wildcard_or_exact() {
    let s = parse(&object("estate > space exact > folder wildcard confers select", "  permission view = @scoped @rls maps select")).expect("parses");
    let o = &s.objects[0];
    assert_eq!((o.scoped.len(), o.scope_exact.as_slice(), o.scope_wildcards.as_slice()), (3, &["space".to_string()][..], &["folder".to_string()][..]));
    for (level, nullable, exact) in [("estate", false, false), ("space", true, true), ("folder", true, false)] {
        assert_eq!((o.scope_is_wildcard(level), o.scope_is_exact(level)), (nullable, exact), "{level}");
    }
    for op in ["select", "insert", "update", "delete"] {
        assert!(!o.scope_is_wildcard_for("space", op), "an exact level widens no operation, {op} included");
        assert_eq!(o.scope_is_wildcard_for("folder", op), op == "select", "{op}");
    }
    let got = refusal(&object("estate > space exact confers select", ""));
    assert!(got.contains("confers"), "an exact level confers nothing: {got}");
}

fn require_leaves(expr: &str) -> Vec<Builtin> {
    let src = object("estate", &format!("  permission view = @scoped @rls maps select\n  require view = {expr}"));
    let s = parse(&src).unwrap_or_else(|e| panic!("{expr:?} doesn't parse: {e}"));
    let tree = &s.objects[0].requires[0].tree;
    assert_eq!(tree.display(), expr, "the expression displays as it was written");
    tree.leaves()
        .into_iter()
        .map(|t| match &t.kind {
            TermKind::Builtin(b) => b.clone(),
            other => panic!("{expr:?} holds a term that is no builtin: {other:?}"),
        })
        .collect()
}

#[test]
fn null_and_exact_forms_parse_beside_the_valued_ones() {
    assert_eq!(
        require_leaves(
            r#"@row(owner_id, null) + @row(kind, "note") + @claim("folder_id", null) + @claim("tier", "gold") + @within(space exact) + @within(space nullable)"#
        ),
        [
            Builtin::RowNull("owner_id".into()),
            Builtin::Row { col: "kind".into(), val: "note".into() },
            Builtin::ClaimAbsent("folder_id".into()),
            Builtin::Claim { key: "tier".into(), val: "gold".into() },
            Builtin::WithinExact("space".into()),
            Builtin::Within { level: "space".into(), nullable: true },
        ]
    );
    for b in require_leaves(r#"@row(owner_id, null) + @claim("folder_id", null) + @within(space exact)"#) {
        assert!(["row", "claim", "within"].contains(&b.name()), "{b:?} keeps its builtin's name");
    }
}

#[test]
fn a_null_form_reports_its_column_key_or_level_and_no_value() {
    let src = object(
        "estate",
        "  permission view = @scoped @rls maps select\n  require view = @row(owner_id, null) + @claim(\"folder_id\", null) + @within(space exact)",
    );
    let s = parse(&src).expect("parses");
    let PermNode::Or(kids) = &s.objects[0].requires[0].tree else { panic!("a union") };
    let terms: Vec<_> = kids.iter().map(|k| k.term().expect("a leaf")).collect();
    assert_eq!((terms[0].row_col(), terms[0].row_val(), terms[0].row_null()), ("owner_id", "", true));
    assert_eq!((terms[1].claim_key(), terms[1].claim_val(), terms[1].claim_absent()), ("folder_id", "", true));
    assert_eq!((terms[2].within_level(), terms[2].within_nullable(), terms[2].within_exact()), ("space", false, true));
    assert!(!terms[0].claim_absent() && !terms[0].within_exact() && !terms[1].row_null() && !terms[2].row_null());
}

#[test]
fn a_null_test_takes_the_bare_word_and_nothing_else() {
    for expr in ["@row(owner_id, nil)", "@row(owner_id)", "@claim(\"k\", nothing)", "@within(space exactly)"] {
        let src = object("estate", &format!("  permission view = @scoped @rls maps select\n  require view = {expr}"));
        assert!(parse(&src).is_err(), "{expr:?} parses");
    }
}

#[test]
fn a_reach_use_reads_through_each_grant_it_lists() {
    let vias = |clause: &str| -> Vec<String> {
        let s = parse(&object("estate > folder wildcard", &format!("  reach down {clause}\n  permission view = @scoped @rls maps select"))).expect("parses");
        s.objects[0].reach_uses[0].via.clone()
    };
    assert_eq!(vias("via up for select"), ["up"]);
    assert_eq!(vias("via down, up for select"), ["down", "up"]);
    assert_eq!(vias("unscoped"), [] as [&str; 0]);
    assert!(parse(&object("estate", "  reach down via for select")).is_err(), "`via` names at least one grant");
}
