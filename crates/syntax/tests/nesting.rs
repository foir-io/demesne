use demesne_syntax::{MAX_NESTING, PermNode, parse};

fn spec(clause: &str, expr: &str) -> String {
    format!(
        "subject member {{ anchor workspace; reach self; identifies sub; roles none }}\nobject doc {{\n  table docs\n  scoped workspace\n  relation owner: member via owner_id\n  {clause} = {expr}\n}}\n"
    )
}

fn nested(depth: usize) -> String {
    format!("{}owner{}", "(".repeat(depth), ")".repeat(depth))
}

#[test]
fn parentheses_nested_to_the_limit_parse() {
    let src = spec("permission view", &format!("{} @rls maps select", nested(MAX_NESTING)));
    let s = parse(&src).unwrap_or_else(|e| panic!("{MAX_NESTING} levels don't parse: {e}"));
    assert!(matches!(&s.objects[0].perms[0].tree, PermNode::Leaf(t) if t.ident() == "owner"), "{:?}", s.objects[0].perms[0].tree);
}

#[test]
fn one_level_past_the_limit_is_a_parse_error_on_its_line() {
    for clause in ["permission view", "require view"] {
        let src = spec(clause, &nested(MAX_NESTING + 1));
        let err = parse(&src).expect_err("a permission past the nesting limit parses");
        assert_eq!(err.to_string(), format!("line 6: parentheses nest more than {MAX_NESTING} deep"), "{clause}");
    }
}

#[test]
fn the_limit_counts_depth_not_groups() {
    let siblings = vec!["(owner)"; MAX_NESTING * 4].join(" + ");
    let deep_pair = format!("{} and {}", nested(MAX_NESTING), nested(MAX_NESTING));
    for expr in [siblings, deep_pair] {
        let src = spec("permission view", &format!("{expr} @rls maps select"));
        if let Err(e) = parse(&src) {
            panic!("{e}:\n{src}");
        }
    }
}
