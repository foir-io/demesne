use demesne_emit_sql::{GenFn, Sql};
use demesne_model::{ConditionalExt, SpecExt};

const HEAD: &str =
    "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\n";
const RELATIONS: &str = "  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation second: member via edge doc_edges(principal_id, object_id) key rule_id where slot = \"2\"\n  relation barred: member via edge doc_bars(principal_id, object_id) key rule_id\n  relation parent: member via composition docs(id, parent_id)\n";

fn doc(rules: &str) -> String {
    format!("{HEAD}object doc {{\n  table docs\n  scoped estate > space\n{RELATIONS}{rules}\n}}\n")
}

fn compile(src: &str) -> Result<demesne_syntax::Spec, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

fn view(expr: &str) -> String {
    doc(&format!("  permission view = {expr} @rls maps select"))
}

fn select_using(src: &str) -> String {
    let s = compile(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    Sql::new(&s).emit_rls().expect("the policies compile").policies.into_iter().find(|p| p.name == "docs_select").expect("a select policy").using
}

fn definers(src: &str) -> Vec<GenFn> {
    let s = compile(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    Sql::new(&s).emit_definers().expect("the definers compile")
}

const EL: &str = "demesne_element.v";

#[test]
fn a_some_term_displays_as_written() {
    for expr in [
        "some r in rules_live (named)",
        "some r in rules_live prefix \"read.\" held rules_held (@element prefix \"read.edge.\" and named and not barred)",
        "owner + some r in rules_live held rules_held (named + second)",
    ] {
        let s = compile(&view(expr)).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert_eq!(s.objects[0].perms[0].tree.display(), expr);
    }
}

#[test]
fn some_binds_one_element_of_the_rows_set_and_filters_it_before_any_lookup() {
    let src = view("some r in rules_live prefix \"read.\" held rules_held (named and not barred)");
    let s = compile(&src).expect("compiles");
    let sql = Sql::new(&s);
    let (sub, held) = (sql.claim("sub"), sql.claim("rules_held"));
    let using = select_using(&src);
    let want = format!(
        "EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE starts_with({EL}, 'read.') AND {EL} = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text({held}::jsonb) e)) AND ((auth.doc_named_keyed({sub}, docs.id, {EL})) AND ((auth.doc_barred_keyed({sub}, docs.id, {EL})) IS NOT TRUE)))"
    );
    assert!(using.ends_with(&format!("AND ({want}))")), "{using}");
    let bare = select_using(&view("some r in rules_live (named)"));
    assert!(
        bare.ends_with(&format!(
            "AND (EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE (auth.doc_named_keyed({sub}, docs.id, {EL})))))"
        )),
        "{bare}"
    );
}

#[test]
fn an_element_test_picks_the_branch_and_ordinary_terms_keep_their_meaning_inside() {
    let using = select_using(&view(
        "some r in rules_live (((@element prefix \"read.edge.\" and named) + (@element prefix \"read.open.\" and mode visibility = \"listed\") + (@element prefix \"read.tree.\" and parent)) and not barred)",
    ));
    for frag in [
        "(starts_with(demesne_element.v, 'read.edge.')) AND (auth.doc_named_keyed(",
        "OR (starts_with(demesne_element.v, 'read.open.')) AND (visibility = 'listed')",
        "OR (starts_with(demesne_element.v, 'read.tree.')) AND (auth.doc_composition_parent(docs.id, 'read'))",
    ] {
        assert!(using.contains(frag), "lacks {frag:?}:\n{using}");
    }
}

#[test]
fn a_some_branch_is_written_after_the_ordinary_branches_of_its_union() {
    let using = select_using(&view("some r in rules_live (named) + owner + mode visibility = \"public\""));
    let (owner, mode, some) = (
        using.find("owner_id = ").expect("owner"),
        using.find("visibility = 'public'").expect("mode"),
        using.find("EXISTS (SELECT 1 FROM unnest").expect("some"),
    );
    assert!(owner < some && mode < some, "a row an ordinary term admits never runs the some:\n{using}");
    let plain = select_using(&view("mode visibility = \"public\" + owner"));
    assert!(plain.find("visibility").expect("mode") < plain.find("owner_id").expect("owner"), "a union with no some keeps its order:\n{plain}");
}

#[test]
fn a_keyed_edge_matches_principal_object_and_key_and_a_literal_when_it_names_one() {
    let defs = definers(&view("some r in rules_live (named and second and not barred)"));
    let get = |name: &str| defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"));
    let named = get("doc_named_keyed");
    assert_eq!((named.sig.as_str(), named.strict), ("p_principal text, p_object text, p_key text", true));
    assert_eq!(named.body, "EXISTS (SELECT 1 FROM doc_edges WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key)");
    assert_eq!(
        get("doc_second_keyed").body,
        "EXISTS (SELECT 1 FROM doc_edges WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key AND slot = '2')"
    );
    assert_eq!(get("doc_barred_keyed").body, "EXISTS (SELECT 1 FROM doc_bars WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key)");
}

#[test]
fn a_keyed_edge_matches_the_row_column_it_names_in_place_of_the_key() {
    let src = format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate > space\n  relation of_owner: member via edge doc_edges(principal_id, object_id) key rule_id on owner_id where object = \"owner\"\n  relation of_row: member via edge doc_edges(principal_id, object_id) key rule_id where object = \"record\"\n  permission view = some r in rules_live (of_owner + of_row) @rls maps select\n}}\n"
    );
    let using = select_using(&src);
    assert!(using.contains("auth.doc_of_owner_keyed(") && using.contains(", docs.owner_id, demesne_element.v)"), "{using}");
    assert!(using.contains(", docs.id, demesne_element.v)"), "{using}");
}

#[test]
fn the_composition_definer_keeps_the_some_and_drops_only_the_composition_inside_it() {
    let defs = definers(&view("owner + some r in rules_live ((@element prefix \"t.\" and parent) + (@element prefix \"e.\" and named))"));
    let cascade = defs.iter().find(|d| d.name == "doc_composition_parent").expect("the composition definer").create_sql();
    assert!(
        cascade.contains("EXISTS (SELECT 1 FROM unnest(") && cascade.contains("doc_named_keyed("),
        "the ancestor still admits by its keyed edge:\n{cascade}"
    );
    assert!(
        !cascade.contains("doc_composition_parent(docs.id") && !cascade.contains("starts_with(demesne_element.v, 't.')"),
        "the composition branch is pruned from the ancestor's own predicate:\n{cascade}"
    );
    let only_tree = definers(&view("owner + some r in rules_live (@element prefix \"t.\" and parent)"));
    let cascade = only_tree.iter().find(|d| d.name == "doc_composition_parent").expect("the composition definer").create_sql();
    assert!(!cascade.contains("unnest("), "a some left with nothing inside is dropped whole:\n{cascade}");
}

#[test]
fn a_write_rule_that_repeats_the_read_rules_some_term_reaches_its_readers() {
    let some = "some r in rules_live held rules_held (named and not barred)";
    compile(&doc(&format!("  permission view = owner + {some} @rls maps select\n  permission edit = owner and (owner + {some}) @rls maps update")))
        .expect("the write is inside the read");
    let err = compile(&doc(&format!("  permission view = owner @rls maps select\n  permission edit = {some} @rls maps update")))
        .map(|_| ())
        .expect_err("a some the read lacks");
    assert!(err.contains("admits callers the select permission doc.view does not reach"), "{err}");
}

#[test]
fn the_reader_listing_carries_a_conditional_row_for_a_some_term() {
    let s = compile(&view("owner + some r in rules_live (named)")).expect("compiles");
    let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
    assert_eq!(rows.iter().map(|r| (r.source.as_str(), r.row_cond.as_str())).collect::<Vec<_>>(), [("some", "cardinality(rules_live) > 0")]);
}

#[test]
fn some_and_its_keyed_terms_are_refused_where_they_bind_nothing() {
    let cases = [
        ("a keyed relation outside a some", view("owner + named"), "uses keyed relation \"named\" outside a `some`"),
        ("an element test outside a some", view("owner and @element prefix \"x\""), "uses @element prefix \"x\" outside a `some`"),
        ("a some inside a some", view("some r in rules_live (named and some q in rules_live (second))"), "nests a `some` inside `some r`"),
        ("only an element test inside", view("some r in rules_live (@element prefix \"x\")"), "@element prefix \"x\" would admit a caller by itself"),
        ("only a negation inside", view("some r in rules_live (not barred)"), "whose brackets hold no positive term"),
        ("a containment term inside", view("some r in rules_live (@scoped and named)"), "uses @scoped inside `some r`"),
        ("an unknown relation inside", view("some r in rules_live (stranger)"), "stranger"),
    ];
    for (what, src, want) in cases {
        let err = compile(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
    let three = format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate\n  relation e: member via edge t(a, b, c) key k\n  permission view = @scoped @rls maps select\n}}\n"
    );
    assert!(demesne_syntax::parse(&three).expect_err("three columns").to_string().contains("a keyed edge names 2 columns (principal, object), got 3"));
}
