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
        "some r in rules_live prefix \"read.\" clear of rules_cleared (named)",
        "some r in rules_live held rules_held clear of rules_cleared (named and not barred)",
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
    assert_eq!((named.sig().as_str(), named.strict), ("p_principal text, p_object text, p_key text", true));
    assert_eq!(
        named.body,
        "p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub') AND (EXISTS (SELECT 1 FROM doc_edges WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key))",
        "the edge is the caller's own, never another principal's"
    );
    assert_eq!(
        get("doc_second_keyed").body,
        "p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub') AND (EXISTS (SELECT 1 FROM doc_edges WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key AND slot = '2'))"
    );
    assert_eq!(
        get("doc_barred_keyed").body,
        "p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub') AND (EXISTS (SELECT 1 FROM doc_bars WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key))"
    );
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

fn shared(expr: &str) -> String {
    format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation parent: member via composition docs(id, parent_id)\n  permission view = {expr} @rls maps select\n}}\n"
    )
}

fn listing_body(src: &str, name: &str) -> String {
    definers(src).into_iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} in\n{src}")).create_sql()
}

#[test]
fn a_union_of_conditions_alone_lists_only_its_conditional_rows() {
    let src = shared("@kind(\"auditor\") + (mode visibility = \"open\" and @claim(\"tier\", \"gold\"))");
    let s = compile(&src).expect("compiles");
    let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
    assert_eq!(
        rows.iter().map(|r| (r.source.as_str(), r.row_cond.as_str(), r.claims.iter().map(|c| c.key.as_str()).collect::<Vec<_>>())).collect::<Vec<_>>(),
        [("claim", "", vec!["kind"]), ("mode", "visibility = 'open'", vec!["tier"])],
        "{rows:#?}"
    );
    let listing = listing_body(&src, "docs_accessors_conditional");
    assert!(listing.contains("WHERE false"), "the union names nobody, so its own branch lists no row:\n{listing}");
    assert!(!listing.contains("'owner'::text"), "{listing}");
}

#[test]
fn a_some_naming_principals_lists_them_on_the_rows_it_binds_and_no_one_else() {
    let src = shared("some r in tags prefix \"open.\" ((owner and @claim(\"tier\", \"gold\")) + grantee:read)");
    let s = compile(&src).expect("compiles");
    let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
    assert!(rows.is_empty(), "the brackets name every caller they admit, so no row admits anyone: {rows:#?}");
    let listing = listing_body(&src, "docs_accessors");
    let bound = format!("EXISTS (SELECT 1 FROM unnest(tags) AS demesne_element(v) WHERE starts_with({EL}, 'open.'))");
    let named = format!("a(source, principal_kind, principal_id, access)\n    WHERE EXISTS (SELECT 1 FROM docs WHERE id = p_id AND {bound})");
    assert!(listing.contains(&named), "the owner is listed only where an element is bound:\n{listing}");
    assert!(listing.contains("'owner'::text, 'member'::text, owner_id"), "{listing}");

    for (what, expr) in [
        ("a composition inside", "some r in tags (owner + parent)"),
        ("an element test inside", "some r in tags ((@element prefix \"x.\" and owner) + grantee:read)"),
        ("conditions alone inside", "some r in tags (@kind(\"auditor\"))"),
    ] {
        let s = compile(&shared(expr)).unwrap_or_else(|e| panic!("{what}: {e}"));
        let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
        assert_eq!(
            rows.iter().map(|r| (r.source.as_str(), r.row_cond.as_str())).collect::<Vec<_>>(),
            [("some", "cardinality(tags) > 0")],
            "{what}: a some the listing can't name through stays one row admitting anyone it binds: {rows:#?}"
        );
    }
}

#[test]
fn a_condition_beside_the_principals_a_some_names_is_listed_on_the_rows_it_binds() {
    let bound = format!("EXISTS (SELECT 1 FROM unnest(tags) AS demesne_element(v) WHERE starts_with({EL}, 'open.'))");
    let src = shared("some r in tags prefix \"open.\" (owner + @kind(\"auditor\"))");
    let s = compile(&src).expect("compiles");
    let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
    assert_eq!(
        rows.iter().map(|r| (r.source.as_str(), r.row_cond.as_str(), r.claims.iter().map(|c| c.key.as_str()).collect::<Vec<_>>())).collect::<Vec<_>>(),
        [("claim", bound.as_str(), vec!["kind"])],
        "{rows:#?}"
    );

    let composed = shared("(owner and @row(status, \"open\")) + some r in tags prefix \"open.\" (grantee:read + @kind(\"auditor\"))");
    let listing = listing_body(&composed, "docs_accessors_conditional");
    let named = format!("a(source, principal_kind, principal_id, access)\n    WHERE EXISTS (SELECT 1 FROM docs WHERE id = p_id AND {bound})");
    assert!(listing.contains(&named), "a union that composes still names the grantees the some binds:\n{listing}");
}

#[test]
fn a_some_lists_the_branches_it_names_through_and_keeps_one_row_for_the_rest() {
    let src = shared("some r in tags prefix \"open.\" (owner + grantee:read + parent)");
    let s = compile(&src).expect("compiles");
    let rows = s.conditional_accessors(s.object_by_name("doc").expect("the object"));
    assert_eq!(
        rows.iter().map(|r| (r.source.as_str(), r.row_cond.as_str())).collect::<Vec<_>>(),
        [("some", "cardinality(tags) > 0")],
        "the composition can't be named through, so one row still admits every caller the term binds: {rows:#?}"
    );
    let listing = listing_body(&src, "docs_accessors_conditional");
    let bound = format!("EXISTS (SELECT 1 FROM unnest(tags) AS demesne_element(v) WHERE starts_with({EL}, 'open.'))");
    let named = format!("a(source, principal_kind, principal_id, access)\n    WHERE EXISTS (SELECT 1 FROM docs WHERE id = p_id AND {bound})");
    assert!(listing.contains(&named), "the others are named where an element is bound:\n{listing}");
    assert!(listing.contains("'owner'::text, 'member'::text, owner_id"), "the owner:\n{listing}");
    assert!(listing.contains("doc_acl"), "the grantees:\n{listing}");
}

#[test]
fn clear_of_binds_only_what_the_claims_list_leaves_out_and_nothing_without_a_list() {
    let src = view("owner + some r in rules_live prefix \"read.\" held rules_held clear of rules_cleared (named)");
    let s = compile(&src).expect("compiles");
    let sql = Sql::new(&s);
    let (sub, held, cleared) = (sql.claim("sub"), sql.claim("rules_held"), sql.claim_object("rules_cleared"));
    let using = select_using(&src);
    let want = format!(
        "EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE starts_with({EL}, 'read.') AND {EL} = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text({held}::jsonb) e)) AND jsonb_typeof({cleared}) = 'array' AND {EL} <> ALL(ARRAY(SELECT e FROM jsonb_array_elements_text({cleared}) e)) AND (auth.doc_named_keyed({sub}, docs.id, {EL})))"
    );
    assert!(using.contains(&want), "{using}");
    let borrowed = format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate > space\n{RELATIONS}  permission view = owner + some r in rules_live prefix \"read.\" clear of rules_cleared (named) @rls maps select\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  relation of: member via object doc->view on doc_id\n  permission view = of @rls maps select\n  export view as note_view_allowed(id text as row_id, estate_id text as row_estate_id, space_id text as row_space_id, doc_id text as row_doc_id)\n}}\n"
    );
    let body = definers(&borrowed).into_iter().find(|d| d.name == "doc_can_view").expect("the borrow's definer").body;
    assert!(
        body.contains("jsonb_typeof((demesne_call.claims -> 'rules_cleared')) = 'array' AND demesne_element.v <> ALL(ARRAY(SELECT e FROM jsonb_array_elements_text((demesne_call.claims -> 'rules_cleared')) e))"),
        "the definer reads the list from the claims it binds once a call:\n{body}"
    );
}

fn policy_using(src: &str, name: &str) -> String {
    let s = compile(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    Sql::new(&s).emit_rls().expect("the policies compile").policies.into_iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no policy {name}")).using
}

#[test]
fn a_some_whose_body_reads_no_element_tests_its_bounds_before_its_body() {
    let src = view("some r in rules_live prefix \"read.\" held rules_held (parent + mode visibility = \"listed\")");
    let s = compile(&src).expect("compiles");
    let held = Sql::new(&s).claim("rules_held");
    let using = select_using(&src);
    let want = format!(
        "(EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE starts_with({EL}, 'read.') AND {EL} = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text({held}::jsonb) e))) AND (auth.doc_composition_parent(docs.id, 'read') OR visibility = 'listed') IS TRUE)"
    );
    assert!(using.contains(&want), "{using}");
    let bare = select_using(&view("some r in rules_live (mode visibility = \"listed\")"));
    assert!(bare.contains("(EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v)) AND (visibility = 'listed') IS TRUE)"), "{bare}");
}

#[test]
fn a_some_whose_body_reads_its_element_in_any_branch_keeps_the_body_beside_its_bounds() {
    let using = select_using(&view("some r in rules_live prefix \"read.\" ((@element prefix \"read.e.\" and parent) + mode visibility = \"listed\")"));
    assert!(
        using.contains("EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE starts_with(demesne_element.v, 'read.') AND ("),
        "{using}"
    );
    assert!(!using.contains("IS TRUE"), "the body stays inside the element scan:\n{using}");
    let keyed = select_using(&view("some r in rules_live (named + mode visibility = \"listed\")"));
    assert!(keyed.contains("WHERE (auth.doc_named_keyed(") && !keyed.contains("IS TRUE"), "a keyed term reads the element:\n{keyed}");
}

#[test]
fn a_negated_some_whose_body_reads_no_element_counts_an_unknown_body_as_holding() {
    let src = doc(
        "  permission view = owner + some r in rules_live (mode visibility = \"listed\") @rls maps select\n  permission edit = owner and not some r in rules_live prefix \"read.\" (mode state = \"locked\") @rls maps update",
    );
    let using = policy_using(&src, "docs_update");
    assert!(
        using.contains("((EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE starts_with(demesne_element.v, 'read.')) AND (state = 'locked') IS NOT FALSE)) IS NOT TRUE"),
        "{using}"
    );
}
