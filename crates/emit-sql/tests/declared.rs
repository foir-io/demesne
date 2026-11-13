use demesne_emit_sql::{GenFn, Sql};

const HEAD: &str =
    "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\n";
const RELATIONS: &str = "  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation edge_slot: member via edge doc_edges(principal_id, object_id) key rule_id slot slot\n  relation by_part: member via edge doc_edges(principal_id, object_id) key rule_id slot part from slot\n  relation borrow: member via composition doc_reads(descendant_id, ancestor_id) slot first_field from param\n";

fn view(expr: &str) -> String {
    format!("{HEAD}object doc {{\n  table docs\n  scoped estate > space\n{RELATIONS}  permission view = {expr} @rls maps select\n}}\n")
}

fn compile(src: &str) -> Result<demesne_syntax::Spec, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

fn emitted(src: &str) -> (String, Vec<GenFn>) {
    let s = compile(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let using = sql.emit_rls().expect("the policies compile").policies.into_iter().find(|p| p.name == "docs_select").expect("a select policy").using;
    (using.replace(&sql.claim("sub"), "SUB"), sql.emit_definers().expect("the definers compile"))
}

const ROWS: &str = "auth.rule_slots_declared_by_rule_id(demesne_element.v) AS demesne_slot";

#[test]
fn the_terms_display_as_written() {
    let expr = "some r in rules_live (every s in rule_slots(rule_id) where role = \"require\" (@slot(kind, \"edge\") and edge_slot) and none s in rule_slots(rule_id) (@slot(kind, \"edge\") and edge_slot))";
    assert_eq!(compile(&view(expr)).expect("compiles").objects[0].perms[0].tree.display(), expr);
}

#[test]
fn every_refuses_when_a_declared_row_fails_and_none_when_one_matches() {
    let (using, _) = emitted(&view(
        "some r in rules_live (every s in rule_slots(rule_id) where role = \"require\" ((@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"grant\") and grantee:read)) and none s in rule_slots(rule_id) where role = \"except\" (@slot(kind, \"edge\") and edge_slot))",
    ));
    let edge = "(demesne_slot.kind = 'edge') AND (auth.doc_edge_slot_keyed(SUB, docs.id, demesne_element.v, demesne_slot.slot))";
    let every = format!(
        "NOT EXISTS (SELECT 1 FROM {ROWS} WHERE demesne_slot.role = 'require' AND ({edge} OR (demesne_slot.kind = 'grant') AND (auth.doc_acl_grants(SUB, docs.id, 'read'))) IS NOT TRUE)"
    );
    let none = format!("NOT EXISTS (SELECT 1 FROM {ROWS} WHERE demesne_slot.role = 'except' AND ({edge}) IS NOT FALSE)");
    assert!(using.contains(&format!("WHERE (({every}) AND ({none}))")), "{using}");
    let (unfiltered, _) = emitted(&view("some r in rules_live (every s in rule_slots(rule_id) (@slot(kind, \"edge\") and edge_slot))"));
    assert!(unfiltered.contains(&format!("NOT EXISTS (SELECT 1 FROM {ROWS} WHERE ({edge}) IS NOT TRUE)")), "{unfiltered}");
}

#[test]
fn the_declared_rows_come_through_one_definer_that_returns_only_the_columns_the_spec_reads() {
    let (_, defs) = emitted(&view(
        "some r in rules_live (every s in rule_slots(rule_id) where role = \"require\" ((@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"borrow\") and borrow)) and none s in rule_slots(rule_id) where role = \"except\" (@slot(kind, \"edge\") and by_part))",
    ));
    let rows: Vec<&GenFn> = defs.iter().filter(|d| d.name.starts_with("rule_slots_declared")).collect();
    assert_eq!(rows.len(), 1, "one definer for the table and key");
    let f = rows[0];
    assert_eq!((f.name.as_str(), f.sig.as_str(), f.strict), ("rule_slots_declared_by_rule_id", "p_key text", true));
    assert_eq!(f.returns, "TABLE(kind text, param text, role text, slot text)");
    assert_eq!(
        f.body,
        "  SELECT rule_slots.kind::text, rule_slots.param::text, rule_slots.role::text, rule_slots.slot::text FROM rule_slots WHERE rule_slots.rule_id = p_key;"
    );
}

#[test]
fn a_slot_binds_into_a_keyed_edge_and_into_the_hops_a_composition_follows() {
    let (using, defs) =
        emitted(&view("some r in rules_live (every s in rule_slots(rule_id) ((@slot(kind, \"edge\") and by_part) + (@slot(kind, \"borrow\") and borrow)))"));
    let get = |name: &str| defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"));
    let edge = get("doc_by_part_keyed");
    assert_eq!(edge.sig, "p_principal text, p_object text, p_key text, p_slot text");
    assert_eq!(
        edge.body,
        "EXISTS (SELECT 1 FROM doc_edges WHERE principal_id = p_principal AND object_id = p_object AND rule_id = p_key AND part::text = p_slot)"
    );
    assert!(
        using.contains("auth.doc_by_part_keyed(SUB, docs.id, demesne_element.v, demesne_slot.slot)"),
        "the edge's column is matched against the declared column named after `from`:\n{using}"
    );
    assert_eq!(get("doc_named_keyed").sig, "p_principal text, p_object text, p_key text", "an edge with no slot keeps three arguments");
    let borrow = get("doc_composition_borrow");
    assert_eq!(borrow.sig, "p_doc_id text, p_access text, p_slot text");
    assert!(borrow.arms[0].body.starts_with("EXISTS (SELECT 1 FROM doc_reads e WHERE e.descendant_id = p_doc_id AND e.first_field::text = p_slot AND EXISTS (SELECT 1 FROM docs WHERE docs.id = e.ancestor_id AND "), "{}", borrow.arms[0].body);
    assert!(using.contains("auth.doc_composition_borrow(docs.id, 'read', demesne_slot.param)"), "{using}");
}

#[test]
fn the_cascade_judges_an_ancestor_without_the_branches_that_need_a_composition() {
    let (_, defs) = emitted(&view(
        "owner + some r in rules_live (every s in rule_slots(rule_id) ((@slot(kind, \"edge\") and edge_slot) + (@slot(kind, \"borrow\") and borrow)))",
    ));
    let arm = &defs.iter().find(|d| d.name == "doc_composition_borrow").expect("the cascade").arms[0].body;
    assert!(arm.contains("doc_edge_slot_keyed(") && arm.contains(ROWS), "the ancestor still admits by its declared edges:\n{arm}");
    assert!(!arm.contains("doc_composition_borrow(") && !arm.contains("demesne_slot.kind = 'borrow'"), "{arm}");
    let (_, barred) = emitted(&view(
        "owner + some r in rules_live (named and none s in rule_slots(rule_id) where role = \"except\" ((@slot(kind, \"borrow\") and borrow) + (@slot(kind, \"edge\") and edge_slot)))",
    ));
    let arm = &barred.iter().find(|d| d.name == "doc_composition_borrow").expect("the cascade").arms[0].body;
    assert!(
        arm.contains(&format!("NOT EXISTS (SELECT 1 FROM {ROWS} WHERE demesne_slot.role = 'except' AND ((demesne_slot.kind = 'borrow') OR (demesne_slot.kind = 'edge') AND (auth.doc_edge_slot_keyed(")),
        "at the ancestor a declared exception that needs a composition bars by being declared, since one hop cannot tell whether it matches:\n{arm}"
    );
    let (_, every) = emitted(&view("owner + some r in rules_live (named and every s in rule_slots(rule_id) (@slot(kind, \"borrow\") and borrow))"));
    let arm = &every.iter().find(|d| d.name == "doc_composition_borrow").expect("the cascade").arms[0].body;
    assert!(!arm.contains("unnest("), "an `every` that can be met only through a composition is never met at the ancestor, so its `some` goes:\n{arm}");
}

#[test]
fn declared_scopes_and_slot_terms_are_refused_where_they_bind_nothing() {
    let cases = [
        ("every outside a some", view("owner and every s in rule_slots(rule_id) (@slot(kind, \"edge\") and named)"), "outside a `some`"),
        (
            "a slot test outside every",
            view("some r in rules_live (named and @slot(kind, \"edge\"))"),
            "uses @slot(kind, \"edge\") outside an `every` or `none`",
        ),
        ("a slot-bound edge outside every", view("some r in rules_live (edge_slot)"), "uses slot-bound relation \"edge_slot\" outside an `every` or `none`"),
        ("a slot-bound composition outside every", view("some r in rules_live (borrow)"), "uses slot-bound relation \"borrow\" outside an `every` or `none`"),
        (
            "every inside every",
            view("some r in rules_live (every s in rule_slots(rule_id) (edge_slot and every t in rule_slots(rule_id) (edge_slot)))"),
            "nests every t in rule_slots(rule_id) (edge_slot) inside `every s`",
        ),
        (
            "only a slot test inside",
            view("some r in rules_live (every s in rule_slots(rule_id) (@slot(kind, \"edge\")))"),
            "@slot(kind, \"edge\") would admit a caller by itself",
        ),
        (
            "only a negation inside",
            view("some r in rules_live (named and none s in rule_slots(rule_id) (not edge_slot))"),
            "uses `none s` whose brackets hold no positive term",
        ),
        ("a containment term inside", view("some r in rules_live (every s in rule_slots(rule_id) (@scoped and edge_slot))"), "uses @scoped inside `every s`"),
    ];
    for (what, src, want) in cases {
        let err = compile(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}
