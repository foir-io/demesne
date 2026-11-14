use demesne_emit_sql::{GenFn, Language, Sql};

const HEAD: &str = "topology { level estate }\nsubject member { anchor estate; reach self; identifies sub; roles none }\n";
const HOPS: &str = "(every h in doc_trail_hops(trail) ((@slot(kind, \"claim\") and @slot(rule held rules_held)) + (@slot(kind, \"live\") and @holds_at(doc_id, rule slot field))))";
const VIEW: &str = "some r in rules_live held rules_held (every s in rule_slots(rule) where role = \"require\" ((@slot(kind, \"edge\") and shared) + (@slot(kind, \"lend\") and lent) + (@slot(kind, \"tree\") and under)) and none s in rule_slots(rule) where role = \"except\" (@slot(kind, \"lend\") and lent))";

fn path() -> String {
    format!("path trail along {HOPS}")
}

fn spec(nested: &str, path: &str, view: &str) -> String {
    let tree = if path.is_empty() { String::new() } else { format!("path seen along {}", HOPS.replace(" slot field", "")) };
    format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate\n{nested}\n  relation shared: member via edge doc_shares(member_id, doc_id) key rule\n  relation lent: member via composition doc_lends(borrower_id, lender_id) slot field from param {path}\n  relation under: member via composition doc_tree(below_id, above_id) {tree}\n  permission view = {view} @rls maps select\n}}\n"
    )
}

fn compiled(src: &str) -> Result<(String, Vec<GenFn>), String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    let sql = Sql::new(&s);
    let using = sql.emit_rls().map_err(|e| e.to_string())?.policies.into_iter().find(|p| p.name == "docs_select").ok_or("no select policy")?.using;
    let claims = |text: &str| text.replace(&sql.claim("sub"), "SUB").replace(&sql.claim("rules_held"), "HELD").replace(&sql.claim("estate_id"), "ESTATE");
    let defs = sql.emit_definers().map_err(|e| e.to_string())?;
    Ok((
        claims(&using),
        defs.into_iter()
            .map(|d| GenFn {
                body: claims(&d.body),
                arms: d.arms.into_iter().map(|a| demesne_emit_sql::DefinerArm { body: claims(&a.body), ..a }).collect(),
                ..d
            })
            .collect(),
    ))
}

fn emitted(nested: &str) -> (String, Vec<GenFn>) {
    let src = spec(nested, &path(), VIEW);
    compiled(&src).unwrap_or_else(|e| panic!("{e}\n{src}"))
}

fn named<'a>(defs: &'a [GenFn], name: &str) -> &'a GenFn {
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} among {:?}", defs.iter().map(|d| &d.name).collect::<Vec<_>>()))
}

fn holds(text: &str, parts: &[&str]) {
    for part in parts {
        assert!(text.contains(part), "missing `{part}` in:\n{text}");
    }
}

fn lacks(text: &str, parts: &[&str]) {
    for part in parts {
        assert!(!text.contains(part), "unexpected `{part}` in:\n{text}");
    }
}

const EXCEPT: &str = "demesne_slot.role = 'except' AND ((demesne_slot.kind = 'lend') AND";

#[test]
fn the_terms_display_as_written() {
    let s = demesne_syntax::parse(&spec("  nested 2", &path(), VIEW)).expect("parses");
    let demesne_syntax::Repr::Composition(vc) = &s.objects[0].relations[1].repr else { panic!("a composition") };
    let path = vc.path.as_ref().expect("a path");
    assert_eq!((path.col_for("select"), path.col_for("delete"), s.objects[0].nested), (Some("trail"), Some("trail"), Some(2)));
    assert_eq!(
        path.along.display(),
        "every h in doc_trail_hops(trail) (@slot(kind, \"claim\") and @slot(rule held rules_held) + @slot(kind, \"live\") and @holds_at(doc_id, rule slot field))"
    );
    let per_op = demesne_syntax::parse(&spec("  nested 0", &self::path().replace("path trail", "path select seen, update changed"), VIEW)).expect("parses");
    let demesne_syntax::Repr::Composition(vc) = &per_op.objects[0].relations[1].repr else { panic!("a composition") };
    let path = vc.path.as_ref().expect("a path");
    assert_eq!((path.col_for("select"), path.col_for("update"), path.col_for("delete")), (Some("seen"), Some("changed"), None));
}

#[test]
fn the_policy_follows_a_composition_that_widens_by_its_lower_bound_and_one_that_narrows_by_its_upper() {
    let (using, _) = emitted("  nested 1");
    holds(
        &using,
        &[
            "(demesne_slot.kind = 'lend') AND (auth.doc_composition_lent(docs.id, 'read', demesne_slot.param))",
            "(demesne_slot.kind = 'tree') AND (auth.doc_composition_under(docs.id, 'read'))) IS NOT TRUE)",
            &format!("{EXCEPT} (auth.doc_composition_lent_upper(docs.id, 'read', demesne_slot.param))) IS NOT FALSE)"),
        ],
    );
}

const ALONG: &str = " THEN (NOT EXISTS (SELECT 1 FROM auth.doc_trail_hops_declared_by_trail(";
const HOP: &str = "(SELECT CASE WHEN demesne_hop.record IS NULL OR demesne_hop.element IS NULL";

fn own_and_hop<'a>(defs: &'a [GenFn], name: &str) -> (&'a str, &'a str) {
    let arm = &named(defs, name).arms[0].body;
    let (own, along) = arm.split_once(ALONG).unwrap_or_else(|| panic!("no path in {arm}"));
    let at = along.find(HOP).unwrap_or_else(|| panic!("no hop judged in {along}"));
    (own, &along[at..])
}

#[test]
fn a_hop_counts_only_when_every_row_declared_for_its_path_key_holds() {
    let (_, defs) = emitted("  nested 1");
    let followed = &named(&defs, "doc_composition_lent").arms[0].body;
    assert!(followed.starts_with("EXISTS (SELECT 1 FROM doc_lends e WHERE e.borrower_id = p_doc_id AND e.field::text = p_slot AND CASE WHEN EXISTS (SELECT 1 FROM docs WHERE docs.id = e.lender_id AND ((estate_id = ESTATE AND"), "{followed}");
    holds(
        followed,
        &[&format!(
            "{ALONG}e.trail::text) AS demesne_slot WHERE (((demesne_slot.kind = 'claim') AND (demesne_slot.rule = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text(HELD::jsonb) e)))) OR ((demesne_slot.kind = 'live') AND ({HOP} OR demesne_hop.slot IS NULL THEN NULL ELSE EXISTS (SELECT 1 FROM docs WHERE docs.id = demesne_hop.record AND "
        )],
    );
    assert!(
        followed.ends_with(" END FROM (SELECT demesne_slot.doc_id AS record, demesne_slot.rule AS element, demesne_slot.field AS slot) AS demesne_hop)))) IS NOT TRUE)) ELSE false END)"),
        "{followed}"
    );
    let (own, _) = own_and_hop(&defs, "doc_composition_lent");
    holds(own, &[&format!("{EXCEPT} (auth.doc_composition_lent_0_upper(docs.id, 'read', demesne_slot.param))) IS NOT FALSE)")]);
    lacks(own, &["demesne_slot.kind = 'tree'", "auth.doc_composition_lent(", "auth.doc_composition_under"]);
    let (lowest, _) = own_and_hop(&defs, "doc_composition_lent_0");
    holds(lowest, &["demesne_slot.role = 'except' AND ((demesne_slot.kind = 'lend')) IS NOT FALSE)"]);
    let tree = &named(&defs, "doc_composition_under").arms[0].body;
    holds(
        tree,
        &["doc_trail_hops_declared_by_trail(e.seen::text)", " END FROM (SELECT demesne_slot.doc_id AS record, demesne_slot.rule AS element) AS demesne_hop)"],
    );
    let rows = named(&defs, "doc_trail_hops_declared_by_trail");
    assert_eq!(rows.returns, "TABLE(doc_id text, field text, kind text, rule text)");
}

#[test]
fn a_hop_is_judged_with_its_own_composition_taken_as_followed_and_the_others_one_level_down() {
    let (_, defs) = emitted("  nested 1");
    let (_, lent) = own_and_hop(&defs, "doc_composition_lent");
    holds(
        lent,
        &[
            "EXISTS (SELECT 1 FROM docs WHERE docs.id = demesne_hop.record AND estate_id = ESTATE AND (EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE demesne_element.v = demesne_hop.element AND demesne_element.v = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text(HELD::jsonb) e)) AND ",
            "(demesne_slot.kind = 'lend') AND ((demesne_slot.param = demesne_hop.slot OR auth.doc_composition_lent_0(docs.id, 'read', demesne_slot.param)))",
            "(demesne_slot.kind = 'tree') AND (auth.doc_composition_under_0(docs.id, 'read'))",
            &format!(
                "{EXCEPT} ((demesne_slot.param = demesne_hop.slot OR auth.doc_composition_lent_0_upper(docs.id, 'read', demesne_slot.param)))) IS NOT FALSE)"
            ),
        ],
    );
    let (_, lowest) = own_and_hop(&defs, "doc_composition_lent_0");
    holds(lowest, &["(demesne_slot.kind = 'lend') AND (demesne_slot.param = demesne_hop.slot)", &format!("{EXCEPT} (true)) IS NOT FALSE)")]);
    lacks(lowest, &["demesne_slot.kind = 'tree'", "auth.doc_composition"]);
    let (_, tree) = own_and_hop(&defs, "doc_composition_under");
    lacks(tree, &["demesne_hop.slot"]);
    holds(
        tree,
        &["(demesne_slot.kind = 'tree') AND (true)", "(demesne_slot.kind = 'lend') AND (auth.doc_composition_lent_0(docs.id, 'read', demesne_slot.param))"],
    );
    let whole = named(&defs, "doc_select_holds_at");
    assert_eq!((whole.sig.as_str(), whole.strict), ("p_record text, p_element text", true));
    assert!(whole.body.starts_with("EXISTS (SELECT 1 FROM docs WHERE docs.id = p_record AND estate_id = ESTATE AND (EXISTS (SELECT 1 FROM unnest(docs.rules_live) AS demesne_element(v) WHERE demesne_element.v = p_element AND "), "{}", whole.body);
    holds(
        &whole.body,
        &[
            "auth.doc_composition_lent(docs.id, 'read', demesne_slot.param)",
            "auth.doc_composition_under(docs.id, 'read')",
            "auth.doc_composition_lent_upper(docs.id, 'read', demesne_slot.param)",
        ],
    );
}

#[test]
fn an_upper_bound_counts_what_cannot_be_decided_and_what_lies_deeper_than_the_nesting() {
    let (_, defs) = emitted("  nested 1");
    let (_, lowest) = own_and_hop(&defs, "doc_composition_lent_0_upper");
    holds(
        lowest,
        &[
            "(demesne_slot.kind = 'lend') AND (true)",
            "OR (demesne_slot.kind = 'tree')) IS FALSE)",
            &format!("{EXCEPT} (demesne_slot.param = demesne_hop.slot)) IS TRUE)"),
            " IS NOT FALSE))) END FROM (SELECT demesne_slot.doc_id AS record",
        ],
    );
    let (own, above) = own_and_hop(&defs, "doc_composition_lent_upper");
    holds(
        above,
        &[
            "(demesne_slot.param = demesne_hop.slot OR auth.doc_composition_lent_0_upper(docs.id, 'read', demesne_slot.param))",
            "auth.doc_composition_under_0_upper(docs.id, 'read')",
            &format!("{EXCEPT} ((demesne_slot.param = demesne_hop.slot OR auth.doc_composition_lent_0(docs.id, 'read', demesne_slot.param)))) IS TRUE)"),
        ],
    );
    assert!(own.ends_with(" IS NOT FALSE)"), "{own}");
    assert!(above.ends_with(" AS demesne_hop)))) IS FALSE)) ELSE false END)"), "{above}");
    lacks(own, &["demesne_slot.kind = 'tree'", "demesne_hop"]);
}

#[test]
fn only_the_functions_something_calls_are_emitted_and_those_a_chain_calls_keep_their_plans() {
    let names = |defs: &[GenFn]| {
        defs.iter().map(|d| d.name.clone()).filter(|n| n.contains("holds_at") || n.contains("composition")).collect::<std::collections::BTreeSet<_>>()
    };
    let languages = |defs: &[GenFn]| ["doc_shared_keyed", "rule_slots_declared_by_rule", "doc_select_holds_at"].map(|n| named(defs, n).language);
    let widening = "some r in rules_live held rules_held (every s in rule_slots(rule) ((@slot(kind, \"edge\") and shared) + (@slot(kind, \"lend\") and lent) + (@slot(kind, \"tree\") and under)))";
    let src = spec("  nested 1", &path(), widening);
    let (_, defs) = compiled(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    assert_eq!(
        names(&defs).into_iter().collect::<Vec<_>>(),
        ["doc_composition_lent", "doc_composition_lent_0", "doc_composition_under", "doc_composition_under_0", "doc_select_holds_at"],
        "nothing narrows by a composition, so no upper bound is emitted, and a hop is judged where it is followed"
    );
    assert_eq!(languages(&defs), [Language::Plpgsql, Language::Plpgsql, Language::Sql]);
    let edge = named(&defs, "doc_shared_keyed").create_sql();
    assert!(edge.ends_with("AS $$\n#variable_conflict use_column\nBEGIN\n  RETURN EXISTS (SELECT 1 FROM doc_shares WHERE member_id = p_principal AND doc_id = p_object AND rule = p_key);\nEND\n$$;"), "{edge}");
    let rows = named(&defs, "rule_slots_declared_by_rule").create_sql();
    assert!(
        rows.ends_with("BEGIN\n  RETURN QUERY SELECT rule_slots.kind::text, rule_slots.param::text FROM rule_slots WHERE rule_slots.rule = p_key;\nEND\n$$;"),
        "{rows}"
    );
    let src = spec("", "", widening);
    let (_, defs) = compiled(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    assert_eq!(
        names(&defs).into_iter().collect::<Vec<_>>(),
        ["doc_composition_lent", "doc_composition_under"],
        "a spec with no path and no nesting emits what it did"
    );
    assert_eq!([named(&defs, "doc_shared_keyed").language, named(&defs, "rule_slots_declared_by_rule").language], [Language::Sql, Language::Sql]);
}

#[test]
fn a_chain_is_refused_where_nothing_could_judge_it() {
    let hop = "@holds_at(doc_id, rule slot field)";
    let cases = [
        ("a path with no nesting", spec("", &path(), VIEW), "declares a `path`, but the object declares no `nested <n>`"),
        ("nesting with no some", spec("  nested 1", "", "shared"), "declares `nested`, but no permission of it holds a `some`"),
        ("a path of something else", spec("  nested 0", "path trail along (@kind(\"x\"))", VIEW), "a path holds `every` and `none` terms"),
        (
            "a hop tested by a relation",
            spec("  nested 0", "path trail along (every h in doc_trail_hops(trail) (@slot(kind, \"live\") and shared))", VIEW),
            "a hop is tested with `@slot` and `@holds_at`",
        ),
        (
            "an unknown operation",
            spec("  nested 0", &path().replace(hop, "@holds_at(doc_id, rule slot field for insert)"), VIEW),
            "\"insert\" is not select, update or delete",
        ),
        (
            "an operation that judges no element",
            spec("  nested 0", &path().replace(hop, "@holds_at(doc_id, rule slot field for update)"), VIEW),
            "no permission that maps update holds a `some`",
        ),
        (
            "a slot-bound composition's hop naming no slot",
            spec("  nested 0", &path().replace(hop, "@holds_at(doc_id, rule)"), VIEW),
            "so a hop says which slot it follows",
        ),
        (
            "two columns for one operation",
            spec("  nested 0", &path().replace("path trail", "path select a, select b"), VIEW),
            "names two path columns for \"select\"",
        ),
        ("no column for a mapped operation", spec("  nested 0", &path().replace("path trail", "path update a"), VIEW), "names no path column for select"),
        ("holds_at beside a some", spec("  nested 0", &path(), &format!("{VIEW} and @holds_at(a, b)")), "outside a composition's `path`"),
        (
            "holds_at outside a path",
            spec("  nested 0", &path(), &VIEW.replace("(@slot(kind, \"lend\") and lent))", "(@holds_at(a, b) and lent))")),
            "outside a composition's `path`",
        ),
    ];
    for (what, src, want) in cases {
        let err = compiled(&src).map(|(using, _)| using).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}

#[test]
fn a_write_that_repeats_the_read_rule_is_reached_by_it_unless_a_composition_narrows() {
    let edit = |view: &str| {
        let written = view.replacen("some r in rules_live", "some w in rules_live prefix \"w.\"", 1);
        spec("  nested 0", &path(), view)
            .replace("@rls maps select\n", &format!("@rls maps select\n  permission edit = {written} and {view} @rls maps update\n"))
            .replace(" slot field))))", " slot field for select))))")
    };
    let widening = "some r in rules_live held rules_held (every s in rule_slots(rule) ((@slot(kind, \"edge\") and shared) + (@slot(kind, \"lend\") and lent)))";
    compiled(&edit(widening)).unwrap_or_else(|e| panic!("a composition followed for write reaches no further than for read: {e}"));
    let err = compiled(&edit(VIEW)).map(|(using, _)| using).expect_err("an exception by a composition is weaker for write than for read");
    assert!(err.contains("admits callers the select permission doc.view does not reach"), "{err}");
}

#[test]
fn a_composition_under_not_is_followed_by_its_upper_bound_and_a_declared_row_is_tested_against_a_claim() {
    let view = "some r in rules_live held rules_held (every s in rule_slots(rule) (@slot(kind held kinds_held) and shared) and not under)";
    let src = spec("  nested 0", &path(), view);
    let s = demesne_syntax::parse(&src).expect("parses");
    let kinds = Sql::new(&s).claim("kinds_held");
    let (using, defs) = compiled(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let using = using.replace(&kinds, "KINDS");
    holds(
        &using,
        &[
            "(demesne_slot.kind = ANY(ARRAY(SELECT e FROM jsonb_array_elements_text(KINDS::jsonb) e))) AND (auth.doc_shared_keyed(SUB, docs.id, demesne_element.v))",
            "AND ((auth.doc_composition_under_upper(docs.id, 'read')) IS NOT TRUE)",
        ],
    );
    assert_eq!(named(&defs, "rule_slots_declared_by_rule").returns, "TABLE(kind text)");
    lacks(&using, &["auth.doc_composition_under(docs.id"]);
    let never = &named(&defs, "doc_composition_under").arms[0].body;
    assert!(never.contains("WHERE docs.id = e.above_id AND (false))"), "an own rule that an exception always bars admits nobody:\n{never}");
}
