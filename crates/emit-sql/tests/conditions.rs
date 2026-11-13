use demesne_emit_sql::{GenFn, Sql};

const HEAD: &str = "topology { level estate }\nsubject member { anchor estate; reach self; identifies sub; roles none; binds owner }\n";
const RELATIONS: &str = "  relation owner: member via owner_id\n  relation named: member via edge doc_edges(principal_id, object_id) key rule_id\n  relation fits: member via conditions doc_terms(object_id, term, op) values (num, txt, at) on id from claim facts\n  relation matches: member via conditions rule_terms(object_id, term, op) values (num, txt, at, list, lat, lng) key rule_id on id from claim facts\n";

fn spec(head: &str, view: &str) -> String {
    format!("{head}{HEAD}object doc {{\n  table docs\n  scoped estate\n{RELATIONS}  permission view = {view} @rls maps select\n}}\n")
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
    (using, sql.emit_definers().expect("the definers compile"))
}

const VIEW: &str = "owner + (@kind(\"member\") and fits) + some r in rules_live (named and matches)";
const FACTS: &str = "(SELECT (current_setting('request.jwt.claims', true)::json -> 'facts')::jsonb)";

#[test]
fn the_policy_passes_the_row_the_element_and_the_callers_values_read_once() {
    let (using, defs) = emitted(&spec("", VIEW));
    assert!(using.contains(&format!("auth.doc_fits_hold(docs.id, {FACTS})")), "{using}");
    assert!(using.contains(&format!("auth.doc_matches_hold(docs.id, demesne_element.v, {FACTS})")), "{using}");
    let get = |name: &str| defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"));
    assert_eq!(get("doc_fits_hold").sig, "p_object text, p_values jsonb");
    assert_eq!(get("doc_matches_hold").sig, "p_object text, p_key text, p_values jsonb");
    assert_eq!(defs.iter().filter(|d| d.name == "demesne_instant").count(), 1, "one instant parser for the spec");
}

#[test]
fn the_function_is_false_when_a_condition_fails_and_unknown_when_one_cannot_be_decided() {
    let (_, defs) = emitted(&spec("", VIEW));
    let keyed = &defs.iter().find(|d| d.name == "doc_matches_hold").expect("the function").body;
    let lacking: Vec<&str> = [
        "BEGIN\n  IF p_object IS NULL THEN\n    RETURN NULL;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM rule_terms c WHERE c.object_id = p_object AND c.rule_id = p_key) THEN\n    RETURN true;\n  END IF;",
        "RETURN (SELECT CASE WHEN bool_or(h.holds IS FALSE) THEN false WHEN bool_or(h.holds IS NULL) THEN NULL ELSE true END",
        "SELECT (CASE c.op",
        "END) AS holds",
        "FROM rule_terms c CROSS JOIN LATERAL (",
        "WHERE c.object_id = p_object AND c.rule_id = p_key\n  ) h);\nEND",
        "WHEN 'eq' THEN CASE WHEN c.num IS NOT NULL THEN c.num = x.num WHEN c.at IS NOT NULL THEN c.at = x.at ELSE c.txt = x.txt COLLATE \"C\" END",
        "WHEN 'lt' THEN CASE WHEN c.num IS NOT NULL THEN c.num < x.num WHEN c.at IS NOT NULL THEN c.at < x.at END",
        "WHEN 'not_in' THEN NOT (CASE WHEN jsonb_typeof(x.v) = 'array' THEN EXISTS (",
        "WHEN 'includes' THEN x.scalar = ANY(c.list)",
        "WHEN 'not_includes' THEN CASE WHEN x.scalar IS NOT NULL AND c.list IS NOT NULL THEN NOT (x.scalar = ANY(c.list)) END",
        "WHEN 'not_contains' THEN CASE WHEN x.txt IS NOT NULL AND c.txt IS NOT NULL THEN NOT (strpos(c.txt, x.txt) > 0) END",
        "WHEN 'caller_prefix' THEN starts_with(x.txt, c.txt)",
        "WHEN 'suffix' THEN right(c.txt, length(x.txt)) = x.txt COLLATE \"C\"",
        "WHEN 'not_before' THEN now() >= c.at",
        "WHEN 'not_after' THEN now() <= c.at",
        "CASE WHEN jsonb_typeof(p_values -> c.term) = 'number' THEN (p_values ->> c.term)::double precision END AS num",
        "THEN auth.demesne_instant(p_values ->> c.term) END AS at",
        "THEN 6371.0 * 2 * atan2(sqrt(least(1.0, (sin(radians(x.lat - c.lat) / 2) ^ 2 + cos(radians(c.lat)) * cos(radians(x.lat)) * sin(radians(x.lng - c.lng) / 2) ^ 2))), sqrt(greatest(0.0, 1.0 - (",
        "<= c.num END",
        "c.lat BETWEEN -90 AND 90 AND c.lng BETWEEN -180 AND 180 AND x.lat BETWEEN -90 AND 90 AND x.lng BETWEEN -180 AND 180 AND c.num >= 0",
    ]
    .into_iter()
    .filter(|frag| !keyed.contains(frag))
    .collect();
    assert_eq!(lacking, [] as [&str; 0], "{keyed}");
    let per_operator = &keyed[keyed.find("SELECT (CASE c.op").expect("the operators")..keyed.find("END) AS holds").expect("their end")];
    assert!(!per_operator.contains("ELSE true") && !per_operator.contains("ELSE false"), "an operator that cannot decide answers neither way:\n{per_operator}");
    let plain = &defs.iter().find(|d| d.name == "doc_fits_hold").expect("the function").body;
    assert!(
        plain.contains("WHERE c.object_id = p_object\n  ) h);") && plain.contains("FROM doc_terms c WHERE c.object_id = p_object) THEN\n    RETURN true;"),
        "an unkeyed relation matches the row alone:\n{plain}"
    );
    assert!(!plain.contains("within_km") && !plain.contains("'includes'"), "an operator whose columns the relation does not name is not offered:\n{plain}");
}

#[test]
fn postgis_is_used_for_distance_only_when_the_spec_declares_it_and_in_the_schema_it_names() {
    let distance = |head: &str| {
        let (_, defs) = emitted(&spec(head, VIEW));
        let body = &defs.iter().find(|d| d.name == "doc_matches_hold").expect("the function").body;
        body.lines().find(|l| l.contains("WHEN 'within_km'")).expect("the operator").to_string()
    };
    assert!(distance("").contains("atan2(") && !distance("").contains("ST_"), "{}", distance(""));
    let public = distance("extension postgis\n");
    assert!(
        public.ends_with("THEN public.ST_DWithin(public.ST_SetSRID(public.ST_MakePoint(c.lng, c.lat), 4326)::public.geography, public.ST_SetSRID(public.ST_MakePoint(x.lng, x.lat), 4326)::public.geography, c.num * 1000.0) END"),
        "{public}"
    );
    assert!(!public.contains("atan2("), "{public}");
    assert!(distance("extension postgis schema \"extensions\"\n").contains("extensions.ST_DWithin(extensions.ST_SetSRID("));
    assert!(distance("extension pgcrypto\n").contains("atan2("), "another extension changes nothing");
}

#[test]
fn stored_conditions_only_narrow_and_keyed_ones_need_an_element() {
    let cases = [
        ("alone", spec("", "owner + fits"), "uses fits where it would admit a caller by itself — stored conditions hold for a row that stores none"),
        ("beside only a row test", spec("", "owner + (fits and @row(kind, \"note\"))"), "uses fits where it would admit a caller by itself"),
        ("negated and alone", spec("", "owner + (not fits)"), "is not positively gated"),
        ("alone in a some", spec("", "owner + some r in rules_live (matches)"), "uses `some r` in which matches would admit a caller by itself"),
        ("keyed outside a some", spec("", "owner + (@kind(\"member\") and matches)"), "uses keyed relation \"matches\" outside a `some`"),
    ];
    for (what, src, want) in cases {
        let err = compile(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
    compile(&spec("", "owner + (@kind(\"member\") and fits and not @row(kind, \"draft\"))")).expect("beside a term that grants");
    for (bad, want) in [
        ("via conditions t(a, b) values (n, t, a) on id from claim c", "names 3 columns (object, term, operator), got 2"),
        ("via conditions t(a, b, c) values (n, t) on id from claim c", "names a number, a text and an instant column"),
        ("via conditions t(a, b, c) values (n, t, a, l, x, y, z) on id from claim c", "names at most 6 columns, got 7"),
    ] {
        let src = format!("{HEAD}object doc {{\n  table docs\n  scoped estate\n  relation r: member {bad}\n  permission view = @scoped @rls maps select\n}}\n");
        let err = demesne_syntax::parse(&src).expect_err(bad).to_string();
        assert!(err.contains(want), "{bad}: {err}");
    }
    demesne_syntax::parse(&format!("extension postgis\nextension postgis\n{HEAD}")).expect_err("an extension declared twice");
    demesne_syntax::parse(&format!("extension postgis schema \"a b\"\n{HEAD}")).expect_err("a schema that is no identifier");
}
