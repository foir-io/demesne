use demesne_emit_sql::Sql;
use demesne_model::{ConditionalExt, SpecExt};

fn spec(held: &str, implies: &str) -> String {
    format!(
        "topology {{ level estate level space parent estate }}\nvocabulary staff {{ permission docs:read permission docs:write{implies} }}\nrolestore staff {{\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n{held}}}\nsubject staff {{ anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }}\nobject doc {{\n  table docs\n  scoped estate > space wildcard\n  permission view = @holds(docs:read) @rls maps select\n}}\nobject ledger {{\n  table ledgers\n  scoped estate\n  permission view = @holds(docs:read) @rls maps select\n}}\n"
    )
}

fn compiled(src: &str) -> (Vec<(String, String)>, Vec<demesne_emit_sql::GenFn>, demesne_syntax::Spec) {
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let mut policies: Vec<(String, String)> = sql.emit_rls().expect("the policies compile").policies.into_iter().map(|p| (p.name, p.using)).collect();
    for (_, using) in &mut policies {
        for key in ["sub", "estate_id", "space_id"] {
            *using = using.replace(&sql.claim(key), &format!("<{key}>"));
        }
    }
    let defs = sql.emit_definers().expect("the definers compile");
    (policies, defs, s)
}

const HELD: &str = "  held claim held_verbs\n";

#[test]
fn without_the_line_holds_is_the_rolestore_alone() {
    let (policies, defs, _) = compiled(&spec("", ""));
    assert!(policies[0].1.ends_with("AND (auth.staff_has_perm(<sub>, estate_id, space_id, 'docs:read')))"), "{}", policies[0].1);
    assert!(!defs.iter().any(|d| d.name.contains("holds_by_claim")));
}

#[test]
fn a_held_verb_counts_where_an_assignment_at_the_sessions_place_would() {
    let (policies, _, _) = compiled(&spec(HELD, ""));
    let using = |name: &str| &policies.iter().find(|(n, _)| n == name).expect("the policy").1;
    assert!(
        using("docs_select").ends_with(
            "AND ((auth.staff_has_perm(<sub>, estate_id, space_id, 'docs:read') OR ((SELECT auth.staff_holds_by_claim('docs:read')) AND estate_id = <estate_id> AND (<space_id> IS NULL OR space_id = <space_id>)))))"
        ),
        "{}",
        using("docs_select")
    );
    assert!(
        using("ledgers_select").ends_with(
            "AND ((auth.staff_has_perm(<sub>, estate_id, NULL, 'docs:read') OR ((SELECT auth.staff_holds_by_claim('docs:read')) AND estate_id = <estate_id> AND <space_id> IS NULL))))"
        ),
        "an object not scoped at a level holds only for a session that names nothing there:\n{}",
        using("ledgers_select")
    );
}

#[test]
fn the_verb_check_reads_the_claim_as_an_array_and_follows_the_vocabularys_implications() {
    let carried = "(SELECT (current_setting('request.jwt.claims', true)::json -> 'held_verbs')::jsonb)";
    let body = |implies: &str| compiled(&spec(HELD, implies)).1.into_iter().find(|d| d.name == "staff_holds_by_claim").expect("the check").body;
    assert_eq!(
        body(""),
        format!(
            "CASE WHEN jsonb_typeof({carried}) = 'array' THEN EXISTS (SELECT 1 FROM jsonb_array_elements_text({carried}) v WHERE v = p_perm) ELSE false END"
        )
    );
    assert!(body(" implies docs:read").contains("WHERE v = ANY(auth.staff_perm_implied_by(p_perm))"), "{}", body(" implies docs:read"));
}

#[test]
fn the_reader_listing_says_a_held_verb_may_admit_callers_it_cannot_name() {
    let (_, _, with) = compiled(&spec(HELD, ""));
    let (_, _, without) = compiled(&spec("", ""));
    let sources =
        |s: &demesne_syntax::Spec| s.conditional_accessors(s.object_by_name("doc").expect("the object")).into_iter().map(|r| r.source).collect::<Vec<_>>();
    assert_eq!(sources(&with), ["held"]);
    assert_eq!(sources(&without), [] as [&str; 0]);
}
