use demesne_emit_sql::Sql;

const SPEC: &str = r#"topology { level control virtual level estate parent control level space parent estate }

grant support at estate via edge approvals(holder_id, estate_id)

subject helper { anchor control; reach via grant support; identifies sub; roles none }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }

object ledger {
  table ledgers
  scoped estate
  permission view = @scoped and @row(state, "open") @rls maps select
  permission edit = @scoped and @row(state, "open") @rls maps update
  permission open_only = @scoped and @row(state, "open") @rls predicate
}

object passbook {
  table passbooks
  scoped estate
  permission view = (@scoped and @row(state, "open")) + via grant support @rls maps select
}

object memo {
  table memos
  scoped estate
  permission view = @scoped @rls maps select
}

object keepsake {
  table keepsakes
  scoped estate
  relation owner: member via holder_id
  permission view = @self(holder_id) @rls maps select
}

object space {
  table spaces
  level space
  scoped estate > space
  permission view = @scoped and @row(state, "open") @rls maps select
}

object note {
  table notes
  scoped estate > space
  permission view = @scoped and @row(state, "open") @rls maps select
}

object entry {
  table entries
  scoped estate > space
  relation in_open_ledger: member via object ledger->open_only on ledger_id
  permission view = @scoped and in_open_ledger @rls maps select
}
"#;

const DECLARED: &str = r#"topology { level control virtual level estate parent control level space parent estate }

grant audit at estate via edge audits(holder_id, estate_id) scope space on space_id missing deny

subject auditor { anchor control; reach via grant audit; identifies sub; roles none }

object book {
  table books
  scoped estate
  reach audit unscoped for select
  permission view = @scoped and @row(state, "open") @rls maps select
  permission edit = @scoped and @row(state, "open") @rls maps update blind
}
"#;

const REACH: &str = "estate_id IN (SELECT auth.approvals_reach_set((SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')))";
const STANDS: &str = "estate_id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'estate_id')";
const SPACE: &str = "space_id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'space_id')";

fn emitted(src: &str) -> String {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the spec compiles");
    sql
}

fn refusal(src: &str) -> String {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect_err("the spec is refused").to_string()
}

fn using(sql: &str, policy: &str) -> String {
    let at = sql.find(&format!("CREATE POLICY {policy} ")).unwrap_or_else(|| panic!("no policy {policy} in\n{sql}"));
    let line = sql[at..].lines().nth(1).unwrap_or_else(|| panic!("policy {policy} has no predicate"));
    let line = line.trim().trim_end_matches(';');
    line.strip_prefix("USING (").and_then(|rest| rest.strip_suffix(')')).unwrap_or_else(|| panic!("policy {policy} reads `{line}`")).to_string()
}

#[test]
fn on_a_one_level_object_the_terms_bind_a_caller_who_comes_in_by_a_grant() {
    let sql = emitted(SPEC);
    assert_eq!(using(&sql, "ledgers_select"), format!("(({REACH} OR ({STANDS})) AND ((state = 'open')))"));
    assert_eq!(using(&sql, "ledgers_update"), format!("(({REACH} OR ({STANDS})) AND ((state = 'open')))"));
}

#[test]
fn on_a_levels_own_table_the_terms_bind_a_caller_who_comes_in_by_a_grant() {
    assert_eq!(using(&emitted(SPEC), "spaces_select"), format!("(({REACH} OR ({STANDS})) AND ((state = 'open')))"));
}

#[test]
fn on_an_object_with_a_lower_level_the_grant_widens_its_own_level_as_it_did() {
    assert_eq!(using(&emitted(SPEC), "notes_select"), format!("(({STANDS} OR {REACH}) AND {SPACE} AND ((state = 'open')))"));
}

#[test]
fn a_permission_that_is_the_scope_alone_emits_what_it_did() {
    assert_eq!(using(&emitted(SPEC), "memos_select"), format!("{REACH} OR ({STANDS})"));
}

#[test]
fn a_grant_named_in_the_permission_passes_without_the_other_terms_as_it_did() {
    assert_eq!(using(&emitted(SPEC), "passbooks_select"), format!("{REACH} OR ({STANDS} AND ((state = 'open')))"));
}

#[test]
fn a_permission_with_no_term_under_the_scope_gives_a_grant_nothing() {
    let sql = emitted(SPEC);
    assert_eq!(using(&sql, "keepsakes_select"), "holder_id = (SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')");
}

#[test]
fn a_predicate_another_object_borrows_binds_the_grant_the_same_way() {
    let sql = emitted(SPEC);
    assert!(
        sql.contains(&format!("WHERE ledgers.id = p_ledger_id AND ((({REACH} OR ({STANDS})) AND ((state = 'open')))));")),
        "the borrowed predicate:\n{sql}"
    );
}

#[test]
fn a_reach_the_object_declares_for_an_operation_passes_there_and_is_bound_elsewhere() {
    let sql = emitted(DECLARED);
    let unscoped = "estate_id IN (SELECT auth.audits_reach_unscoped_set((SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')))";
    let any = "estate_id IN (SELECT auth.audits_reach_set((SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')))";
    assert_eq!(using(&sql, "books_select"), format!("{unscoped} OR ({STANDS} AND ((state = 'open')))"));
    assert_eq!(using(&sql, "books_update"), format!("(({any} OR ({STANDS})) AND ((state = 'open')))"));
}

#[test]
fn a_grant_named_where_it_already_widens_a_level_is_refused() {
    let lower = SPEC.replace(
        "table notes\n  scoped estate > space\n  permission view = @scoped and @row(state, \"open\") @rls maps select",
        "table notes\n  scoped estate > space\n  permission view = (@scoped and @row(state, \"open\")) + via grant support @rls maps select",
    );
    assert_ne!(lower, SPEC);
    let why = refusal(&lower);
    assert!(why.contains("object \"note\" permission \"view\": `via grant support` adds nothing here: the grant already widens level \"estate\""), "{why}");
    assert!(why.contains("remove the term"), "{why}");
    let anchored = SPEC.replace("subject helper { anchor control;", "subject helper { anchor estate;");
    assert_ne!(anchored, SPEC);
    let why = refusal(&anchored);
    assert!(why.contains("object \"passbook\" permission \"view\": `via grant support` adds nothing here"), "{why}");
}

#[test]
fn a_pinned_borrow_is_refused_where_the_terms_bind_a_grants_callers() {
    let pinned = SPEC
        .replace(
            "table ledgers\n  scoped estate\n",
            "table ledgers\n  scoped estate\n  relation in_open_memo: member via object memo->view on estate_id pinned\n",
        )
        .replace(
            "permission view = @scoped and @row(state, \"open\") @rls maps select\n  permission edit",
            "permission view = @scoped and in_open_memo @rls maps select\n  permission edit",
        );
    assert_ne!(pinned, SPEC);
    let why = refusal(&pinned);
    assert!(why.contains("relation \"in_open_memo\" is `pinned` on \"estate_id\""), "{why}");
    assert!(why.contains("a grant reaches rows of this object outside its containment"), "{why}");
    assert!(why.ends_with("Drop `pinned`, or name the grant in the permission: `+ via grant support`"), "{why}");
}

#[test]
fn a_pinned_borrow_is_emitted_where_the_permission_names_the_grant() {
    let named = SPEC
        .replace(
            "table ledgers\n  scoped estate\n",
            "table ledgers\n  scoped estate\n  relation in_open_memo: member via object memo->view on estate_id pinned\n",
        )
        .replace(
            "permission view = @scoped and @row(state, \"open\") @rls maps select\n  permission edit",
            "permission view = (@scoped and in_open_memo) + via grant support @rls maps select\n  permission edit",
        )
        .replace(
            "permission edit = @scoped and @row(state, \"open\") @rls maps update",
            "permission edit = (@scoped and in_open_memo) + via grant support @rls maps update",
        );
    assert_ne!(named, SPEC);
    let pred = using(&emitted(&named), "ledgers_select");
    let pinned = "(SELECT auth.memo_can_view((SELECT current_setting('request.jwt.claims', true)::json ->> 'estate_id')))";
    assert_eq!(
        pred,
        format!("{REACH} OR ({STANDS} AND (({pinned})))"),
        "the grant's holders pass by the named grant, and the pinned call binds only callers the scope holds"
    );
}

const AUDITOR: &str = "((SELECT current_setting('request.jwt.claims', true)::json ->> 'kind') = 'auditor') AND (state = 'shut')";

#[test]
fn on_a_one_level_object_an_admit_arm_and_a_projection_take_the_grants_reach_as_the_permission_does() {
    let ledger = "  permission open_only = @scoped and @row(state, \"open\") @rls predicate\n}";
    let spec = SPEC.replacen(
        ledger,
        "  permission open_only = @scoped and @row(state, \"open\") @rls predicate\n  admit select = @kind(\"auditor\") and @row(state, \"shut\")\n  projection shut_ledgers(id text) = @kind(\"auditor\") and @row(state, \"shut\")\n}",
        1,
    );
    assert_ne!(spec, SPEC, "the ledger takes the arm");
    let sql = emitted(&spec);
    assert_eq!(using(&sql, "ledgers_select"), format!("((({REACH} OR ({STANDS})) AND ((state = 'open')))) OR (({REACH} OR ({STANDS})) AND ({AUDITOR}))"));
    assert!(sql.contains(&format!("SELECT ledgers.id::text FROM ledgers WHERE ({REACH} OR ({STANDS})) AND ({AUDITOR});")), "the projection:\n{sql}");
}

#[test]
fn on_a_one_level_object_the_evaluator_a_hop_asks_takes_the_grants_reach_as_the_policy_does() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/chains.demesne");
    let chains = std::fs::read_to_string(&path).expect("the chains example reads");
    let topology = "topology { level estate level space parent estate level folder parent space }";
    assert!(chains.contains(topology), "the example's topology");
    let spec = chains.replacen(
        topology,
        "topology { level control virtual level estate parent control level space parent estate level folder parent space }\ngrant support at estate via edge approvals(holder_id, estate_id)\nsubject helper { anchor control; reach via grant support; identifies helper_id; roles none }",
        1,
    );
    let sql = emitted(&spec);
    let reach = "estate_id IN (SELECT auth.approvals_reach_set((SELECT current_setting('request.jwt.claims', true)::json ->> 'helper_id')))";
    assert!(
        sql.contains(&format!("WHERE docs.id = demesne_hop.record AND ({reach} OR ({STANDS})) AND (EXISTS (SELECT 1 FROM unnest(docs.rules_live)")),
        "the hop's evaluator:\n{sql}"
    );
}

const AGENT: &str = "estate_id IN (SELECT auth.approvals_reach_set((SELECT current_setting('request.jwt.claims', true)::json ->> 'agent_id')))";

fn with_agent(spec: &str, anchor: &str) -> String {
    let helper = "subject helper { anchor control; reach via grant support; identifies sub; roles none }\n";
    let two = spec.replacen(helper, &format!("{helper}subject agent {{ anchor {anchor}; reach via grant support; identifies agent_id; roles none }}\n"), 1);
    assert_ne!(two, spec, "the spec takes a second subject reaching by the grant");
    two
}

fn pinned_under(spec: &str, view: &str) -> String {
    let pinned = spec
        .replace(
            "table ledgers\n  scoped estate\n",
            "table ledgers\n  scoped estate\n  relation in_open_memo: member via object memo->view on estate_id pinned\n",
        )
        .replace(
            "permission view = @scoped and @row(state, \"open\") @rls maps select\n  permission edit",
            &format!("permission view = {view} @rls maps select\n  permission edit"),
        )
        .replace("permission edit = @scoped and @row(state, \"open\") @rls maps update", &format!("permission edit = {view} @rls maps update"));
    assert_ne!(pinned, spec, "the ledger takes the pinned borrow");
    pinned
}

#[test]
fn a_grant_two_subjects_reach_by_is_named_for_both_and_binds_both_where_it_is_not() {
    let sql = emitted(&with_agent(SPEC, "control"));
    assert_eq!(using(&sql, "passbooks_select"), format!("{REACH} OR {AGENT} OR ({STANDS} AND ((state = 'open')))"));
    assert_eq!(using(&sql, "ledgers_select"), format!("(({REACH} OR {AGENT} OR ({STANDS})) AND ((state = 'open')))"));
    let pinned = emitted(&pinned_under(&with_agent(SPEC, "control"), "(@scoped and in_open_memo) + via grant support"));
    assert!(using(&pinned, "ledgers_select").starts_with(&format!("{REACH} OR {AGENT} OR ({STANDS} AND ")), "{pinned}");
}

#[test]
fn a_grant_named_adds_nothing_only_where_it_widens_the_level_for_every_subject_it_reaches() {
    let helper_within = |agent: &str| with_agent(SPEC, agent).replace("subject helper { anchor control;", "subject helper { anchor estate;");
    let sql = emitted(&helper_within("control"));
    assert_eq!(using(&sql, "passbooks_select"), format!("{AGENT} OR (({STANDS} OR {REACH}) AND ((state = 'open')))"));
    let why = refusal(&helper_within("estate"));
    assert!(why.contains("object \"passbook\" permission \"view\": `via grant support` adds nothing here"), "{why}");
}

#[test]
fn a_pinned_refusal_names_only_the_grants_the_permission_leaves_unnamed() {
    let two = SPEC.replacen(
        "subject helper {",
        "grant escort at estate via edge escorts(holder_id, estate_id)\nsubject escortee { anchor control; reach via grant escort; identifies escort_id; roles none }\nsubject helper {",
        1,
    );
    let why = refusal(&pinned_under(&two, "(@scoped and in_open_memo) + via grant support"));
    assert!(why.ends_with("Drop `pinned`, or name the grant in the permission: `+ via grant escort`"), "{why}");
}

#[test]
fn on_the_grants_own_table_naming_the_grant_admits_no_subject_v4_did_not() {
    let own = with_agent(SPEC, "control").replacen(
        "object memo {",
        "object approval {\n  table approvals\n  scoped estate\n  permission view = (@scoped and @row(state, \"open\")) + via grant support @rls maps select\n}\n\nobject memo {",
        1,
    );
    assert_eq!(using(&emitted(&own), "approvals_select"), format!("{REACH} OR ({STANDS} AND ((state = 'open')))"));
}
