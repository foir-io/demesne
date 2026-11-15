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
    assert!(why.contains("is `pinned` on") && why.contains("a grant reaches rows of this object outside its containment"), "{why}");
}
