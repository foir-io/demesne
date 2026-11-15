use demesne_emit_sql::{Execute, GenFn, Sql};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ABOUT_A_ROW_OR_THE_VOCABULARY: [&str; 13] =
    ["p_id", "p_key", "p_object", "p_element", "p_record", "p_access", "p_perm", "p_slot", "p_type", "p_text", "p_group", "p_resource", "p_container"];
const THE_CALLERS_OWN: [&str; 8] = ["user_id", "p_principal", "p_member", "p_node", "p_ancestor", "p_descendant", "p_claim", "p_values"];

fn specs_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            specs_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "demesne") {
            out.push(path);
        }
    }
}

fn emitted() -> Vec<(String, Vec<GenFn>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    for dir in ["examples", "testdata/corpus/fixtures", "testdata/gaps"] {
        specs_under(&root.join(dir), &mut paths);
    }
    let mut out = Vec::new();
    for path in paths {
        let Ok(src) = std::fs::read_to_string(&path) else { continue };
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        if let Ok(defs) = Sql::new(&s).emit_definers() {
            out.push((path.display().to_string(), defs));
        }
    }
    out
}

fn parameters(f: &GenFn) -> Vec<&str> {
    f.sig.split(',').filter_map(|p| p.split_whitespace().next()).collect()
}

fn the_first_of_a_point_check(f: &GenFn, at: usize) -> bool {
    at == 0 && f.name.contains("_can_access_")
}

fn about_a_row(f: &GenFn, at: usize, parameter: &str) -> bool {
    ABOUT_A_ROW_OR_THE_VOCABULARY.contains(&parameter)
        || (at == 1 && f.name.contains("_memberin_"))
        || parameter.starts_with("check_")
        || parameter.starts_with("row_")
        || (parameter.starts_with("p_") && parameter.ends_with("_id"))
        || f.create_sql().contains("current_setting(")
}

fn bound(f: &GenFn, parameter: &str) -> bool {
    let text = f.create_sql();
    [
        format!("{parameter} = (SELECT NULLIF(current_setting("),
        format!("{parameter} IN ((SELECT NULLIF(current_setting("),
        format!("{parameter} IS NOT DISTINCT FROM (SELECT "),
    ]
    .iter()
    .any(|guard| text.contains(guard.as_str()))
        || text.contains(" AND false;")
        || text.contains(" AND (false OR false));")
}

#[test]
fn a_function_public_may_run_answers_only_about_the_callers_own_claims() {
    let all = emitted();
    assert!(all.len() > 150, "{} specs emitted", all.len());
    let (mut checked, mut unbound, mut unknown) = (0, BTreeSet::new(), BTreeSet::new());
    let asked = all.iter().flat_map(|(spec, defs)| defs.iter().filter(|f| f.execute == Execute::Public).map(move |f| (spec, f)));
    for (spec, f, at, parameter) in asked.flat_map(|(spec, f)| parameters(f).into_iter().enumerate().map(move |(at, parameter)| (spec, f, at, parameter))) {
        let callers = THE_CALLERS_OWN.contains(&parameter) || the_first_of_a_point_check(f, at);
        checked += usize::from(callers);
        if callers && !bound(f, parameter) {
            unbound.insert(format!("{}({}) takes {parameter} unbound [{spec}]", f.name, f.sig));
        }
        if !callers && !about_a_row(f, at, parameter) {
            unknown.insert(format!("{}({}): is {parameter} a row or the caller's? [{spec}]", f.name, f.sig));
        }
    }
    assert!(unknown.is_empty(), "parameters this test cannot place:\n{}", unknown.into_iter().collect::<Vec<_>>().join("\n"));
    let shown: Vec<String> =
        unbound.iter().map(|line| line.split(" [").next().unwrap_or_default().to_string()).collect::<BTreeSet<_>>().into_iter().take(60).collect();
    assert!(unbound.is_empty(), "{} functions answer for a value that is not the caller's:\n{}", unbound.len(), shown.join("\n"));
    assert!(checked > 250, "{checked} caller parameters checked");
}

#[test]
fn a_membership_answers_when_either_side_is_the_callers_own() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/552954073f6906e3.demesne");
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let member = defs.iter().find(|d| d.name == "admin_memberin_tenant").expect("the membership check");
    let own = format!("(p_principal = {} OR p_tenant = {}) AND (EXISTS (", sql.session_claim("sub"), sql.session_claim("tenant_id"));
    assert!(member.body.starts_with(&own), "a rule asks it about the caller, or about a row's principal in the caller's own tenant:\n{}", member.body);
    let held = defs.iter().find(|d| d.name == "has_platform_role").expect("a role check");
    assert!(held.text().starts_with(&format!("user_id = {} AND (", sql.session_claim("sub"))), "{}", held.text());
}

#[test]
fn a_membership_no_rule_asks_by_scope_answers_for_the_callers_principal_alone() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/38d02b53bac27607.demesne");
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let member = defs.iter().find(|d| d.name == "admin_memberin_space").expect("the membership check");
    let own = format!("p_principal = {} AND (EXISTS (", sql.session_claim("sub"));
    assert!(member.body.starts_with(&own), "every rule passes the caller's claim as the principal, so no scope alone is answered for:\n{}", member.body);
    assert!(!member.body.contains("p_space = (SELECT"), "{}", member.body);
}

#[test]
fn a_rule_that_passes_the_callers_own_principal_opens_no_scope_side() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/552954073f6906e3.demesne");
    let src = std::fs::read_to_string(&path).expect("the fixture reads");
    let both = src.replace("memberin tenant(id, @tenant_id)", "memberin tenant(@sub, @tenant_id)");
    assert_ne!(src, both, "the fixture states the rule this test rewrites");
    let s = demesne_syntax::parse(&both).expect("the spec parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let member = defs.iter().find(|d| d.name == "admin_memberin_tenant").expect("the membership check");
    let own = format!("p_principal = {} AND (EXISTS (", sql.session_claim("sub"));
    assert!(member.body.starts_with(&own), "only a rule that asks about a row's principal needs the scope side:\n{}", member.body);
}

fn the_chains_example_with(change: impl Fn(&str) -> String) -> (String, Vec<GenFn>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/chains.demesne");
    let example = std::fs::read_to_string(&path).expect("the example reads");
    let changed = change(&example);
    let s = demesne_syntax::parse(&changed).unwrap_or_else(|e| panic!("the example parses: {e}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("the example validates: {e}"));
    let sql = Sql::new(&s);
    let policies = sql.emit_rls().expect("the policies compile").policy_sql("authenticated");
    (policies, sql.emit_definers().expect("the definers compile"))
}

fn the_chains_example() -> (String, Vec<GenFn>) {
    the_chains_example_with(str::to_string)
}

fn all_sql(defs: &[GenFn]) -> String {
    defs.iter().map(GenFn::create_sql).collect::<Vec<_>>().join("\n")
}

#[test]
fn a_function_with_a_second_side_remembers_nothing_and_has_no_copy() {
    let (_, defs) = the_chains_example();
    let member = defs.iter().find(|d| d.name == "keeper_memberin_space").expect("the membership check");
    assert_eq!(member.bound, None, "one remembered argument cannot stand for a check that reads two");
    assert!(defs.iter().find(|d| d.name == "doc_shared_keyed").expect("the keyed edge").bound.is_some());
}

#[test]
fn a_name_no_setting_can_hold_is_verified_on_every_call() {
    let (_, defs) = the_chains_example_with(|example| format!("definers schema \"Auth\"\n{example}"));
    let sql = all_sql(&defs);
    assert!(!sql.contains("'demesne."), "a setting's name is folded to lower case, so two schemas could share one");
    assert!(sql.contains("  RETURN p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub') AND (EXISTS ("), "{sql}");
    assert!(sql.contains("  IF p_object IS NULL OR NOT (p_values IS NOT DISTINCT FROM (SELECT (NULLIF(current_setting('request.jwt.claims', true), '')::json -> 'facts')::jsonb)) THEN"));
}

#[test]
fn a_copy_is_emitted_only_under_a_name_postgres_keeps_whole_and_nothing_else_has() {
    let long = "r".repeat(52);
    let (_, defs) = the_chains_example_with(|example| example.replace("shared", &long));
    let keyed = format!("doc_{long}_keyed");
    assert!(defs.iter().any(|d| d.name == keyed) && !defs.iter().any(|d| d.name == format!("{keyed}_inside")), "a name past 63 bytes is cut short by Postgres");
    assert!(all_sql(&defs).contains(&format!("auth.{keyed}((SELECT current_setting(")), "so a chain function asks the bound function");

    let taken = |example: &str| example.replace("live_skin", "doc_shared_keyed_inside");
    let (_, defs) = the_chains_example_with(taken);
    let named: Vec<&GenFn> = defs.iter().filter(|d| d.name == "doc_shared_keyed_inside").collect();
    assert_eq!(named.len(), 1, "the name is the lookup's");
    assert_eq!(named[0].sig, "p_node text");
    assert!(all_sql(&defs).contains("auth.doc_shared_keyed((SELECT current_setting("), "so a chain function asks the bound function");
}

#[test]
fn inside_a_chain_a_bound_function_remembers_the_claim_only_while_the_claims_keep_their_text() {
    let (_, defs) = the_chains_example();
    let claims = "current_setting('request.jwt.claims', true)";
    let own = "p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub')";
    let keyed = defs.iter().find(|d| d.name == "doc_shared_keyed").expect("the keyed edge").create_sql();
    let remembered = format!(
        "  IF current_setting('demesne.auth.doc_shared_keyed.seen', true) = {claims} AND current_setting('demesne.auth.doc_shared_keyed.own', true) = p_principal::text THEN\n    RETURN p_principal = p_principal AND (EXISTS ("
    );
    assert!(keyed.contains(&remembered), "the remembered value counts only for the same claims text and the same argument:\n{keyed}");
    let kept = format!(
        "  IF {own} THEN\n    PERFORM set_config('demesne.auth.doc_shared_keyed.own', p_principal::text, true), set_config('demesne.auth.doc_shared_keyed.seen', coalesce({claims}, ''), true);\n  END IF;\n  RETURN {own} AND (EXISTS ("
    );
    assert!(keyed.contains(&kept), "it is kept only once verified against the claims, and any other call is judged against them:\n{keyed}");

    let terms = defs.iter().find(|d| d.name == "doc_terms_hold").expect("the conditions check").create_sql();
    let verified = format!(
        "  IF (current_setting('demesne.auth.doc_terms_hold.seen', true) = {claims} AND current_setting('demesne.auth.doc_terms_hold.own', true) = coalesce(p_values::text, '')) IS NOT TRUE THEN\n    IF NOT (p_values IS NOT DISTINCT FROM (SELECT (NULLIF({claims}, '')::json -> 'facts')::jsonb)) THEN\n      RETURN NULL;\n    END IF;\n    PERFORM set_config("
    );
    assert!(terms.contains(&verified), "{terms}");
}

#[test]
fn a_copy_public_cannot_run_is_called_only_with_the_callers_own_claim_and_never_by_a_policy() {
    let (policies, defs) = the_chains_example();
    assert!(!policies.contains("_inside("), "a policy runs as the caller, so it calls the bound function");
    assert!(policies.contains("auth.doc_shared_keyed(") && policies.contains("auth.doc_terms_hold("), "{policies}");
    let mut calls = 0;
    for (copy, position) in [("doc_shared_keyed_inside", 0), ("doc_terms_hold_inside", 2)] {
        let f = defs.iter().find(|d| d.name == copy).unwrap_or_else(|| panic!("{copy} is emitted"));
        assert_eq!(f.execute, Execute::Granted, "{copy}");
        assert!(!f.create_sql().contains("demesne.auth."), "{copy} reads no remembered value:\n{}", f.create_sql());
        let call = format!("auth.{copy}(");
        let texts: Vec<String> = defs.iter().filter(|d| d.name != copy).map(GenFn::create_sql).collect();
        for after in texts.iter().flat_map(|text| text.split(call.as_str()).skip(1)) {
            let passed = after.split(", ").nth(position).unwrap_or_default();
            assert!(passed.starts_with("(SELECT current_setting(") || passed.starts_with("(SELECT (current_setting("), "{copy} is asked about {passed:.80}");
            calls += 1;
        }
    }
    assert_eq!(calls, 10, "every call a chain function makes with the claim goes to the copy");
    let direct = defs.iter().filter(|d| d.name != "doc_shared_keyed" && d.create_sql().contains("auth.doc_shared_keyed(")).count();
    assert_eq!(direct, 0, "no generated function pays for the binding it already satisfies");
}

#[test]
fn a_spec_with_no_chain_gets_no_copy() {
    for (spec, defs) in emitted() {
        let chained = defs.iter().any(|d| d.name.contains("_composition_"));
        let copies: Vec<&str> = defs.iter().filter(|d| d.name.ends_with("_inside")).map(|d| d.name.as_str()).collect();
        assert!(chained || copies.is_empty(), "{spec}: {copies:?}");
    }
}
