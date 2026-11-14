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
