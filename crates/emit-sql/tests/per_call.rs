use demesne_emit_sql::{Object, Sql, objects};
use std::path::{Path, PathBuf};

const SPEC: &str = "definers schema \"auth\"
topology { level estate level space parent estate }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }
object doc {
  table docs
  scoped estate > space
  relation owner: member via owner_id
  relation edge_slot: member via edge doc_edges(principal_id, object_id) key rule_id slot slot
  permission view = owner + some r in rules_live prefix \"read.\" held rules_held (every s in rule_slots(rule_id) where role = \"require\" nonempty (@slot(kind, \"edge\") and edge_slot) and none s in rule_slots(rule_id) where role = \"except\" (@slot(kind, \"edge\") and edge_slot)) @rls maps select
}
object note {
  table notes
  scoped estate > space
  relation of: member via object doc->view on doc_id
  permission view = of @rls maps select
  export view as note_view_allowed(id text as row_id, estate_id text as row_estate_id, space_id text as row_space_id, doc_id text as row_doc_id)
}
";

fn emitted(src: &str) -> Vec<(Object, String)> {
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql).expect("the spec emits");
    objects(&sql).expect("the emitted SQL splits into objects")
}

fn function<'a>(all: &'a [(Object, String)], name: &str) -> &'a str {
    all.iter()
        .find_map(|(o, stmt)| matches!(o, Object::Function(sig) if sig.split('(').next() == Some(name)).then_some(stmt.as_str()))
        .unwrap_or_else(|| panic!("no function {name} among {:#?}", all.iter().map(|(o, _)| o).collect::<Vec<_>>()))
}

fn policy<'a>(all: &'a [(Object, String)], named: &str) -> &'a str {
    all.iter()
        .find_map(|(o, stmt)| matches!(o, Object::Policy { name, .. } if name == named).then_some(stmt.as_str()))
        .unwrap_or_else(|| panic!("no policy {named}"))
}

fn body(stmt: &str) -> &str {
    stmt.find("AS $").map_or(stmt, |at| &stmt[at..])
}

#[test]
fn a_borrowed_permission_parses_the_claims_once_a_call_and_reads_its_declared_rows_from_their_table() {
    let all = emitted(SPEC);
    let f = body(function(&all, "auth.doc_can_view"));
    let queries = f.matches("RETURN (SELECT ").count();
    assert_eq!(queries, 2, "a row with no `read.` element runs the query with its `some` pruned, any other the whole one:\n{f}");
    assert_eq!(f.matches("current_setting(").count(), queries, "each query a call may run reads the claims setting once, and a call runs one:\n{f}");
    assert!(f.contains("FROM (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb AS claims OFFSET 0) AS demesne_call"), "{f}");
    assert!(f.contains("(demesne_call.claims ->> 'sub')"), "the owner term reads the call's claims:\n{f}");
    assert!(!f.contains("(SELECT current_setting("), "no claim is read by a subquery of its own:\n{f}");
    assert!(!f.contains("rule_slots_declared_by_rule_id("), "the definer reads the declared rows itself:\n{f}");
    assert_eq!(
        f.matches("FROM rule_slots WHERE rule_slots.rule_id = demesne_element.v::text").count(),
        3,
        "the whole query reads the require rows twice and the except rows once, and the pruned one none:\n{f}"
    );
}

#[test]
fn the_policy_of_the_permission_it_borrows_still_reads_claims_once_a_statement_and_declared_rows_through_their_function() {
    let all = emitted(SPEC);
    let p = policy(&all, "docs_select");
    assert!(p.contains("(SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')"), "{p}");
    assert!(p.contains("auth.rule_slots_declared_by_rule_id(demesne_element.v)"), "{p}");
    assert!(!p.contains("demesne_call"), "a policy binds nothing:\n{p}");
    let d = body(function(&all, "auth.rule_slots_declared_by_rule_id"));
    assert!(d.contains("FROM rule_slots WHERE rule_slots.rule_id = p_key"), "the policy's declared rows still come through their function:\n{d}");
}

fn specs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            specs(&path, out);
        } else if path.extension().is_some_and(|x| x == "demesne") {
            out.push(path);
        }
    }
}

fn corpus() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let s = demesne_syntax::parse(&std::fs::read_to_string(&path).ok()?).ok()?;
            demesne_emit_sql::validate(&s).ok()?;
            let mut sql = String::new();
            Sql::new(&s).write_all_sql(&mut sql).ok()?;
            Some((path.display().to_string(), sql))
        })
        .collect()
}

fn faults_of_a_bound_body(stmt: &str) -> Vec<String> {
    let f = body(stmt);
    let mut faults = Vec::new();
    if f.matches(" AS demesne_call").count() != 1 {
        faults.push(format!("binds the call's claims {} times", f.matches(" AS demesne_call").count()));
    }
    if f.matches("current_setting(").count() != 1 {
        faults.push("reads the claims setting other than through the one binding".to_string());
    }
    if !stmt.contains("\nSECURITY DEFINER\n") {
        faults.push("reads tables directly without running as its definer".to_string());
    }
    faults
}

#[test]
fn every_body_that_reads_the_call_s_claims_binds_them_once_and_runs_as_its_definer() {
    let (mut bound, mut statement, mut wrong) = (0, 0, Vec::new());
    for (path, sql) in corpus() {
        for (o, stmt) in objects(&sql).unwrap_or_else(|e| panic!("{path}: {e}")) {
            match o {
                Object::Function(_) if body(&stmt).contains("demesne_call.") => {
                    bound += 1;
                    wrong.extend(faults_of_a_bound_body(&stmt).into_iter().map(|fault| format!("{path}: {o:?}: {fault}")));
                }
                Object::Policy { .. } if stmt.contains("demesne_call") => wrong.push(format!("{path}: {o:?}: a policy reads a call's binding")),
                Object::Policy { .. } if stmt.contains("current_setting(") => statement += 1,
                _ => {}
            }
        }
    }
    assert!(bound > 20 && statement > 50, "the corpus must hold bound definers and statement policies: {bound} and {statement}");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
