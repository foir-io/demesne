use demesne_emit_sql::{ExecuteLists, Object, Sql, objects};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

fn body(stmt: &str) -> &str {
    stmt.find("AS $").map_or(stmt, |at| &stmt[at..])
}

fn kept_because(o: &Object, sig: &str, stmts: &[(Object, String)], lists: &ExecuteLists, surface: &str) -> Option<&'static str> {
    if lists.callable.contains(sig) {
        return Some("callable");
    }
    if lists.grantable.contains(sig) {
        return Some("grantable");
    }
    let call = format!("{}(", sig.split('(').next().unwrap_or_default());
    let by = |kind: fn(&Object) -> bool| stmts.iter().any(|(other, text)| kind(other) && other != o && body(text).contains(&call));
    if by(|x| matches!(x, Object::Policy { .. })) {
        Some("a policy")
    } else if by(|x| matches!(x, Object::Trigger { .. })) {
        Some("a trigger")
    } else if by(|x| matches!(x, Object::Function(_))) {
        Some("a function")
    } else {
        surface.contains(&call).then_some("a generated check")
    }
}

#[test]
fn every_emitted_function_is_callable_grantable_or_called_by_what_the_spec_emits() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    let (mut wrong, mut reasons, mut specs_read) = (Vec::new(), BTreeMap::<&str, usize>::new(), 0);
    for path in &paths {
        let Ok(src) = std::fs::read_to_string(path) else { continue };
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        let sql = Sql::new(&s);
        let mut b = String::new();
        if sql.write_all_sql(&mut b).is_err() {
            continue;
        }
        specs_read += 1;
        let at = path.display();
        let lists = sql.manifest().unwrap_or_else(|e| panic!("{at}: {e}")).execute.expect("the manifest records who may run each function");
        let stmts = objects(&b).unwrap_or_else(|e| panic!("{at}: {e}"));
        let surface = [demesne_emit_ts::emit_framework_ts(&s), demesne_emit_ts::emit_ts(&s)].map(Result::unwrap_or_default).concat();
        for (o, _) in &stmts {
            let Object::Function(sig) = o else { continue };
            match kept_because(o, sig, &stmts, &lists, &surface) {
                Some(reason) => *reasons.entry(reason).or_default() += 1,
                None => wrong.push(format!("{at}: {sig} is not callable or grantable, and nothing the spec emits calls it")),
            }
        }
    }
    assert!(wrong.is_empty(), "{} functions:\n{}", wrong.len(), wrong.join("\n"));
    assert!(specs_read > 150, "only {specs_read} specs emitted");
    for reason in ["callable", "grantable", "a policy", "a trigger", "a function", "a generated check"] {
        assert!(reasons.get(reason).copied().unwrap_or_default() > 0, "no function is kept as {reason}: {reasons:?}");
    }
}
