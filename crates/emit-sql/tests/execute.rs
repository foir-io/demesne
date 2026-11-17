use demesne_emit_sql::{Manifest, Sql, file_sql, granted_to_public, revoked_from_public, validate_files};
use demesne_syntax::parse_files;
use std::collections::BTreeSet;
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

#[test]
fn every_function_the_sql_creates_says_whether_public_may_run_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    let mut checked = 0;
    for path in &paths {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        let sql = Sql::new(&s);
        let mut b = String::new();
        if sql.write_all_sql(&mut b).is_err() {
            continue;
        }
        let at = path.display();
        let functions = Manifest::from_sql(&b).unwrap_or_else(|e| panic!("{at}: {e}")).functions;
        let (revoked, granted) = (revoked_from_public(&b), granted_to_public(&b));
        for f in &functions {
            let said = revoked.iter().chain(&granted).filter(|g| *g == f).count();
            assert_eq!(said, 1, "{at}: {f} is followed by {said} statements saying whether PUBLIC may run it");
        }
        let named: BTreeSet<&String> = revoked.iter().chain(&granted).collect();
        assert!(named.iter().all(|f| functions.contains(*f)), "{at}: an EXECUTE statement names a function the SQL does not create: {named:?}");
        let lists = sql.manifest().unwrap_or_else(|e| panic!("{at}: {e}")).execute.expect("the manifest records who may run each function");
        let unrun: BTreeSet<String> = lists.grantable.union(&lists.revoked).cloned().collect();
        assert_eq!(unrun, revoked.iter().cloned().collect::<BTreeSet<_>>(), "{at}");
        let public: BTreeSet<String> = lists.callable.union(&lists.internal).cloned().collect();
        assert_eq!(public, granted.iter().cloned().collect::<BTreeSet<_>>(), "{at}");
        checked += 1;
    }
    assert!(checked > 100, "only {checked} specs emitted");
}

#[test]
fn a_later_file_that_lets_public_run_a_function_grants_it_again() {
    let head = "topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
";
    let doc = |view: &str| {
        format!(
            "object doc {{
  table docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access)
  relation team: customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = {view} @rls maps select
}}
"
        )
    };
    let revoke = "REVOKE EXECUTE ON FUNCTION auth.docs_team_flat_resources() FROM PUBLIC;";
    let grant = "GRANT EXECUTE ON FUNCTION auth.docs_team_flat_resources() TO PUBLIC;";
    for (first, then, before, after) in [("grantee:read + team", "team", revoke, grant), ("team", "grantee:read + team", grant, revoke)] {
        let (a, b) = (format!("{head}{}", doc(first)), format!("replace {}", doc(then)));
        let files = parse_files([("a.demesne", a.as_bytes()), ("b.demesne", b.as_bytes())]).expect("the files parse");
        validate_files(&files).expect("the files validate");
        let earlier = file_sql(&files, 0).expect("the first file emits");
        assert!(earlier.contains(before), "{first}: {earlier}");
        let later = file_sql(&files, 1).expect("the second file emits");
        let created = later
            .find("CREATE OR REPLACE FUNCTION auth.docs_team_flat_resources()")
            .unwrap_or_else(|| panic!("{then}: the function is not written again:\n{later}"));
        let said = later[created..].find(after).unwrap_or_else(|| panic!("{then}: no `{after}` after the function:\n{later}"));
        assert!(!later[created + 1..created + said].contains("CREATE "), "{then}: `{after}` does not follow its function:\n{later}");
    }
}
