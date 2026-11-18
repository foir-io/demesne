use demesne_emit_sql::{Before, Manifest, Sql, file_sql, granted_to_public, revoked_from_public, validate_files};
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

const BORROWED: &str = "topology { level tenant level workspace parent tenant }
grant support at tenant via edge support_grants(holder_id, tenant_id)
subject staff { anchor tenant; reach via grant support; identifies sub; roles none }
subject member { anchor workspace; reach self; identifies member_id; roles none; binds owner }
object acl_entry {
  table acl
  scoped tenant > workspace
  permission view = @store_manage @rls maps select
  permission edit = @store_manage @rls maps update
}
object doc {
  table docs
  scoped tenant > workspace
  relation owner: member via owner_id
  relation grantee: member via grant acl(resource_id, principal_kind, principal_id, access) where resource_type = \"doc\"
  permission view = owner + grantee:read + grantee:write @rls maps select
  permission edit = owner + grantee:write @rls maps update
}
";

fn note(replace: &str, view: &str) -> String {
    format!(
        "{replace}object note {{\n  table notes\n  scoped tenant > workspace\n  relation author: member via author_id\n  relation doc: member via object doc->edit on doc_id\n  permission view = {view} @rls maps select\n}}\n"
    )
}

#[test]
fn a_later_file_that_lets_public_run_a_function_grants_it_again() {
    let opening = format!("{BORROWED}{}", note("", "author"));
    let (borrows, writes) = (note("replace ", "doc"), note("replace ", "author"));
    let files = parse_files([("a.demesne", opening.as_bytes()), ("b.demesne", borrows.as_bytes()), ("c.demesne", writes.as_bytes())]).expect("the files parse");
    validate_files(&files).expect("the files validate");
    let revoke = "REVOKE EXECUTE ON FUNCTION auth.doc_can_edit(text) FROM PUBLIC, authenticated;";
    let grant = "GRANT EXECUTE ON FUNCTION auth.doc_can_edit(text) TO PUBLIC;";
    let first = file_sql(&files, 0).expect("the first file emits");
    assert!(first.contains(revoke), "only the store's dispatch calls it, as its owner:\n{first}");
    for (k, said, why) in [(1, grant, "a policy borrows it"), (2, revoke, "no policy borrows it any more")] {
        let sql = file_sql(&files, k).expect("the file emits");
        let created =
            sql.find("CREATE OR REPLACE FUNCTION auth.doc_can_edit(").unwrap_or_else(|| panic!("file {k}, {why}: the function is not written again:\n{sql}"));
        let at = sql[created..].find(said).unwrap_or_else(|| panic!("file {k}, {why}: no `{said}` after the function:\n{sql}"));
        assert!(!sql[created + 1..created + at].contains("CREATE "), "file {k}: `{said}` does not follow its function:\n{sql}");
    }
}

#[test]
fn the_store_and_a_borrow_name_the_check_they_share_alike() {
    let made = |src: &str| {
        let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
        demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
        let defs = Sql::new(&s).emit_definers().expect("the definers compile");
        defs.into_iter().find(|d| d.name == "doc_can_edit").expect("the dispatch's check")
    };
    let store = made(BORROWED);
    let borrow = made(&format!("{BORROWED}{}", note("", "doc")));
    assert_eq!((store.sig().as_str(), borrow.sig().as_str()), ("p_doc_id text", "p_doc_id text"), "one parameter list, whichever generator makes it");
    assert_eq!((store.before, borrow.before), (Before::DropRenamed, Before::Nothing), "only the copy no policy calls drops an earlier form");
    assert!(store.create_sql().starts_with("DO $demesne$ BEGIN\n  IF EXISTS (SELECT 1 FROM pg_proc WHERE oid = to_regprocedure('auth.doc_can_edit(text)') AND proargnames IS DISTINCT FROM ARRAY['p_doc_id']::text[]) THEN\n    DROP FUNCTION auth.doc_can_edit(text);"), "{}", store.create_sql());
}
