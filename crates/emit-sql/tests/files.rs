use demesne_emit_sql::{Manifest, Sql, file_migration, file_sql, validate_files, validate_files_warnings};
use demesne_syntax::{SpecFiles, parse, parse_files};

const MULTI: [&str; 3] = ["base.demesne", "extra.demesne", "last.demesne"];

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../testdata/multi/{name}", env!("CARGO_MANIFEST_DIR"))).expect("the fixture reads")
}

fn named(files: &[(&str, &str)]) -> Result<SpecFiles, demesne_syntax::Error> {
    parse_files(files.iter().map(|(n, s)| (*n, s.as_bytes())))
}

fn multi() -> SpecFiles {
    let texts: Vec<String> = MULTI.iter().map(|n| fixture(n)).collect();
    let files = named(&MULTI.iter().copied().zip(texts.iter().map(String::as_str)).collect::<Vec<_>>()).expect("the fixture parses");
    validate_files(&files).expect("the fixture validates");
    files
}

fn all_sql(files: &SpecFiles, k: usize) -> String {
    let mut b = String::new();
    Sql::new(files.prefix(k)).write_all_sql(&mut b).expect("the prefix emits");
    b
}

fn function<'a>(sql: &'a str, name: &str) -> &'a str {
    let start = sql.find(&format!("CREATE OR REPLACE FUNCTION auth.{name}(")).unwrap_or_else(|| panic!("no function {name} in:\n{sql}"));
    let end = sql[start..].find("$$;").map_or(sql.len(), |e| start + e);
    &sql[start..end]
}

#[test]
fn the_first_file_emits_its_whole_sql() {
    let files = multi();
    let one = parse(&fixture("base.demesne")).expect("the first file parses alone");
    let mut b = String::new();
    Sql::new(&one).write_all_sql(&mut b).expect("the first file emits alone");
    assert_eq!(file_sql(&files, 0).expect("the first file emits"), b);
}

#[test]
fn a_later_file_writes_again_a_function_it_widens() {
    let files = multi();
    let sql = file_sql(&files, 1).expect("the second file emits");
    assert!(function(&sql, "acl_manage").contains("WHEN 'note' THEN auth.note_can_edit(p_id)"), "{sql}");
    assert!(!function(&all_sql(&files, 0), "acl_manage").contains("'note'"));
    assert!(sql.contains("CREATE POLICY notes_select ON public.notes"), "{sql}");
    assert!(!sql.contains("CREATE POLICY docs_select"), "an unchanged policy is written again:\n{sql}");
    assert!(sql.contains("CREATE OR REPLACE FUNCTION auth.doc_can_view("), "the borrow's check is missing:\n{sql}");
}

#[test]
fn a_replaced_declaration_rewrites_the_functions_it_emits() {
    let files = multi();
    let sql = file_sql(&files, 1).expect("the second file emits");
    assert!(function(&sql, "support_grants_reach").contains("AND ended_at IS NULL"), "{sql}");
    assert!(!function(&all_sql(&files, 0), "support_grants_reach").contains("ended_at"));
}

#[test]
fn a_later_file_drops_what_its_replacement_no_longer_emits() {
    let files = multi();
    let sql = file_sql(&files, 2).expect("the third file emits");
    assert!(sql.contains("DROP FUNCTION IF EXISTS auth.doc_readable(text, text, text, text);"), "{sql}");
    assert!(!sql.contains("CREATE POLICY"), "the replacement keeps doc's policies, so none is written again:\n{sql}");
    assert!(!all_sql(&files, 2).contains("doc_readable"));
}

#[test]
fn a_files_migration_drops_what_its_previous_surface_had() {
    let files = multi();
    let mut previous = Sql::new(files.prefix(1)).manifest().expect("the prefix has a manifest");
    previous.functions.insert("auth.retired(text)".into());
    let sql = file_migration(&files, 1, &previous).expect("the second file migrates");
    assert!(sql.contains("DROP FUNCTION IF EXISTS auth.retired(text);"), "{sql}");
    let current = Sql::new(files.prefix(2)).manifest().expect("the last prefix has a manifest");
    let last = file_migration(&files, 2, &current).expect("the last file migrates");
    assert!(last.contains("DROP FUNCTION IF EXISTS auth.doc_readable(text, text, text, text);"), "what the prefix before it made is dropped too:\n{last}");
    let first = file_migration(&files, 0, &Manifest::default()).expect("the first file migrates");
    assert_eq!(first, Sql::new(files.prefix(0)).migration(&Manifest::default()).expect("the first file's migration"));
}

#[test]
fn a_finding_names_its_file_and_line() {
    let base = fixture("base.demesne");
    let bad = "\nobject stray {\n  table strays\n  scoped tenant > workspace\n  relation owner: member via owner_id\n  permission view = nobody @rls maps select\n}\n";
    let files = named(&[("base.demesne", &base), ("bad.demesne", bad)]).expect("the files parse");
    let err = validate_files(&files).expect_err("a permission naming no relation is refused").to_string();
    assert!(err.starts_with("bad.demesne:6: permission stray.view references unknown relation \"nobody\""), "{err}");
}

#[test]
fn a_file_cannot_refer_to_a_later_file() {
    let base = fixture("base.demesne");
    let (head, doc) = base.split_at(base.find("object doc {").expect("the fixture declares doc"));
    let note = fixture("extra.demesne");
    let note = note.split("replace grant").next().expect("the note comes first");
    let files = named(&[("a.demesne", &format!("{head}{note}")), ("b.demesne", doc)]).expect("the files parse");
    let err = validate_files(&files).expect_err("the first file borrows what only the second declares").to_string();
    assert!(err.starts_with("a.demesne:"), "{err}");
    assert!(err.contains("doc"), "{err}");
}

#[test]
fn a_finding_with_no_line_names_the_file_whose_prefix_failed() {
    let files = named(&[
        ("a.demesne", "subject member { anchor tenant; reach self; identifies member_id; roles none }\n"),
        ("b.demesne", "topology { level tenant }\n"),
    ])
    .expect("the files parse");
    let err = validate_files(&files).expect_err("the first file has no topology").to_string();
    assert!(err.starts_with("a.demesne: "), "{err}");
}

#[test]
fn replace_needs_an_earlier_declaration() {
    let err = named(&[("a.demesne", "topology { level tenant }\n"), ("b.demesne", "replace grant nope at tenant via edge t(a, b)\n")])
        .expect_err("nothing earlier declares the grant")
        .to_string();
    assert_eq!(err, "b.demesne:1: replace grant \"nope\": no earlier file declares it");
}

#[test]
fn a_spec_in_one_file_cannot_replace() {
    let err = parse("topology { level tenant }\nreplace grant g at tenant via edge t(a, b)\n").expect_err("one file has no earlier file").to_string();
    assert!(err.starts_with("line 2: `replace`"), "{err}");
}

#[test]
fn a_later_file_cannot_declare_again_what_a_spec_declares_once() {
    let err = named(&[("a.demesne", "topology { level tenant }\n"), ("b.demesne", "\ntopology { level tenant }\n")]).expect_err("two topologies").to_string();
    assert_eq!(err, "b.demesne:2: duplicate topology block");
    let replaced =
        named(&[("a.demesne", "topology { level tenant }\n"), ("b.demesne", "replace topology { level org }\n")]).expect("a topology may be replaced");
    assert_eq!(replaced.spec().topology.as_ref().map(|t| t.levels.len()), Some(1));
    assert_eq!(replaced.spec().topology.as_ref().map(|t| t.levels[0].name.as_str()), Some("org"));
}

#[test]
fn a_replacement_takes_the_place_of_what_it_replaces() {
    let base = fixture("base.demesne");
    let files = named(&[("base.demesne", &base), ("last.demesne", &fixture("last.demesne"))]).expect("the files parse");
    let names: Vec<&str> = files.spec().objects.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(names, ["acl_entry", "doc"]);
    assert!(files.spec().objects[1].exports.is_empty());
    assert_eq!(files.prefix(0).objects[1].exports.len(), 1);
}

#[test]
fn a_later_file_may_use_an_earlier_files_template() {
    let first = "topology { level tenant }\nsubject member { anchor tenant; reach self; identifies member_id; roles none; binds owner }\ntemplate owned {\n  permission view = owner @rls maps select\n}\n";
    let second = "object doc {\n  table docs\n  scoped tenant\n  use owned\n  relation owner: member via owner_id\n}\n";
    let files = named(&[("a.demesne", first), ("b.demesne", second)]).expect("the files parse");
    assert_eq!(files.spec().objects[0].perms.iter().map(|p| p.verb.as_str()).collect::<Vec<_>>(), ["view"]);
}

#[test]
fn a_warning_names_its_file_once() {
    let base = fixture("base.demesne");
    let blind = "object ledger {\n  table ledgers\n  scoped tenant > workspace\n  relation owner:   member via owner_id\n  relation grantee: member via grant ledger_acl(ledger_id, principal_kind, principal_id, access)\n  permission view   = owner @rls maps select\n  permission delete = owner + grantee:delete @rls maps delete blind\n}\n";
    let files = named(&[("base.demesne", &base), ("blind.demesne", blind), ("last.demesne", &fixture("last.demesne"))]).expect("the files parse");
    validate_files(&files).expect("a blind write validates");
    let warnings: Vec<String> = validate_files_warnings(&files).iter().map(ToString::to_string).collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].starts_with("blind.demesne:7: permission ledger.delete maps delete"), "{warnings:?}");
}
