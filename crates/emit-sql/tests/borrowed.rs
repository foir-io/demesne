use demesne_emit_sql::Sql;
use std::path::{Path, PathBuf};

const BORROWED: &str = "demesne_borrowed";

const HEAD: &str =
    "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\n";

fn spec(doc_perms: &str, note_relation: &str, more: &str) -> String {
    format!(
        "{HEAD}object folder {{\n  table folders\n  scoped estate > space\n  relation owner: member via owner_id\n  permission view = owner @rls maps select\n}}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  relation shelf: member via object folder->view on folder_id\n{doc_perms}\n}}\nobject note {{\n  table notes\n  scoped estate > space\n  {note_relation}\n  permission view = of @rls maps select\n}}\n{more}"
    )
}

const VIEW_ONLY: &str = "  permission view = owner + shelf @rls maps select\n  permission edit = owner @rls maps update";
const OF_VIEW: &str = "relation of: member via object doc->view on doc_id";

struct Compiled {
    policies: Vec<demesne_emit_sql::Policy>,
    definers: Vec<demesne_emit_sql::GenFn>,
    definers_sql: String,
}

fn compiled(src: &str) -> Compiled {
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let sql = Sql::new(&s);
    let definers = sql.emit_definers().expect("the definers compile");
    Compiled { policies: sql.emit_rls().expect("the policies compile").policies, definers_sql: demesne_emit_sql::definers_sql(&definers), definers }
}

fn using<'p>(policies: &'p [demesne_emit_sql::Policy], name: &str) -> &'p str {
    &policies.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no policy {name}")).using
}

const EXPORTED: &str = "relation of: member via object doc->view on doc_id\n  export view as note_view_allowed(id text as row_id, estate_id text as row_estate_id, space_id text as row_space_id, doc_id text as row_doc_id)";

#[test]
fn a_policy_borrows_by_the_borrowed_rows_own_policy_and_a_definer_never_does() {
    let c = compiled(&spec(VIEW_ONLY, EXPORTED, ""));
    let notes = using(&c.policies, "notes_select");
    assert!(notes.contains("EXISTS (SELECT 1 FROM public.docs AS demesne_borrowed WHERE demesne_borrowed.id = notes.doc_id)"), "{notes}");
    assert!(!notes.contains("doc_can_view("), "the policy reads the docs themselves, under their own policy:\n{notes}");
    let docs = using(&c.policies, "docs_select");
    assert!(docs.contains("EXISTS (SELECT 1 FROM public.folders AS demesne_borrowed"), "{docs}");
    let names: Vec<&str> = c.definers.iter().map(|d| d.name.as_str()).collect();
    let definer = |name: &str| c.definers.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} among {names:?}"));
    assert!(
        definer("note_view_allowed").body.contains("doc_can_view("),
        "an export runs as its owner and borrows through the definer:\n{}",
        definer("note_view_allowed").body
    );
    assert!(definer("doc_can_view").body.contains("folder_can_view("), "a definer borrows through the definer:\n{}", definer("doc_can_view").body);
    assert!(!c.definers_sql.contains(BORROWED), "a definer runs as its owner, past every policy, and so never borrows by rows:\n{}", c.definers_sql);
}

#[test]
fn a_second_read_policy_on_a_borrowed_object_is_refused_before_it_could_widen_a_borrow() {
    let two = "  permission view = owner + shelf @rls maps select\n  permission peek = owner @rls maps select\n  permission edit = owner @rls maps update";
    let src = spec(two, OF_VIEW, "");
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let refusal = demesne_emit_sql::validate(&s).expect_err("a second select-mapped permission on doc").to_string();
    assert!(refusal.contains("(V15)"), "{refusal}");
}

#[test]
fn a_borrow_of_a_verb_that_isn_t_the_read_keeps_the_definer() {
    let c = compiled(&spec(VIEW_ONLY, "relation of: member via object doc->edit on doc_id", ""));
    let notes = using(&c.policies, "notes_select");
    assert!(!notes.contains(BORROWED), "docs' select policy is view's, not edit's:\n{notes}");
    assert!(notes.contains("doc_can_edit("), "{notes}");
}

#[test]
fn a_borrow_of_a_table_another_object_also_rules_keeps_the_definer() {
    let draft = "object draft {\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id\n  permission make = owner @rls maps insert\n}\n";
    let c = compiled(&spec(VIEW_ONLY, OF_VIEW, draft));
    let notes = using(&c.policies, "notes_select");
    assert!(!notes.contains(BORROWED), "docs carries draft's policies too, so its rows are not doc's view alone:\n{notes}");
    assert!(notes.contains("doc_can_view("), "{notes}");
}

#[test]
fn a_borrow_of_an_object_whose_table_admits_more_than_its_view_keeps_the_definer() {
    let admitted = "  permission view = owner + shelf @rls maps select\n  permission edit = owner @rls maps update\n  admit select = owner";
    let c = compiled(&spec(admitted, OF_VIEW, ""));
    let notes = using(&c.policies, "notes_select");
    assert!(!notes.contains(BORROWED), "docs' select policy holds an admit arm view doesn't lend:\n{notes}");
    assert!(notes.contains("doc_can_view("), "{notes}");
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

#[test]
fn across_the_corpus_no_definer_borrows_by_rows_and_each_borrowed_table_has_one_permissive_read() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    let (mut specs_read, mut borrowing) = (0, 0);
    for path in paths {
        let Some(s) = std::fs::read_to_string(&path).ok().and_then(|src| demesne_syntax::parse(&src).ok()) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        let sql = Sql::new(&s);
        let (Ok(rls), Ok(defs)) = (sql.emit_rls(), sql.emit_definers()) else { continue };
        specs_read += 1;
        let definers_sql = demesne_emit_sql::definers_sql(&defs);
        assert!(!definers_sql.contains(BORROWED), "{}: a definer borrows by rows:\n{definers_sql}", path.display());
        for p in rls.policies.iter().filter(|p| p.using.contains(BORROWED) || p.check.contains(BORROWED)) {
            borrowing += 1;
            for table in borrowed_tables(&p.using).into_iter().chain(borrowed_tables(&p.check)) {
                assert_ne!(table, p.table, "{}: {} borrows its own table by rows", path.display(), p.name);
                let reads = rls.policies.iter().filter(|q| q.table == table && !q.restrictive && matches!(q.cmd.as_str(), "SELECT" | "ALL")).count();
                assert_eq!(reads, 1, "{}: {} borrows {table} by its rows, which {reads} permissive read policies admit", path.display(), p.name);
            }
        }
    }
    assert!(specs_read > 10, "the corpus was read: {specs_read} specs");
    assert!(borrowing > 0, "some corpus policy borrows by rows");
}

fn borrowed_tables(sql: &str) -> Vec<String> {
    sql.split("FROM ")
        .skip(1)
        .filter_map(|rest| rest.split_once(" AS demesne_borrowed").map(|(table, _)| table.trim().rsplit('.').next().unwrap_or_default().to_owned()))
        .collect()
}
