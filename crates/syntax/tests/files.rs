use demesne_syntax::{Finding, SpecFiles, parse_files};

const TOPOLOGY: &str = "topology { level tenant }\n";

fn named(files: &[(&str, &str)]) -> Result<SpecFiles, demesne_syntax::Error> {
    parse_files(files.iter().map(|(n, s)| (*n, s.as_bytes())))
}

fn refused(files: &[(&str, &str)]) -> String {
    named(files).expect_err("the files are refused").to_string()
}

fn object(name: &str) -> String {
    format!("object {name} {{\n  table {name}s\n  scoped tenant\n}}\n")
}

#[test]
fn no_files_is_no_spec() {
    assert_eq!(parse_files(std::iter::empty()).expect_err("nothing to parse").to_string(), "no spec files to parse");
}

#[test]
fn the_files_keep_their_names_and_order() {
    let files = named(&[("a.demesne", TOPOLOGY), ("b.demesne", &object("doc"))]).expect("the files parse");
    assert_eq!(files.names(), ["a.demesne", "b.demesne"]);
    assert_eq!(files.len(), 2);
    assert!(!files.is_empty());
    assert!(files.prefix(0).objects.is_empty());
    assert_eq!(files.spec().objects.len(), 1);
}

#[test]
fn a_declaration_the_spec_makes_once_cannot_be_made_again_in_a_later_file() {
    for (decl, message) in [
        (TOPOLOGY, "duplicate topology block"),
        ("claims via \"req\" json\n", "duplicate claims block"),
        ("definers schema \"authz\"\n", "duplicate definers block"),
        ("tables schema \"rows\"\n", "duplicate tables block"),
        ("identifiers uuid\n", "duplicate identifiers declaration"),
    ] {
        let first = if decl == TOPOLOGY { TOPOLOGY.to_string() } else { format!("{TOPOLOGY}{decl}") };
        assert_eq!(refused(&[("a.demesne", &first), ("b.demesne", &format!("\n{decl}"))]), format!("b.demesne:2: {message}"));
        let replaced = named(&[("a.demesne", &first), ("b.demesne", &format!("replace {decl}"))]);
        assert!(replaced.is_ok(), "replace {decl}: {:?}", replaced.err());
    }
    assert_eq!(
        refused(&[("a.demesne", TOPOLOGY), ("b.demesne", "replace identifiers uuid\n")]),
        "b.demesne:1: replace identifiers: no earlier file declares one"
    );
}

#[test]
fn an_external_predicate_is_declared_once_unless_replaced() {
    let first = format!("{TOPOLOGY}external predicate in_tenant(text, text[])\n");
    assert_eq!(
        refused(&[("a.demesne", &first), ("b.demesne", "external predicate in_tenant(text)\n")]),
        "b.demesne:1: duplicate external predicate \"in_tenant\""
    );
    let files = named(&[("a.demesne", &first), ("b.demesne", "replace external predicate in_tenant(text)\n")]).expect("a predicate may be replaced");
    assert_eq!(files.spec().externals.len(), 1);
    assert_eq!(files.spec().externals[0].arg_types, ["text"]);
}

#[test]
fn a_replacement_is_matched_to_its_own_declaration_wherever_it_sits_in_the_file() {
    let first = format!("{TOPOLOGY}{}{}", object("doc"), object("note"));
    for second in [format!("{}replace {}", object("extra"), object("doc")), format!("replace {}{}", object("doc"), object("extra"))] {
        let files = named(&[("a.demesne", &first), ("b.demesne", &second)]).expect("the files parse");
        let names: Vec<&str> = files.spec().objects.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["doc", "note", "extra"], "{second}");
        let placed = files.place(&Finding::at(files.spec().objects[0].pos.line, "doc")).to_string();
        assert_eq!(placed, if second.starts_with("replace") { "b.demesne:1: doc" } else { "b.demesne:5: doc" }, "{second}");
    }
}

#[test]
fn a_replacement_stands_for_every_earlier_declaration_of_its_name() {
    let block = |rpc: &str| format!("procedures crew {{\n  docs.v1.DocService/{rpc} -> docs:read\n}}\n");
    let first = format!("{TOPOLOGY}{}{}{}", block("GetDoc"), object("doc"), block("ListDocs"));
    let files = named(&[("a.demesne", &first), ("b.demesne", &format!("replace {}", block("Only")))]).expect("the files parse");
    assert_eq!(files.spec().procedures.len(), 1);
    assert_eq!(files.spec().procedures[0].entries[0].proc_, "docs.v1.DocService/Only");
}

#[test]
fn a_template_problem_names_the_file_it_surfaced_in() {
    let second = "object doc {\n  table docs\n  scoped tenant\n  use missing\n}\n";
    assert_eq!(refused(&[("a.demesne", TOPOLOGY), ("b.demesne", second)]), "b.demesne: object \"doc\" uses unknown template \"missing\"");
}

#[test]
fn a_parse_error_names_its_file_and_line() {
    assert_eq!(refused(&[("a.demesne", TOPOLOGY), ("b.demesne", "\n\nobject {\n")]), "b.demesne:3: expected IDENT, got { \"{\"");
}
