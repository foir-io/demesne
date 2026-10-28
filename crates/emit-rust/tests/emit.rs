use demesne_emit_rust::{Builder, Surface, emit_rust, item_path};

const SPEC: &str = r"
topology { level org col org_ref claim org level workspace parent org col ws_ref claim ws }
vocabulary app { permission self:read }
subject member { anchor workspace reach self identifies member_ref roles none binds owner }
object note {
  table notes
  pk note_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner @rls maps select
}
object r#OBJ {
  table things
  pk thing_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner @rls maps select
}
";

fn spec(name: &str) -> demesne_syntax::Spec {
    let src = SPEC.replace("r#OBJ", name);
    let s = demesne_syntax::parse(&src).expect("parse");
    demesne_emit_sql::validate(&s).expect("validate");
    s
}

fn items(code: &str) -> Vec<&str> {
    code.lines().map(str::trim).filter(|l| l.starts_with("pub static ") || l.starts_with("pub const ")).collect()
}

#[test]
fn only_the_named_surfaces_are_emitted() {
    let s = spec("thing");
    let code = emit_rust(&s, &[Surface::PointCheck("note".into())]).expect("emit");
    assert_eq!(items(&code), vec![r#"pub const POINT_CHECK_SQL: &str = "SELECT EXISTS (SELECT 1 FROM notes WHERE note_pk = $1)";"#]);
    assert!(!code.contains("thing"), "an unnamed object leaked into the output:\n{code}");
    let none = emit_rust(&s, &[]).expect("emit");
    assert_eq!(items(&none), [] as [&str; 0]);
}

#[test]
fn the_same_surface_named_twice_is_emitted_once() {
    let s = spec("thing");
    let code = emit_rust(&s, &[Surface::Session, Surface::Session, Surface::PointCheck("note".into())]).expect("emit");
    assert_eq!(items(&code).len(), 2);
}

#[test]
fn an_unknown_name_is_refused() {
    let s = spec("thing");
    let err = emit_rust(&s, &[Surface::PointCheck("nope".into()), Surface::Vocabulary("nope".into()), Surface::Grant("nope".into())]).expect_err("refused");
    assert!(err.is_surface() && !err.is_spec() && !err.is_io(), "{err:?}");
    let err = err.to_string();
    assert_eq!(err.lines().count(), 3, "{err}");
    assert!(err.contains("PointCheckSQL: no object \"nope\" in the spec"), "{err}");
    assert!(err.contains("no vocabulary \"nope\" in the spec"), "{err}");
}

#[test]
fn a_rust_keyword_object_becomes_a_raw_identifier() {
    let s = spec("loop");
    let w = Surface::PointCheck("loop".into());
    assert_eq!(item_path(&s, &w).expect("path"), "objects::r#loop::POINT_CHECK_SQL");
    let code = emit_rust(&s, &[w]).expect("emit");
    assert!(code.contains("pub mod r#loop {"), "{code}");
}

#[test]
fn a_permission_without_a_check_layer_has_no_check() {
    let s = spec("thing");
    let err = emit_rust(&s, &[Surface::Check("note".into(), "view".into())]).expect_err("refused").to_string();
    assert!(err.contains("note.view has no @check layer"), "{err}");
}

#[test]
fn builder_reports_a_spec_error_with_its_path() {
    let dir = std::env::temp_dir().join(format!("demesne-emit-rust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let bad = dir.join("bad.demesne");
    std::fs::write(&bad, "object {").expect("write");
    let err = Builder::new(&bad).session().render().expect_err("parse error");
    assert!(err.is_spec(), "{err:?}");
    assert!(err.to_string().starts_with(&bad.display().to_string()), "{err}");
    let invalid = dir.join("invalid.demesne");
    std::fs::write(&invalid, SPEC.replace("r#OBJ", "thing").replace("permission view = owner", "permission view = nobody")).expect("write");
    let err = Builder::new(&invalid).session().render().expect_err("validation error");
    assert!(err.is_spec(), "{err:?}");
    assert!(err.to_string().starts_with(&invalid.display().to_string()), "{err}");
    let missing = dir.join("missing.demesne");
    assert!(Builder::new(&missing).render().expect_err("no such file").is_io());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn builder_reads_a_spec_in_several_files() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/multi");
    let many = Builder::new(dir.join("base.demesne"))
        .spec(dir.join("extra.demesne"))
        .spec(dir.join("last.demesne"))
        .resource_access("note")
        .render()
        .expect("the files render");
    assert!(many.contains("notes_accessors"), "{many}");
    let base = dir.join("base.demesne");
    let later = Builder::new(&base).spec(dir.join("extra.demesne")).resource_access("note");
    let err = Builder::new(dir.join("extra.demesne")).spec(&base).resource_access("note").render().expect_err("the second file comes first");
    assert!(err.is_spec(), "{err:?}");
    assert!(err.to_string().ends_with("extra.demesne:11: replace grant \"support\": no earlier file declares it"), "{err}");
    later.render().expect("the files in order render");
}
