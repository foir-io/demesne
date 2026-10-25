use demesne_model::pdp::emit_pdp;

const SPEC: &str = "topology {
  level org col org_ref claim org
}

procedures missing {
  a.v1.Service/Get -> x:read
}
";

#[test]
fn an_emitter_error_names_the_emitter_and_indents_each_finding_under_it() {
    let s = demesne_syntax::parse(SPEC).expect("the spec parses");
    let err = emit_pdp(&s).expect_err("the procedures block targets an undeclared vocabulary");
    assert_eq!(err.to_string(), "PDP emit:\n  line 5: procedures block targets unknown vocabulary \"missing\" (V10)");
    let found: Vec<(Option<usize>, &str)> = err.findings().iter().map(|f| (f.line(), f.message())).collect();
    assert_eq!(found, [(Some(5), "procedures block targets unknown vocabulary \"missing\" (V10)")]);
}
