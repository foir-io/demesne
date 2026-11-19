use demesne_emit_sql::Sql;

const HEAD: &str = "topology { level estate }\nsubject member { anchor estate; reach self; identifies sub; roles none; binds owner }\n";

fn compile(rules: &str) -> Result<demesne_syntax::Spec, String> {
    let src = format!("{HEAD}object doc {{\n  table docs\n  scoped estate\n  relation owner: member via owner_id\n{rules}\n}}\n");
    let s = demesne_syntax::parse(&src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

fn policy(rules: &str, name: &str) -> String {
    let s = compile(rules).unwrap_or_else(|e| panic!("{e}\n{rules}"));
    Sql::new(&s).emit_rls().expect("the policies compile").policies.into_iter().find(|p| p.name == name).expect("the policy").using
}

#[test]
fn the_clock_term_compares_a_row_instant_with_now_and_its_negation_admits_an_unset_one() {
    let view = "  permission view = @scoped and @clock(opens_at reached) and not @clock(closes_at reached) @rls maps select";
    assert_eq!(compile(view).expect("compiles").objects[0].perms[0].tree.display(), "@scoped and @clock(opens_at reached) and not @clock(closes_at reached)");
    assert!(policy(view, "docs_select").ends_with("AND ((opens_at <= now()) AND ((closes_at <= now()) IS NOT TRUE)))"), "{}", policy(view, "docs_select"));
    let floor = "  permission view = @scoped @rls maps select\n  require view = owner + not @clock(purge_after reached)";
    assert!(policy(floor, "docs_select_require").ends_with("OR (purge_after <= now()) IS NOT TRUE"), "{}", policy(floor, "docs_select_require"));
}

#[test]
fn the_clock_term_only_narrows_in_a_permission() {
    let err = compile("  permission view = owner + @clock(opens_at reached) @rls maps select")
        .map(|_| ())
        .expect_err("it would admit everyone once the instant passes");
    assert!(err.contains("uses @clock(opens_at reached) where it would admit a caller by itself"), "{err}");
    demesne_syntax::parse(&format!(
        "{HEAD}object doc {{\n  table docs\n  scoped estate\n  permission view = @scoped and @clock(opens_at) @rls maps select\n}}\n"
    ))
    .expect_err("the term says `reached`");
}
