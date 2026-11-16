use demesne_emit_sql::{Execute, GenFn, Sql};

const HEAD: &str = "topology { level estate level space parent estate }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }
";

const ENTRY: &str = "object entry {
  table entries
  scoped estate > space
  relation in_open: member via object ledger->open_only on ledger_id for select
  permission view = @scoped and in_open @rls maps select
}
";

fn spec(ledger: &str, entry: &str) -> String {
    format!(
        "{HEAD}object ledger {{\n  table ledgers\n  scoped estate\n  permission view = @scoped @rls maps select\n  permission open_only = @scoped and @row(state, \"open\") @rls predicate\n{ledger}\n}}\n{entry}"
    )
}

fn definers(src: &str) -> Result<Vec<GenFn>, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Sql::new(&s).emit_definers().map_err(|e| e.to_string())
}

fn named<'a>(defs: &'a [GenFn], name: &str) -> &'a GenFn {
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"))
}

#[test]
fn a_point_check_is_the_borrow_of_its_permission_on_the_one_row_its_key_names() {
    for (check, borrow) in [("check open_only for select", "ledger_can_open_only_for_select"), ("check open_only", "ledger_can_open_only")] {
        let entry = if borrow.ends_with("_for_select") { ENTRY.to_string() } else { ENTRY.replace(" for select\n", "\n") };
        let src = spec(&format!("  {check} as ledger_open(id text as id)"), &entry);
        let defs = definers(&src).expect("compiles");
        let borrow = named(&defs, borrow);
        assert!(borrow.body.contains("ledgers.id = p_ledger_id AND "), "the borrow's key: {}", borrow.body);
        let point = named(&defs, "ledger_open");
        assert_eq!((point.sig.as_str(), point.strict, point.principal.as_deref()), ("id text", true, None), "{}", point.create_sql());
        assert_eq!(point.body, borrow.body.replace("ledgers.id = p_ledger_id AND ", "ledgers.id = $1 AND "), "{check}");
        assert!(!point.body.contains("= id") && !point.body.contains("(id)"), "the argument is never read by its name: {}", point.body);
    }
}

#[test]
fn a_point_checks_operation_chooses_which_borrow_it_answers_as() {
    let any = ENTRY.replace("object entry", "object stub").replace("table entries", "table stubs").replace(" for select\n", "\n");
    let src = spec("  check open_only for select as open_read(id text)\n  check open_only as open_any(id text)", &format!("{ENTRY}{any}"))
        .replace("table ledgers\n  scoped estate\n", "table ledgers\n  scoped estate wildcard confers select\n");
    let defs = definers(&src).expect("compiles");
    let keyed = |borrow: &str| named(&defs, borrow).body.replace("ledgers.id = p_ledger_id AND ", "ledgers.id = $1 AND ");
    let (read, any) = (named(&defs, "open_read"), named(&defs, "open_any"));
    assert_ne!(read.body, any.body, "a select reads a row with no estate, and no operation does not");
    assert_eq!(read.body, keyed("ledger_can_open_only_for_select"));
    assert_eq!(any.body, keyed("ledger_can_open_only"));
}

#[test]
fn a_point_check_is_the_adopters_to_call_and_answers_without_a_principal() {
    let src = spec("  check open_only as ledger_open(id text as ledger)", "");
    let s = demesne_syntax::parse(&src).expect("parses");
    demesne_emit_sql::validate(&s).expect("a check is a use of the permission it lends");
    let defs = Sql::new(&s).emit_definers().expect("compiles");
    let check = named(&defs, "ledger_open");
    assert_eq!(check.sig, "ledger text");
    assert_eq!(check.execute, Execute::Public, "{}", check.create_sql());
    assert!(check.create_sql().contains("SECURITY DEFINER"), "{}", check.create_sql());
    assert!(!defs.iter().any(|d| d.name.starts_with("ledger_can_")), "no borrow, so no borrow function");
    let lists = Sql::new(&s).manifest().expect("a manifest").execute.expect("the manifest records who may run each function");
    assert!(lists.callable.contains("auth.ledger_open(text)"), "{lists:?}");
}

#[test]
fn a_point_check_is_refused_where_it_would_not_answer_one_row_of_a_lent_permission() {
    let cases = [
        ("an unknown permission", spec("  check gone as f(id text)", ""), "check \"f\": object \"ledger\" has no permission \"gone\""),
        (
            "a mapped permission",
            spec("  check view as f(id text)", ""),
            "check \"f\": permission \"view\" maps select, and a check answers a predicate-only permission; an export answers a mapped one",
        ),
        (
            "a permission it does not lend",
            spec("  permission peek = @scoped @check\n  check peek as f(id text)", ""),
            "check \"f\": permission \"peek\" is not predicate-only, and a check answers a permission lent with `predicate`",
        ),
        ("an unknown operation", spec("  check open_only for read as f(id text)", ""), "check \"f\" is for unknown operation \"read\""),
        ("a column that is not the key", spec("  check open_only as f(state text)", ""), "check \"f\" takes the key \"id\", not \"state\""),
        ("two arguments", spec("  check open_only as f(id text, state text)", ""), "check \"f\" takes one argument, the key \"id\""),
        ("an unsupported type", spec("  check open_only as f(id varchar)", ""), "check \"f\" argument \"p_id\" has unsupported type \"varchar\""),
        (
            "a probe's name",
            spec("  probe f(id text)\n  check open_only as f(id text)", ""),
            "check \"f\" shares its name with another generated function of the spec",
        ),
        ("a projection's name", spec("  projection f(id text) = @scoped\n  check open_only as f(id text)", ""), "check \"f\" shares its name"),
        ("another check's name", spec("  check open_only as f(id text)\n  check open_only for update as f(id text)", ""), "check \"f\" shares its name"),
        (
            "a composite key",
            spec("  check open_only as f(estate_id text)", "").replace("table ledgers\n", "table ledgers pk (estate_id, code)\n"),
            "check \"f\" is on object \"ledger\", which has a composite key",
        ),
    ];
    for (what, src, want) in cases {
        let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{what}: {e}"));
        let err = demesne_emit_sql::validate(&s).expect_err(what).to_string();
        let line =
            src.lines().enumerate().filter(|(_, l)| l.trim_start().starts_with("check ")).last().map(|(i, _)| i + 1).expect("each case declares a check");
        assert!(err.contains(&format!("line {line}: {want}")), "{what}: the refusal names the check's line {line}: {err}");
    }
    let taken = spec("  check open_only as ledger_can_open_only_for_select(id text)", ENTRY);
    let err = definers(&taken).map(|_| ()).expect_err("a generated function's name");
    assert!(err.contains("check \"ledger_can_open_only_for_select\" collides with a generated function"), "{err}");
    demesne_syntax::parse(&spec("  check open_only as f()", "")).expect_err("a check names the key");
    demesne_syntax::parse(&spec("  check open_only f(id text)", "")).expect_err("a check names its function after `as`");
}

#[test]
fn a_lent_permission_nothing_borrows_or_checks_is_still_refused() {
    let err = definers(&spec("", "")).map(|_| ()).expect_err("a lent permission with no use");
    assert!(err.contains("permission ledger.open_only is `predicate`"), "{err}");
}
