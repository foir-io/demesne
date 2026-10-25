use demesne_emit_sql::validate;

fn spec(objects: &str) -> String {
    format!(
        r"
topology {{
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}}

subject member {{ anchor workspace reach self identifies member_ref roles none binds owner }}

{objects}
"
    )
}

fn object(name: &str, perm: &str, extra: &str) -> String {
    format!(
        r"object {name} {{
  table  items
  pk     item_pk
  scoped org > workspace
  relation owner: member via owner_ref
  {perm}
  {extra}
}}
"
    )
}

const BORROWER: &str = r"object reader {
  table  readers
  pk     reader_pk
  scoped org > workspace
  relation item: second via object second->bound on item_ref
  permission view = item @rls maps select
}
";

fn check(src: &str) -> Result<(), String> {
    validate(&demesne_syntax::parse(src).expect("the test spec parses"))
}

#[test]
fn two_objects_compiling_one_policy_name_on_a_table_are_refused() {
    let err = check(&spec(
        &[object("first", "permission view = owner @rls maps select", ""), object("second", "permission view = owner @rls maps select", "")].concat(),
    ))
    .expect_err("the second policy would replace the first");
    assert!(err.contains(r#"objects "first", "second" on table "items" each compile a policy named "items_select""#), "{err}");
}

#[test]
fn a_second_object_with_only_predicate_permissions_shares_the_table() {
    let res = check(&spec(
        &[
            object("first", "permission view = owner @rls maps select", ""),
            object("second", "permission bound = owner @rls predicate", ""),
            BORROWER.to_string(),
        ]
        .concat(),
    ));
    assert_eq!(res, Ok(()));
}

#[test]
fn two_objects_tracking_one_table_are_refused() {
    let err = check(&spec(
        &[
            object("first", r#"permission view = owner + mode visibility = "open" @rls maps select"#, "track visibility"),
            object("second", r#"permission bound = owner + mode visibility = "open" @rls predicate"#, "track visibility"),
            BORROWER.to_string(),
        ]
        .concat(),
    ))
    .expect_err("the second changelog trigger would replace the first");
    assert!(err.contains(r#"objects "first", "second" each track changes on table "items""#), "{err}");
}

#[test]
fn two_objects_keeping_one_async_index_name_are_refused() {
    let grant = |t: &str| format!("relation viewer: member via grant {t}(item_ref, kind, principal_ref, access) tracked async");
    let err = check(&spec(
        &[
            object("first", "permission view = owner + viewer @rls maps select", &grant("first_grants")),
            object("second", "permission bound = owner + viewer @rls predicate", &grant("second_grants")),
            BORROWER.to_string(),
        ]
        .concat(),
    ))
    .expect_err("the second index's functions would replace the first's");
    assert!(err.contains(r#"objects "first", "second" each keep an async index named "auth.items_viewer_async""#), "{err}");
}
