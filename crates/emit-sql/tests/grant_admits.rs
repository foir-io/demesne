use demesne_emit_sql::Sql;
use demesne_syntax::parse;

fn spec(grant: &str) -> String {
    format!(
        r#"topology {{
  level org     virtual
  level project parent org
}}
subject member {{ anchor project; reach self; identifies sub; roles none; binds owner }}
object doc {{
  table docs
  scoped project
  relation owner: member via owner_id
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access) where resource = "doc"{grant}
  permission view = owner + grantee:read @rls maps select
  permission edit = owner + grantee:write @rls maps update
}}
"#
    )
}

fn sql(grant: &str) -> String {
    let s = parse(&spec(grant)).unwrap_or_else(|e| panic!("{grant:?} doesn't parse: {e}"));
    let mut b = String::new();
    Sql::new(&s).write_all_sql(&mut b).unwrap_or_else(|e| panic!("{grant:?} doesn't emit: {e}"));
    b
}

fn grant_definer(sql: &str) -> &str {
    let start = sql.find("CREATE OR REPLACE FUNCTION auth.doc_acl_grants_doc(").unwrap_or_else(|| panic!("no grant definer in:\n{sql}"));
    let end = sql[start..].find("$$;").map_or(sql.len(), |e| start + e);
    &sql[start..end]
}

#[test]
fn a_grant_term_admits_its_own_class_alone_by_default() {
    let plain = sql("");
    let definer = grant_definer(&plain);
    assert!(definer.contains("AND access = p_access)"), "{definer}");
    assert!(!definer.contains(" IN ("), "{definer}");
}

#[test]
fn an_admitted_class_widens_only_its_own_class_in_one_definer() {
    let wide = sql(" read admits write, delete");
    let definer = grant_definer(&wide);
    assert!(definer.contains("AND (access = p_access OR (p_access = 'read' AND access IN ('write', 'delete'))))"), "{definer}");
    let plain = sql("");
    let head = |d: &str| d.split("$$").next().unwrap_or(d).to_string();
    assert_eq!(head(definer), head(grant_definer(&plain)), "the definer keeps its signature and strictness");
    assert_eq!(wide.replacen(definer, grant_definer(&plain), 1), plain, "an admitted class changes the grant definer's body and nothing else");
}
