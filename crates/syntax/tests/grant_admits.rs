use demesne_syntax::{GrantAdmits, Repr, parse};

fn spec(grant: &str) -> String {
    format!(
        "subject member {{ anchor workspace; reach self; identifies sub; roles none }}\nobject doc {{\n  table docs\n  scoped workspace\n  relation owner: member via owner_id\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access){grant}\n  permission view = owner + grantee:read @rls maps select\n}}\n"
    )
}

fn admits(grant: &str) -> (Vec<GrantAdmits>, bool) {
    let s = parse(&spec(grant)).unwrap_or_else(|e| panic!("{grant:?} doesn't parse: {e}"));
    match &s.objects[0].relations[1].repr {
        Repr::Grant(vg) => (vg.admits.clone(), vg.tracked),
        other => panic!("the grantee relation is not a grant: {other:?}"),
    }
}

fn rule(access: &str, also: &[&str]) -> GrantAdmits {
    GrantAdmits { access: access.into(), also: also.iter().map(|c| (*c).to_string()).collect() }
}

#[test]
fn a_grant_relation_says_which_classes_each_class_admits() {
    assert_eq!(admits(""), (vec![], false));
    assert_eq!(admits(" read admits write, delete"), (vec![rule("read", &["write", "delete"])], false));
    assert_eq!(admits(" read admits write write admits delete tracked"), (vec![rule("read", &["write"]), rule("write", &["delete"])], true));
    assert_eq!(admits(" where kind = \"doc\" read admits delete tracked"), (vec![rule("read", &["delete"])], true));
}

#[test]
fn an_admits_clause_names_at_least_one_class() {
    for clause in [" read admits", " read admits tracked"] {
        let src = spec(clause).replace(" admits tracked", " admits\n  tracked");
        let err = parse(&src).expect_err("an admits clause naming no class parses");
        assert!(err.to_string().ends_with("\"read\" admits no class: name the classes it admits after `admits`, on its line"), "{clause:?}: {err}");
    }
}
