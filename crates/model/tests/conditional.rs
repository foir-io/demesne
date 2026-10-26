use demesne_model::{ConditionalAdmission, ConditionalExt};

const SPEC: &str = r"topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}

subject admin  { anchor tenant; reach descendants; identifies sub; roles none; binds admin }
subject member { anchor project; reach self; identifies member_id; roles none; binds owner }

object doc {
  table  docs
  scoped tenant > project
  relation owner:   member via owner_id
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = VIEW @rls maps select
}
";

fn admissions(view: &str) -> Vec<ConditionalAdmission> {
    let s = demesne_syntax::parse(&SPEC.replace("VIEW", view)).expect("the spec parses");
    match demesne_model::validate_structure(&s) {
        demesne_model::Structure::Errors(f) if f.is_empty() => {}
        demesne_model::Structure::Errors(f) => panic!("{view}: {f:#?}"),
        demesne_model::Structure::Fatal(e) => panic!("{view}: {e}"),
    }
    let doc = s.objects.iter().find(|o| o.name == "doc").expect("a doc object");
    s.conditional_accessors(doc)
}

fn claim(key: &str, val: &str, row_cond: &str) -> ConditionalAdmission {
    ConditionalAdmission { source: "claim".into(), claim_key: key.into(), claim_val: val.into(), row_cond: row_cond.into(), ..Default::default() }
}

#[test]
fn a_conjunction_of_claims_admits_on_its_first_claim() {
    assert_eq!(admissions(r#"owner + (@claim("tier", "gold") and @claim("region", "eu"))"#), [claim("tier", "gold", "")]);
}

#[test]
fn a_later_admissions_row_condition_joins_the_first_admissions() {
    assert_eq!(admissions(r#"owner + (@claim("tier", "gold") and mode visibility = "open")"#), [claim("tier", "gold", "visibility = 'open'")]);
}

#[test]
fn a_negated_narrowing_term_leaves_the_conjunction_listable() {
    assert_eq!(admissions(r#"owner + (@claim("tier", "gold") and @row(status, "open") and not @kind("guest"))"#), [claim("tier", "gold", "status = 'open'")]);
}
