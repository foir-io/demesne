use demesne_model::pdp::{FieldAccess, FieldAccessRule, emit_field_access, emit_field_scopes};
use std::collections::BTreeMap;

fn parse(src: &str) -> demesne_syntax::Spec {
    demesne_syntax::parse(src).expect("the test spec parses")
}

const TOPOLOGY: &str = "topology {
  level tenant
  level project parent tenant
}
";

#[test]
fn field_scopes_map_each_sites_fields_to_their_scope() {
    let s = parse(&format!(
        "{TOPOLOGY}
fieldscopes billing {{
  plan -> billing:manage
  seats -> billing:manage
  plan -> billing:manage
}}
fieldscopes profile {{
  nickname -> profile:edit
}}
"
    ));
    let scopes = |pairs: &[(&str, &str)]| pairs.iter().map(|(f, s)| ((*f).to_string(), (*s).to_string())).collect::<BTreeMap<_, _>>();
    let want = BTreeMap::from([
        ("billing".to_string(), scopes(&[("plan", "billing:manage"), ("seats", "billing:manage")])),
        ("profile".to_string(), scopes(&[("nickname", "profile:edit")])),
    ]);
    assert_eq!(emit_field_scopes(&s), Ok(want));
}

#[test]
fn a_field_mapped_to_two_scopes_is_refused_on_its_line() {
    let s = parse(&format!(
        "{TOPOLOGY}
fieldscopes billing {{
  plan -> billing:manage
  plan -> billing:read
}}
"
    ));
    let err = emit_field_scopes(&s).expect_err("plan has two scopes");
    assert_eq!(err.to_string(), "field-scopes emit:\n  line 8: field \"plan\" mapped to both billing:manage and billing:read");
    assert_eq!(err.findings().iter().map(demesne_syntax::Finding::line).collect::<Vec<_>>(), [Some(8)]);
}

#[test]
fn field_access_lists_each_objects_principals_sorted_and_its_rules_in_order() {
    let s = parse(&format!(
        "{TOPOLOGY}
object profile {{
  table  profiles
  scoped tenant > project
  fields {{ self service admin }}
  field ssn {{ read = admin write = admin }}
  field nickname {{ read = public + self write = self + admin }}
  field secret {{ write = admin column secret_col }}
}}
object note {{
  table  notes
  scoped tenant > project
}}
"
    ));
    let rule = |field: &str, read: &[&str], write: &[&str], column: &str| FieldAccessRule {
        field: field.into(),
        read: read.iter().map(|r| (*r).to_string()).collect(),
        write: write.iter().map(|w| (*w).to_string()).collect(),
        column: column.into(),
    };
    let want = FieldAccess {
        object: "profile".into(),
        principals: vec!["admin".into(), "self".into(), "service".into()],
        rules: vec![
            rule("ssn", &["admin"], &["admin"], ""),
            rule("nickname", &["public", "self"], &["self", "admin"], ""),
            rule("secret", &[], &["admin"], "secret_col"),
        ],
    };
    assert_eq!(emit_field_access(&s), BTreeMap::from([("profile".to_string(), want)]));
}
