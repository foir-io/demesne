use demesne_emit_sql::Sql;
use demesne_postgres::Grantees;

const SPEC: &str = "topology { level tenant }
subject member { anchor tenant; reach self; identifies sub; roles none }
object doc {
  table docs
  scoped tenant
  permission view = @scoped @rls maps select
}
";

#[test]
fn public_is_refused_as_a_grantee_by_name() {
    let s = demesne_syntax::parse(SPEC).expect("the spec parses");
    let manifest = Sql::new(&s).manifest().expect("a manifest");
    for name in ["PUBLIC", "public", "Public"] {
        let e = Grantees::new(&manifest, &["worker".to_string(), name.to_string()]).expect_err(name);
        assert!(e.is_grantee(), "{name}: {e}");
        assert!(e.to_string().contains("PUBLIC holds exactly the functions the SQL grants to PUBLIC"), "{name}: {e}");
    }
    let empty = Grantees::new(&manifest, &[String::new()]).expect_err("an empty role");
    assert!(empty.is_grantee(), "{empty}");
    Grantees::new(&manifest, &["worker".to_string()]).expect("a worker role is a grantee");
}
