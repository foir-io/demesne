use demesne_model::{ClaimMatch, ClaimValue, ConditionalAdmission, ConditionalExt};

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

const ROLE_SPEC: &str = r#"topology {
  level org       virtual
  level tenant    parent org
  level workspace parent tenant
}
vocabulary staff {
  permission docs:read
  preset viewer @ workspace = docs:read
}
rolestore staff {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id workspace_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject staff  { anchor tenant; reach descendants; identifies sub; roles configurable staff; binds admin }
subject member { anchor workspace; reach self; identifies member_id; roles none; binds owner }
object doc {
  table  docs
  scoped tenant > workspace
  relation owner:   member via owner_id
  relation editor:  staff via role
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = VIEW @rls maps select
}
"#;

fn admissions(view: &str) -> Vec<ConditionalAdmission> {
    admissions_in(SPEC, view)
}

fn admissions_in(spec: &str, view: &str) -> Vec<ConditionalAdmission> {
    let s = demesne_syntax::parse(&spec.replace("VIEW", view)).expect("the spec parses");
    match demesne_model::validate_structure(&s) {
        demesne_model::Structure::Errors(f) if f.is_empty() => {}
        demesne_model::Structure::Errors(f) => panic!("{view}: {f:#?}"),
        demesne_model::Structure::Fatal(e) => panic!("{view}: {e}"),
    }
    let doc = s.objects.iter().find(|o| o.name == "doc").expect("a doc object");
    s.conditional_accessors(doc)
}

fn lit(key: &str, val: &str) -> ClaimMatch {
    ClaimMatch { key: key.into(), value: ClaimValue::Literal(val.into()) }
}

fn col(key: &str, column: &str) -> ClaimMatch {
    ClaimMatch { key: key.into(), value: ClaimValue::Column(column.into()) }
}

fn row(source: &str, claims: &[ClaimMatch], row_cond: &str) -> ConditionalAdmission {
    ConditionalAdmission { source: source.into(), claims: claims.to_vec(), row_cond: row_cond.into(), ..Default::default() }
}

#[test]
fn a_conjunction_of_claims_requires_every_claim() {
    assert_eq!(admissions(r#"owner + (@claim("tier", "gold") and @claim("region", "eu"))"#), [row("claim", &[lit("tier", "gold"), lit("region", "eu")], "")]);
}

#[test]
fn a_claim_side_conjunct_joins_the_row_in_the_order_written() {
    assert_eq!(admissions(r#"owner + (@kind("staff") and @claim("tier", "gold"))"#), [row("claim", &[lit("kind", "staff"), lit("tier", "gold")], "")]);
    assert_eq!(
        admissions(r#"owner + (@claim("tier", "gold") and @within(tenant))"#),
        [row("claim", &[lit("tier", "gold"), col("tenant_id", "tenant_id")], "")]
    );
}

#[test]
fn a_conjunction_of_claim_side_terms_alone_lists_one_claim_row() {
    assert_eq!(admissions(r#"owner + (@kind("staff") and @session)"#), [row("claim", &[lit("kind", "staff"), col("project_id", "project_id")], "")]);
}

#[test]
fn a_mode_row_carries_the_claims_beside_it() {
    assert_eq!(admissions(r#"owner + (mode visibility = "open" and @kind("staff"))"#), [row("mode", &[lit("kind", "staff")], "visibility = 'open'")]);
}

#[test]
fn a_later_admissions_row_condition_joins_the_first_admissions() {
    assert_eq!(admissions(r#"owner + (@claim("tier", "gold") and mode visibility = "open")"#), [row("claim", &[lit("tier", "gold")], "visibility = 'open'")]);
}

#[test]
fn a_conjunct_no_row_can_state_is_left_out_and_never_narrows_the_listing_below_the_policy() {
    for conjunct in ["not @kind(\"guest\")", "@scoped", "@within(tenant nullable)"] {
        assert_eq!(
            admissions(&format!(r#"owner + (@claim("tier", "gold") and @row(status, "open") and {conjunct})"#)),
            [row("claim", &[lit("tier", "gold")], "status = 'open'")],
            "{conjunct}"
        );
    }
}

#[test]
fn a_conjunction_beside_a_relation_lists_no_conditional_row() {
    assert_eq!(admissions(r#"owner + (grantee:read and @claim("tier", "gold"))"#), []);
}

#[test]
fn a_session_on_a_role_carries_its_scope_claim_and_leaves_out_the_role() {
    assert_eq!(
        admissions_in(ROLE_SPEC, r#"owner + (@session(editor) and @claim("tier", "gold"))"#),
        [row("claim", &[col("workspace_id", "workspace_id"), lit("tier", "gold")], "")]
    );
}
