use demesne_model::{Structure, validate_structure};

const BASE: &str = r"topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}

vocabulary app { permission docs:read }

rolestore app {
  assignments role_grants
  subject     grantee_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
}

subject admin  { anchor tenant; reach descendants; identifies sub; roles configurable app; binds admin }
subject member { anchor project; reach self; identifies member_id; roles none; binds owner }

object doc {
  table  docs
  scoped tenant > project
  relation owner:   member via owner_id
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + grantee:read @rls maps select
}
";

fn messages(src: &str) -> Vec<String> {
    match validate_structure(&demesne_syntax::parse(src).expect("the test spec parses")) {
        Structure::Fatal(e) => panic!("the topology is sound: {e}"),
        Structure::Errors(f) => f.iter().map(|f| f.message().to_string()).collect(),
    }
}

fn with(edit: impl Fn(&str) -> String) -> Vec<String> {
    messages(&edit(BASE))
}

fn has(found: &[String], want: &str) -> bool {
    found.iter().any(|m| m.contains(want))
}

#[test]
fn the_base_spec_is_valid() {
    assert_eq!(messages(BASE), [] as [String; 0]);
}

fn check(cases: Vec<(&str, Vec<String>, &str, bool)>) {
    for (name, found, want, present) in cases {
        assert_eq!(has(&found, want), present, "{name}: expected {want:?} to be {}: {found:#?}", if present { "reported" } else { "absent" });
    }
}

#[test]
fn rules_on_subjects_claims_and_planes() {
    check(vec![
        ("claims cast", with(|b| format!("claims via \"req\" text role app_user\n{b}")), "claims cast \"text\" must be json or jsonb", true),
        (
            "transient subject without roles",
            with(|b| format!("{b}subject delegate {{ anchor project reach self identifies acting_for transient }}\n")),
            "transient subject \"delegate\" must be `roles none`",
            true,
        ),
        (
            "two admin planes",
            with(|b| format!("{b}subject admin2 {{ anchor tenant; reach descendants; identifies sub; roles configurable app; binds admin }}\n")),
            "both `binds admin`",
            true,
        ),
        (
            "a plane above the deepest level names every level below it",
            with(|b| b.replace("  scope       tenant_id project_id\n", "  scope       tenant_id\n  plane       tenant\n")),
            "names only 1 of the 2 non-virtual levels",
            true,
        ),
        (
            "a plane whose scope names every level",
            with(|b| b.replace("  scope       tenant_id project_id\n", "  scope       tenant_id project_id\n  plane       tenant\n")),
            "non-virtual levels in `scope`",
            false,
        ),
    ]);
}

#[test]
fn rules_on_objects_levels_and_terms() {
    check(vec![
        (
            "a level entity's wildcard on its own level",
            with(|b| {
                format!(
                    "{b}object project {{\n  table  projects\n  level  project\n  scoped tenant > project wildcard confers select\n  permission view = @session(admin) @rls maps select\n}}\n"
                )
            }),
            "is its own level",
            true,
        ),
        (
            "a level entity's wildcard on its parent level",
            with(|b| {
                format!(
                    "{b}object project {{\n  table  projects\n  level  project\n  scoped tenant wildcard confers select > project\n  permission view = @session(admin) @rls maps select\n}}\n"
                )
            }),
            "is its own level",
            false,
        ),
        (
            "a level that is not in the topology",
            with(|b| {
                format!(
                    "{b}object galaxy {{\n  table  galaxies\n  level  galaxy\n  scoped tenant > project\n  permission view = @session(admin) @rls maps select\n}}\n"
                )
            }),
            "declares level \"galaxy\" which is not a topology level",
            true,
        ),
        (
            "a level that is in the topology",
            with(|b| {
                format!(
                    "{b}object project {{\n  table  projects\n  level  project\n  scoped tenant > project\n  permission view = @session(admin) @rls maps select\n}}\n"
                )
            }),
            "which is not a topology level",
            false,
        ),
        (
            "a memberin relation at an unknown level",
            with(|b| {
                b.replace(
                    "  relation owner:   member via owner_id\n",
                    "  relation owner:   member via owner_id\n  relation crew: member via memberin galaxy(id, @galaxy_id) reachedby member\n",
                )
            }),
            "via memberin references unknown level \"galaxy\"",
            true,
        ),
        (
            "an app scope that excludes a grant relation",
            with(|b| {
                b.replace(
                    "permission view = owner + grantee:read @rls maps select",
                    "permission view = @app_scope(exclude grantee) + owner + grantee:read @rls maps select",
                )
            }),
            "@app_scope(exclude \"grantee\") must exclude an owner column relation",
            true,
        ),
    ]);
}

#[test]
fn rules_on_requirements_and_admit_arms() {
    check(vec![
        (
            "a requirement on a permission with a row predicate",
            with(|b| {
                b.replace(
                    "  permission view = owner + grantee:read @rls maps select\n",
                    "  permission view = owner + grantee:read @rls maps select\n  require view = @self(owner_id)\n",
                )
            }),
            "compiles no row predicate",
            false,
        ),
        (
            "a requirement on an @rls permission with no table operation",
            with(|b| {
                b.replace(
                    "  permission view = owner + grantee:read @rls maps select\n",
                    "  permission view = owner + grantee:read @rls maps select\n  permission share = owner @rls\n  require share = @self(owner_id)\n",
                )
            }),
            "is @rls with no `maps` table-op",
            true,
        ),
        (
            "a requirement on a permission only the kernel layer compiles",
            with(|b| {
                b.replace(
                    "  permission view = owner + grantee:read @rls maps select\n",
                    "  permission view = owner + grantee:read @rls maps select\n  permission share = owner @kernel\n  require share = @self(owner_id)\n",
                )
            }),
            "permission \"share\" compiles no row predicate",
            true,
        ),
        (
            "a requirement on a permission the check layer compiles",
            with(|b| {
                b.replace(
                    "  permission view = owner + grantee:read @rls maps select\n",
                    "  permission view = owner + grantee:read @rls maps select\n  permission share = owner @check\n  require share = @self(owner_id)\n",
                )
            }),
            "compiles no row predicate",
            false,
        ),
        (
            "an admit arm joining only a kernel permission",
            with(|b| {
                b.replace(
                    "  permission view = owner + grantee:read @rls maps select\n",
                    "  permission view = owner + grantee:read @rls maps select\n  permission edit = owner @kernel maps update\n  admit update = owner\n",
                )
            }),
            "admits update, but no @rls permission maps update",
            true,
        ),
    ]);
}

#[test]
fn rules_on_borrowed_verbs() {
    check(vec![
        (
            "an acyclic chain of borrowed verbs, borrower first",
            with(|b| {
                format!(
                    "{b}object alpha {{\n  table  alphas\n  scoped tenant > project\n  relation up: member via object beta->view on beta_id\n  permission view = up @rls maps select\n}}\nobject beta {{\n  table  betas\n  scoped tenant > project\n  relation owner: member via owner_id\n  permission view = owner @rls maps select\n}}\n"
                )
            }),
            "form a cycle",
            false,
        ),
        (
            "borrowed verbs that form a cycle",
            with(|b| {
                format!(
                    "{}object note {{\n  table  notes\n  scoped tenant > project\n  relation parent: member via object doc->view on doc_id\n  permission view = parent @rls maps select\n}}\n",
                    b.replace(
                        "  relation owner:   member via owner_id\n",
                        "  relation owner:   member via owner_id\n  relation child: member via object note->view on note_id\n"
                    )
                )
            }),
            "form a cycle through",
            true,
        ),
    ]);
}

#[test]
fn a_grant_built_without_its_edge_columns_is_refused() {
    let mut s = demesne_syntax::parse(&format!("{BASE}grant shared at project via edge shares(grantee_id, project_id)\n")).expect("the test spec parses");
    for strip in [0, 1, 2] {
        let mut broken = s.clone();
        let g = broken.grants.iter_mut().find(|g| g.name == "shared").expect("the grant parses");
        match strip {
            0 => g.table = None,
            1 => g.grantee_col = None,
            _ => g.level_col = None,
        }
        let Structure::Errors(found) = validate_structure(&broken) else { panic!("the topology is sound") };
        assert!(found.iter().any(|f| f.message().contains("grant \"shared\" must name an edge table, grantee column and level column")), "{strip}: {found:#?}");
    }
    s.grants.retain(|g| g.name != "shared");
}
