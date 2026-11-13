use demesne_emit_sql::Sql;

const HEAD: &str = "topology { level root virtual level estate parent root level space parent estate level folder parent space }\nvocabulary staff { permission invites:read permission invites:write implies invites:read }\nrolestore staff {\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n}\nsubject staff { anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }\n";
const SPACE: &str = "object space {\n  table spaces\n  level space\n  scoped estate > space\n  permission view = @holds(invites:read) @rls maps select\n}\n";

fn invite(scoped: &str, term: &str) -> String {
    format!(
        "{HEAD}{SPACE}object invite {{\n  table invites\n  scoped {scoped}\n  permission view = @holds(invites:read) + {} @rls maps select\n  permission create = @holds(invites:write) + {term} @rls maps insert\n}}\n",
        term.replace("invites:write", "invites:read")
    )
}

fn compile(src: &str) -> Result<demesne_syntax::Spec, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

const TERM: &str = "@holds(invites:write every space_ids at space)";

#[test]
fn the_term_displays_as_written_and_is_its_own_builtin() {
    let s = compile(&invite("estate", TERM)).expect("compiles");
    let create = s.objects[1].perms.iter().find(|p| p.verb == "create").expect("a create permission");
    assert_eq!(create.tree.display(), format!("@holds(invites:write) + {TERM}"));
    let every = create.tree.leaves()[1];
    assert_eq!((every.builtin(), every.holds_every(), every.holds_perm()), ("holds_every", Some(("invites:write", "space_ids", "space")), ""));
}

#[test]
fn the_policy_passes_the_array_where_the_level_goes_and_the_definer_checks_every_value() {
    let s = compile(&invite("estate", TERM)).expect("compiles");
    let sql = Sql::new(&s);
    let sub = sql.claim("sub");
    let res = sql.emit_rls().expect("the policies compile");
    let insert = &res.policies.iter().find(|p| p.name == "invites_insert").expect("an insert policy").check;
    assert!(
        insert.ends_with(&format!(
            "AND (auth.staff_has_perm({sub}, estate_id, NULL, 'invites:write') OR auth.staff_has_perm_every_space({sub}, estate_id, space_ids, 'invites:write')))"
        )),
        "{insert}"
    );
    let defs = sql.emit_definers().expect("the definers compile");
    let every = defs.iter().find(|d| d.name == "staff_has_perm_every_space").expect("the definer");
    assert_eq!(every.sig, "user_id text, check_estate_id text, check_space_ids text[], p_perm text");
    assert_eq!(
        every.body,
        "cardinality(check_space_ids) > 0 AND NOT EXISTS (SELECT 1 FROM unnest(check_space_ids) AS v(id) WHERE NOT EXISTS (SELECT 1 FROM spaces e WHERE e.id = v.id AND e.estate_id = check_estate_id) OR auth.staff_has_perm(user_id, check_estate_id, v.id, p_perm) IS NOT TRUE)"
    );
    assert!(!every.strict, "a NULL array must answer false, not NULL through strictness alone");
    assert_eq!(defs.iter().filter(|d| d.name == "staff_has_perm").count(), 1);
}

#[test]
fn the_definer_is_generated_when_the_term_stands_only_in_a_require() {
    let src = format!(
        "{HEAD}{SPACE}object invite {{\n  table invites\n  scoped estate\n  permission view = @scoped @rls maps select\n  require view = @holds(invites:read every space_ids at space)\n}}\n"
    );
    let s = compile(&src).expect("compiles");
    let names: Vec<String> = Sql::new(&s).emit_definers().expect("the definers compile").into_iter().map(|d| d.name).collect();
    assert!(names.contains(&"staff_has_perm_every_space".to_string()) && names.contains(&"staff_has_perm".to_string()), "{names:?}");
}

#[test]
fn the_term_is_refused_where_its_values_could_not_be_placed() {
    let cases = [
        ("a level that is not one", invite("estate", "@holds(invites:write every space_ids at shelf)"), "\"shelf\" is not a level that carries a scope column"),
        ("a virtual level", invite("estate", "@holds(invites:write every space_ids at root)"), "\"root\" is not a level that carries a scope column"),
        ("a level no object declares", invite("estate", "@holds(invites:write every folder_ids at folder)"), "no object declares `level folder`"),
        (
            "a level the rolestore does not reach",
            format!(
                "{}object folder {{\n  table folders\n  level folder\n  scoped estate > space > folder\n  permission view = @holds(invites:read) @rls maps select\n}}\n",
                invite("estate > space", "@holds(invites:write every folder_ids at folder)")
            ),
            "rolestore \"staff\" holds no assignment at level \"folder\"",
        ),
    ];
    for (what, src, want) in cases {
        let err = compile(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
    let unscoped = format!(
        "{HEAD}object folder {{\n  table folders\n  level folder\n  scoped estate > space > folder\n  permission view = @holds(invites:read) @rls maps select\n}}\nobject invite {{\n  table invites\n  scoped estate\n  permission view = @holds(invites:read every folder_ids at folder) @rls maps select\n}}\n"
    );
    let err = compile(&unscoped).map(|_| ()).expect_err("the invite carries no space to check a folder's against");
    assert!(err.contains("object \"invite\" is not scoped at \"space\""), "{err}");
}
