use demesne_emit_sql::Sql;

const HEAD: &str = "topology { level tenant level project parent tenant }
subject customer { anchor project; reach self; identifies customer_id; roles none; binds owner }
subject staff { anchor project; reach self; identifies sub; roles none }
";

fn emitted(objects: &str) -> Result<String, String> {
    let s = demesne_syntax::parse(&format!("{HEAD}{objects}")).map_err(|e| format!("{e:?}"))?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    let sql = Sql::new(&s);
    let rls = sql.emit_rls().map_err(|e| e.to_string())?;
    Ok(rls.policies.iter().map(|p| p.using.clone()).collect::<Vec<_>>().join("\n"))
}

fn refused(objects: &str) -> String {
    match emitted(objects) {
        Ok(sql) => panic!("emitted where it must be refused:\n{sql}"),
        Err(e) => e,
    }
}

fn claim(key: &str) -> String {
    format!("(SELECT current_setting('request.jwt.claims', true)::json ->> '{key}')")
}

const TEAM: &str = "via group tc(grp, mem) edge te(mem, grp) on team_id";

#[test]
fn a_group_of_another_subject_is_refused_until_it_says_which_claim_matches_its_members() {
    let bare = format!(
        "object doc {{ table docs; scoped tenant > project; relation owner: customer via owner_id; relation team: staff {TEAM}; permission view = owner + team @rls maps select }}"
    );
    let e = refused(&bare);
    for part in [
        "relation \"team\" names staff",
        "the owner's claim \"customer_id\"",
        &format!("`relation team: staff {TEAM} from claim sub`"),
        "name the owner subject alone",
    ] {
        assert!(e.contains(part), "{part}:\n{e}");
    }
    let said = bare.replace("on team_id;", "on team_id from claim sub;");
    let sql = emitted(&said).unwrap_or_else(|e| panic!("{e}"));
    assert!(sql.contains(&format!("(auth.tc_member(team_id, {}) AND {} IS NULL)", claim("sub"), claim("customer_id"))), "{sql}");
}

#[test]
fn a_group_of_the_owner_subject_needs_no_claim_and_matches_the_owners() {
    let sql =
        emitted(&format!("object doc {{ table docs; scoped tenant > project; relation team: customer {TEAM}; permission view = team @rls maps select }}"))
            .unwrap_or_else(|e| panic!("{e}"));
    assert!(sql.contains(&format!("auth.tc_member(team_id, {})", claim("customer_id"))) && !sql.contains("IS NULL"), "{sql}");
}

#[test]
fn a_group_of_two_subjects_shows_both_claims_and_matches_each_when_it_names_them() {
    let bare = format!("object doc {{ table docs; scoped tenant > project; relation team: customer | staff {TEAM}; permission view = team @rls maps select }}");
    let e = refused(&bare);
    assert!(e.contains(&format!("`relation team: customer | staff {TEAM} from claim customer_id | sub`")), "{e}");
    let sql = emitted(&bare.replace("on team_id;", "on team_id from claim customer_id | sub;")).unwrap_or_else(|e| panic!("{e}"));
    assert!(sql.contains(&format!("auth.tc_member(team_id, {}) OR", claim("customer_id"))), "{sql}");
    assert!(sql.contains(&format!("(auth.tc_member(team_id, {}) AND {} IS NULL)", claim("sub"), claim("customer_id"))), "{sql}");
    let owners = emitted(&bare.replace("on team_id;", "on team_id from claim customer_id;")).unwrap_or_else(|e| panic!("{e}"));
    assert!(!owners.contains(&claim("sub")), "naming the owner's claim alone matches the owner's members alone:\n{owners}");
}

#[test]
fn a_group_claim_must_be_a_subjects_identity() {
    let e = refused(&format!(
        "object doc {{ table docs; scoped tenant > project; relation team: staff {TEAM} from claim tenant_id; permission view = team @rls maps select }}"
    ));
    assert!(e.contains("`from claim tenant_id` names no subject's identity claim"), "{e}");
}

#[test]
fn a_closure_of_another_subject_is_refused_until_it_says_from_claim() {
    let bare = "object page { table pages; scoped tenant > project; relation in_folder: staff via closure fp(ancestor_id, descendant_id) base folders(id, parent_id) on folder_id; permission view = in_folder @rls maps select }";
    let e = refused(bare);
    for part in ["relation \"in_folder\" names staff", "the caller's node is read from the owner's claim", "from claim sub missing deny`"] {
        assert!(e.contains(part), "{part}:\n{e}");
    }
    let sql = emitted(&bare.replace("on folder_id;", "on folder_id from claim sub missing deny;")).unwrap_or_else(|e| panic!("{e}"));
    assert!(sql.contains(&format!("auth.fp_reachable({}, folder_id)", claim("sub"))), "{sql}");
}

const GRANTEE: &str = "relation grantee: customer | staff via grant acl(resource_id, principal_kind, principal_id, access)";

#[test]
fn a_session_over_several_calls_is_refused_until_it_names_the_subjects_it_admits() {
    let session = |form: &str| format!("object doc {{ table docs; scoped tenant > project; {GRANTEE}; permission view = {form} @rls maps select }}");
    let e = refused(&session("@session(grantee)"));
    for part in [
        "`@session(grantee)` admits through relation \"grantee\"",
        "`@session(grantee as customer)` to keep that",
        "`@session(grantee as customer | staff)` to admit each",
    ] {
        assert!(e.contains(part), "{part}:\n{e}");
    }
    let first = emitted(&session("@session(grantee as customer)")).unwrap_or_else(|e| panic!("{e}"));
    assert!(first.contains("auth.acl_grants(") && !first.contains("acl_grants_staff"), "the first subject's call alone, as v4.0.0 emitted:\n{first}");
    let each = emitted(&session("@session(grantee as customer | staff)")).unwrap_or_else(|e| panic!("{e}"));
    assert!(each.contains("auth.acl_grants(") && each.contains("auth.acl_grants_staff("), "{each}");
    let stray = refused(&session("@session(grantee as admin)"));
    assert!(stray.contains("relation \"grantee\" names no subject \"admin\""), "{stray}");
}

#[test]
fn a_session_names_its_subjects_as_it_is_written() {
    let s = demesne_syntax::parse(&format!(
        "{HEAD}object doc {{ table docs; scoped tenant > project; {GRANTEE}; permission view = @session(grantee as customer | staff) @rls maps select }}"
    ))
    .expect("the spec parses");
    let term = &s.objects[0].perms[0].tree.leaves()[0];
    assert_eq!((term.session_rel(), term.session_subjects()), ("grantee", &["customer".to_string(), "staff".to_string()][..]));
    let demesne_syntax::TermKind::Builtin(b) = &term.kind else { panic!("{term:?} is a builtin") };
    assert_eq!(b.display(), "@session(grantee as customer | staff)");
}
