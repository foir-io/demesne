use demesne_emit_sql::{GenFn, Sql};

const FORMS: &str = "  form claim channel = \"draft\" base\n  form claim channel = \"live\" permissions live_permissions\n  absent claim reads \"live\"\n";

fn spec(lines: &str) -> String {
    format!(
        "topology {{ level estate level space parent estate }}\nvocabulary staff {{ permission docs:read permission docs:write }}\nrolestore staff {{\n  assignments role_grants\n  subject     grantee_id\n  scope       estate_id space_id\n  rolejoin    role_id roles id key\n  permissions permissions\n{lines}}}\nsubject staff {{ anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }}\nobject doc {{\n  table docs\n  scoped estate > space wildcard\n  permission view = @holds(docs:read) @rls maps select\n}}\n"
    )
}

fn definers(src: &str) -> Result<Vec<GenFn>, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    let sql = Sql::new(&s);
    let channel = sql.claim("channel");
    Ok(sql.emit_definers().map_err(|e| e.to_string())?.into_iter().map(|d| GenFn { body: d.body.replace(&channel, "CHANNEL"), ..d }).collect())
}

fn text(defs: &[GenFn]) -> String {
    defs.iter().map(|d| [d.name.as_str(), " ", d.body.as_str(), "\n"].concat()).collect()
}

fn holds(defs: &[GenFn]) -> &str {
    &defs.iter().find(|d| d.name == "staff_has_perm").expect("the permission check").body
}

const PICKED: &str = "CASE COALESCE(CHANNEL, 'live') WHEN 'draft' THEN r.permissions WHEN 'live' THEN r.live_permissions END";

#[test]
fn a_store_with_none_of_the_lines_emits_what_it_did() {
    let defs = definers(&spec("")).expect("compiles");
    assert!(holds(&defs).ends_with("AND p_perm = ANY(r.permissions))"), "{}", holds(&defs));
    assert!(!text(&defs).contains("CASE COALESCE"));
}

#[test]
fn the_claim_picks_the_form_a_role_is_read_in_and_an_unnamed_value_picks_none() {
    let defs = definers(&spec(FORMS)).expect("compiles");
    assert!(holds(&defs).ends_with(&format!("AND p_perm = ANY(({PICKED})))")), "{}", holds(&defs));
    let other = definers(&spec(&FORMS.replace("reads \"live\"", "reads \"draft\""))).expect("compiles");
    assert!(holds(&other).contains("COALESCE(CHANNEL, 'draft')"), "the spec names the form an absent claim takes:\n{}", holds(&other));
}

#[test]
fn an_unversioned_role_is_read_from_the_base_whatever_the_claim_says() {
    let defs = definers(&spec(&format!("{FORMS}  unversioned estate_id null\n  unversioned source = \"builtin\"\n"))).expect("compiles");
    assert!(
        holds(&defs).ends_with(&format!("AND p_perm = ANY((CASE WHEN r.estate_id IS NULL OR r.source = 'builtin' THEN r.permissions ELSE {PICKED} END)))")),
        "{}",
        holds(&defs)
    );
}

#[test]
fn a_role_that_is_not_in_force_is_no_role_on_any_read() {
    let defs = definers(&spec("  active disabled_at null\n  active state = \"on\"\n")).expect("compiles");
    assert!(holds(&defs).ends_with("AND r.disabled_at IS NULL AND r.state = 'on' AND p_perm = ANY(r.permissions))"), "{}", holds(&defs));
    let with_forms = definers(&spec(&format!("{FORMS}  active disabled_at null\n"))).expect("compiles");
    for d in with_forms.iter().filter(|d| d.body.contains(" roles r") || d.body.contains(" roles ro") || d.body.contains(" roles rr")) {
        assert!(d.body.contains("disabled_at IS NULL"), "{} reads the roles table without the in-force test:\n{}", d.name, d.body);
    }
}

#[test]
fn a_form_never_given_permissions_is_no_role_by_name_either() {
    let src = spec(FORMS)
        .replace("permission docs:write }", "permission docs:write preset editor @ space = docs:read }")
        .replace("  permission view = @holds(docs:read)", "  relation member: staff via role\n  permission view = member + @holds(docs:read)");
    let defs = definers(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let all = text(&defs);
    assert!(
        all.contains(
            "(CASE COALESCE(CHANNEL, 'live') WHEN 'draft' THEN r.key WHEN 'live' THEN CASE WHEN r.live_permissions IS NOT NULL THEN r.key END END) IN ("
        ),
        "{all}"
    );
    let keyed = definers(&src.replace("permissions live_permissions", "permissions live_permissions key live_key")).expect("compiles");
    assert!(text(&keyed).contains("WHEN 'live' THEN CASE WHEN r.live_permissions IS NOT NULL THEN r.live_key END END) IN ("), "{}", text(&keyed));
}

#[test]
fn forms_are_refused_where_a_session_could_be_left_to_a_default() {
    let cases = [
        ("no form for an absent claim", FORMS.replace("  absent claim reads \"live\"\n", ""), "names no form for a session with no \"channel\" claim"),
        (
            "an absent claim reading an unnamed form",
            FORMS.replace("reads \"live\"", "reads \"old\""),
            "reads \"old\" for an absent claim, which no `form` line names",
        ),
        ("one value twice", format!("{FORMS}  form claim channel = \"live\" base\n"), "names form \"live\" twice"),
        ("two claims", format!("{FORMS}  form claim other = \"x\" permissions p\n"), "reads its forms from two claims"),
        ("unversioned with no form", "  unversioned estate_id null\n".to_string(), "declares `unversioned` but no `form`"),
        ("absent with no form", "  absent claim reads \"live\"\n".to_string(), "declares `absent claim reads` but no `form`"),
    ];
    for (what, lines, want) in cases {
        let err = definers(&spec(&lines)).map(|d| d.len()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
    let bare = spec(FORMS).replace("  permissions permissions\n", "").replace("@holds(docs:read)", "@scoped");
    let err = definers(&bare).map(|d| d.len()).expect_err("a form with no base permissions");
    assert!(err.contains("declares a `form` but no `permissions` column"), "{err}");
}

fn with_lines(path: &str, lines: &str) -> String {
    let src = std::fs::read_to_string(format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))).expect("the fixture reads");
    let store = src.find("rolestore ").expect("a rolestore");
    let end = store + src[store..].find("\n}").expect("the rolestore closes");
    format!("{}\n{lines}{}", &src[..end], &src[end + 1..])
}

#[test]
fn the_access_listings_read_roles_by_the_same_rule() {
    let holds = text(&definers(&with_lines("testdata/gaps/accessors-holds.demesne", "  active disabled_at null")).expect("compiles"));
    assert!(holds.contains("WHERE e.id = p_id AND ro.disabled_at IS NULL AND 'docs:read' = ANY(ro."), "{holds}");
    let lines = format!("  permissions permissions\n  active disabled_at null\n{}", FORMS.trim_end());
    let roles = text(&definers(&with_lines("examples/example.demesne", &lines)).expect("compiles"));
    assert!(
        roles.contains("AND rr.disabled_at IS NULL AND (CASE COALESCE(CHANNEL, 'live') WHEN 'draft' THEN rr.key WHEN 'live' THEN CASE WHEN rr.live_permissions IS NOT NULL THEN rr.key END END) IN ("),
        "{roles}"
    );
    let in_force = text(&definers(&with_lines("examples/example.demesne", "  active disabled_at null")).expect("compiles"));
    assert!(in_force.contains(" rr ON rr.id = ra.role_id AND rr.disabled_at IS NULL AND rr.key IN ("), "{in_force}");
}
