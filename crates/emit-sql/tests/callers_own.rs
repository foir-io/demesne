use demesne_emit_sql::{Execute, GenFn, Sql};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
struct Emitted {
    path: String,
    spec: demesne_syntax::Spec,
    defs: Vec<GenFn>,
    callers: Vec<String>,
}

fn specs_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            specs_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "demesne") {
            out.push(path);
        }
    }
}

fn emitted() -> Vec<Emitted> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    for dir in ["examples", "testdata/corpus/fixtures", "testdata/gaps"] {
        specs_under(&root.join(dir), &mut paths);
    }
    let mut out = Vec::new();
    for path in paths {
        let Ok(src) = std::fs::read_to_string(&path) else { continue };
        let Ok(spec) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&spec).is_err() {
            continue;
        }
        let sql = Sql::new(&spec);
        let (Ok(defs), Ok(rls)) = (sql.emit_definers(), sql.emit_rls()) else { continue };
        let mut callers: Vec<String> = rls.policies.iter().flat_map(|p| [p.using.clone(), p.check.clone()]).collect();
        if let Ok(surface) = sql.emit_app_surface() {
            for o in surface.objects.iter() {
                callers.extend([o.edit_check_sql.to_string(), o.async_check_sql.to_string()]);
                callers.extend(o.checks.iter().map(|c| c.check_sql.to_string()));
            }
        }
        callers.retain(|t| !t.is_empty());
        out.push(Emitted { path: path.display().to_string(), spec, defs, callers });
    }
    out
}

fn parameters(f: &GenFn) -> Vec<&str> {
    f.sig.split(',').filter_map(|p| p.split_whitespace().next()).collect()
}

fn bound(f: &GenFn, parameter: &str) -> bool {
    let text = f.create_sql();
    [
        format!("{parameter} = (SELECT NULLIF(current_setting("),
        format!("{parameter} IN ((SELECT NULLIF(current_setting("),
        format!("{parameter} IS NOT DISTINCT FROM (SELECT "),
    ]
    .iter()
    .any(|guard| text.contains(guard.as_str()))
        || text.contains(" AND false;")
        || text.contains(" AND (false OR false));")
}

fn binds_any(f: &GenFn) -> bool {
    parameters(f).iter().any(|p| bound(f, p))
}

fn call_arguments(text: &str, call: &str) -> Vec<Vec<String>> {
    let mut calls = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(call) {
        let after = &rest[at + call.len()..];
        let (mut depth, mut quoted, mut arg, mut args) = (0usize, false, String::new(), Vec::new());
        let mut end = after.len();
        for (i, c) in after.char_indices() {
            match c {
                '\'' => quoted = !quoted,
                '(' if !quoted => depth += 1,
                ')' if !quoted && depth == 0 => {
                    end = i;
                    break;
                }
                ')' if !quoted => depth -= 1,
                ',' if !quoted && depth == 0 => {
                    args.push(std::mem::take(&mut arg).trim().to_string());
                    continue;
                }
                _ => {}
            }
            arg.push(c);
        }
        args.push(arg.trim().to_string());
        calls.push(args);
        rest = &after[end..];
    }
    calls
}

fn a_claim_read(arg: &str) -> bool {
    let arg = arg.trim_end_matches("::text");
    (arg.starts_with("(SELECT current_setting(") || arg.starts_with("(SELECT NULLIF(current_setting(") || arg.starts_with("(SELECT (NULLIF(current_setting("))
        && arg.ends_with(')')
        && arg.matches("current_setting(").count() == 1
}

fn the_claim(arg: &str) -> Option<&str> {
    let (_, key) = arg.rsplit_once(" '")?;
    key.split('\'').next()
}

fn a_scope_claim_alone(e: &Emitted, key: &str) -> bool {
    let a_level = e.spec.topology.iter().flat_map(|t| &t.levels).any(|l| l.claim_key() == key);
    let an_identity = e.spec.subjects.iter().any(|s| if s.identifies().is_empty() { key == "sub" } else { s.identifies() == key });
    let a_guard = format!("NULLIF(current_setting('request.jwt.claims', true), '')::json ->> '{key}'");
    a_level && !an_identity && !e.defs.iter().any(|f| f.create_sql().contains(&a_guard))
}

fn adopter_callable(e: &Emitted) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for obj in &e.spec.objects {
        names.extend(obj.exports.iter().map(|x| x.name.clone()));
        names.extend(obj.probes.iter().map(|x| x.name.clone()));
        names.extend(obj.projections.iter().map(|x| x.name.clone()));
        if obj.perms.iter().any(|pm| pm.has_layer("kernel")) {
            let kernel = format!("_can_access_{}", obj.name);
            names.extend(e.defs.iter().filter(|f| f.name.ends_with(&kernel)).map(|f| f.name.clone()));
        }
    }
    if let Ok(surface) = Sql::new(&e.spec).emit_app_surface() {
        for o in surface.objects.iter() {
            if let Some((_, name)) = o.flat_list_fn.rsplit_once('.') {
                names.insert(name.to_string());
            }
        }
    }
    for g in &e.spec.grants {
        names.extend(g.scopes.iter().map(|scope| format!("{}_reach_in_{}", g.definer_base(), scope.level)));
    }
    names
}

#[test]
fn a_parameter_the_generator_filled_from_a_principal_is_the_callers_own_in_every_function_public_may_run() {
    let all = emitted();
    assert!(all.len() > 150, "{} specs emitted", all.len());
    let (mut checked, mut unbound) = (0, BTreeSet::new());
    for e in &all {
        for f in e.defs.iter().filter(|f| f.execute == Execute::Public) {
            let Some(principal) = f.principal.as_deref() else { continue };
            assert!(parameters(f).contains(&principal), "{}({}) marks {principal}, which it does not take [{}]", f.name, f.sig, e.path);
            checked += 1;
            if !bound(f, principal) {
                unbound.insert(format!("{}({}) takes {principal} unbound", f.name, f.sig));
            }
        }
    }
    assert!(
        unbound.is_empty(),
        "{} functions answer for a principal that is not the caller's:\n{}",
        unbound.len(),
        unbound.into_iter().collect::<Vec<_>>().join("\n")
    );
    assert!(checked > 200, "{checked} principals checked");
}

#[test]
fn a_function_public_may_run_that_any_call_passes_a_claim_binds_an_argument_to_the_callers_claims() {
    let all = emitted();
    let (mut asked, mut unbound) = (0, BTreeSet::new());
    for e in &all {
        let mut texts: Vec<String> = e.callers.clone();
        texts.extend(e.defs.iter().map(GenFn::create_sql));
        for f in e.defs.iter().filter(|f| f.execute == Execute::Public) {
            let call = format!("{}.{}(", f.schema(), f.name);
            let given_a_claim = texts
                .iter()
                .flat_map(|t| call_arguments(t, &call))
                .any(|args| args.iter().any(|a| a_claim_read(a) && !the_claim(a).is_some_and(|key| a_scope_claim_alone(e, key))));
            if !given_a_claim {
                continue;
            }
            asked += 1;
            if !binds_any(f) {
                unbound.insert(format!("{}({}) is passed the caller's claim and binds nothing [{}]", f.name, f.sig, e.path));
            }
        }
    }
    assert!(
        unbound.is_empty(),
        "{} functions are asked with a claim and answer for any value:\n{}",
        unbound.len(),
        unbound.into_iter().take(60).collect::<Vec<_>>().join("\n")
    );
    assert!(asked > 200, "{asked} functions asked with a claim");
}

#[test]
fn a_function_is_public_only_where_a_policy_calls_it_or_a_spec_line_makes_it_the_adopters_to_call() {
    let all = emitted();
    let (mut public, mut revoked, mut stray) = (0, 0, BTreeSet::new());
    for e in &all {
        let callable = adopter_callable(e);
        for f in &e.defs {
            if f.execute != Execute::Public {
                revoked += 1;
                continue;
            }
            public += 1;
            let call = format!("{}.{}(", f.schema(), f.name);
            if !callable.contains(&f.name) && !e.callers.iter().any(|t| t.contains(&call)) {
                stray.insert(format!("{}({}) [{}]", f.name, f.sig, e.path));
            }
        }
    }
    assert!(
        stray.is_empty(),
        "{} functions PUBLIC may run that nothing run as the caller calls:\n{}",
        stray.len(),
        stray.into_iter().take(60).collect::<Vec<_>>().join("\n")
    );
    assert!(public > 250 && revoked > 100, "{public} public, {revoked} revoked");
}

#[test]
fn every_function_a_policy_or_the_application_surface_calls_is_one_the_caller_may_run() {
    let (mut calls, mut refused) = (0, BTreeSet::new());
    for e in emitted() {
        for f in &e.defs {
            let call = format!("{}.{}(", f.schema(), f.name);
            if !e.callers.iter().any(|t| t.contains(&call)) {
                continue;
            }
            calls += 1;
            if f.execute != Execute::Public {
                refused.insert(format!("{}({}) [{}]", f.name, f.sig, e.path));
            }
        }
    }
    assert!(
        refused.is_empty(),
        "{} functions run as the caller that PUBLIC may not run:\n{}",
        refused.len(),
        refused.into_iter().take(60).collect::<Vec<_>>().join("\n")
    );
    assert!(calls > 250, "{calls} functions called as the caller");
}

#[test]
fn a_function_only_a_generated_check_calls_stays_one_the_caller_may_run() {
    let src = r#"
topology {
  level tenant
  level team parent tenant
}
vocabulary roles {
  permission docs:read
  preset viewer @ team = docs:read
}
rolestore roles {
  assignments role_assignments
  kind        principal_kind = "member"
  subject     principal_id
  scope       tenant_id team_id
  rolejoin    role_id roles_tbl id key
  revoked     revoked_at
  permissions perms
}
subject member { anchor team; reach descendants; identifies sub; roles configurable roles; binds admin }
object doc {
  table  docs
  scoped tenant > team
  permission view  = @scoped @rls maps select
  permission serve = @holds("docs:read") @check
}
"#;
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = Sql::new(&s);
    let call = "auth.member_has_perm(";
    let rls = sql.emit_rls().expect("the policies compile");
    assert!(rls.policies.iter().all(|p| !p.using.contains(call) && !p.check.contains(call)), "no policy asks the role store");
    let surface = sql.emit_app_surface().expect("the application surface compiles");
    let checks: Vec<String> = surface.objects.iter().flat_map(|o| o.checks.iter().map(|c| c.check_sql.to_string())).collect();
    assert!(checks.iter().any(|c| c.contains(call)), "the point check asks it: {checks:?}");
    let defs = sql.emit_definers().expect("the definers compile");
    let held = defs.iter().find(|d| d.name == "member_has_perm").expect("the role check");
    assert_eq!(held.execute, Execute::Public, "the point check runs as the caller");
}

#[test]
fn a_kernel_check_answers_only_for_the_callers_own_principal() {
    let src = r"
topology {
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}
vocabulary app { permission self:read }
subject member {
  anchor workspace
  reach  self
  identifies member_ref
  roles  none
  binds  owner
}
object note {
  table  notes
  pk     note_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner @rls maps select
  permission edit = owner @kernel maps update
}
";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let defs = Sql::new(&s).emit_definers().expect("the definers compile");
    let kernel = defs.iter().find(|d| d.name == "member_can_access_note").expect("the kernel check");
    assert_eq!(kernel.execute, Execute::Public, "the adopter calls it: {}", kernel.create_sql());
    assert_eq!(kernel.principal.as_deref(), Some("p_member_id"), "{}", kernel.create_sql());
    assert!(bound(kernel, "p_member_id"), "{}", kernel.create_sql());
    let lists = Sql::new(&s).manifest().expect("a manifest").execute.expect("the manifest records who may run each function");
    assert!(lists.callable.contains("auth.member_can_access_note(text, text, text)"), "{lists:?}");
}

#[test]
fn the_resources_a_materialized_group_lists_are_the_adopters_to_call_only_where_the_application_surface_lists_through_them() {
    let src = |view: &str| {
        format!(
            "topology {{ level tenant level project parent tenant }}
vocabulary cust {{ permission self:read }}
subject customer {{ anchor project reach self identifies customer_id roles configurable cust binds owner }}
object doc {{
  table  docs
  scoped tenant > project
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access)
  relation team:    customer via group tc(grp, mem) edge te(mem, grp) on team_id materialized
  permission view = {view} @rls maps select
}}
"
        )
    };
    for (view, listed) in [("team", true), ("grantee:read + team", false)] {
        let s = demesne_syntax::parse(&src(view)).expect("the spec parses");
        demesne_emit_sql::validate(&s).expect("the spec validates");
        let defs = Sql::new(&s).emit_definers().expect("the definers compile");
        let resources = defs.iter().find(|d| d.name == "docs_team_flat_resources");
        let surface = Sql::new(&s).emit_app_surface().expect("the application surface compiles");
        let lists_through = surface.objects.iter().any(|o| o.flat_list_fn.contains(".docs_team_flat_resources"));
        assert_eq!(lists_through, listed, "{view}: {surface:?}");
        assert_eq!(resources.map(|f| f.execute), listed.then_some(Execute::Public), "{view}: emitted only where it is the adopter's to call");
        let lists = Sql::new(&s).manifest().expect("a manifest").execute.expect("the manifest records who may run each function");
        let callable = lists.callable.iter().any(|f| f.contains(".docs_team_flat_resources("));
        assert_eq!(callable, listed, "{view}: {lists:?}");
    }
}

#[test]
fn a_grant_relation_answers_only_for_the_callers_own_principal() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/roundtrip.demesne");
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the example reads")).expect("the example parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let grants = defs.iter().find(|d| d.name == "note_acl_grants").expect("the grant relation");
    assert_eq!(grants.principal.as_deref(), Some("p_member_id"));
    assert_eq!(grants.execute, Execute::Public);
    assert!(grants.body.starts_with(&format!("p_member_id = {} AND (", sql.session_claim("member_ref"))), "{}", grants.body);
}

#[test]
fn a_parameter_named_like_a_principal_in_an_export_or_a_probe_is_not_taken_for_one() {
    let src = r"
topology { level estate }
subject member { anchor estate; reach self; identifies sub; roles none; binds owner }
object share {
  table shares
  scoped estate
  relation owner: member via member
  permission edit = owner @rls maps update
  permission view = owner @rls maps select
  export edit as share_write_allowed(member text as p_member, estate_id text as row_estate_id)
  probe invited(member text as p_member)
}
";
    let s = demesne_syntax::parse(src).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let defs = Sql::new(&s).emit_definers().expect("the definers compile");
    for name in ["share_write_allowed", "invited"] {
        let f = defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"));
        assert_eq!(f.principal, None, "{name}");
        assert!(!f.body.starts_with("p_member = "), "{name}: {}", f.body);
        assert_eq!(f.execute, Execute::Public, "{name} is the adopter's to call");
    }
}

#[test]
fn a_membership_answers_when_either_side_is_the_callers_own() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/552954073f6906e3.demesne");
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let member = defs.iter().find(|d| d.name == "admin_memberin_tenant").expect("the membership check");
    let own = format!("(p_principal = {} OR p_tenant = {}) AND (EXISTS (", sql.session_claim("sub"), sql.session_claim("tenant_id"));
    assert!(member.body.starts_with(&own), "a rule asks it about the caller, or about a row's principal in the caller's own tenant:\n{}", member.body);
    let held = defs.iter().find(|d| d.name == "has_platform_role").expect("a role check");
    assert!(held.text().starts_with(&format!("user_id = {} AND (", sql.session_claim("sub"))), "{}", held.text());
}

#[test]
fn a_membership_no_rule_asks_is_not_emitted() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/38d02b53bac27607.demesne");
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    let names: Vec<String> = Sql::new(&s).emit_definers().expect("the definers compile").into_iter().map(|d| d.name).collect();
    assert!(!names.iter().any(|n| n == "admin_memberin_space"), "no permission names the relation, so nothing calls its check: {names:?}");
}

#[test]
fn a_rule_that_passes_the_callers_own_principal_opens_no_scope_side() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/fixtures/552954073f6906e3.demesne");
    let src = std::fs::read_to_string(&path).expect("the fixture reads");
    let both = src.replace("memberin tenant(id, @tenant_id)", "memberin tenant(@sub, @tenant_id)");
    assert_ne!(src, both, "the fixture states the rule this test rewrites");
    let s = demesne_syntax::parse(&both).expect("the spec parses");
    let sql = Sql::new(&s);
    let defs = sql.emit_definers().expect("the definers compile");
    let member = defs.iter().find(|d| d.name == "admin_memberin_tenant").expect("the membership check");
    let own = format!("p_principal = {} AND (EXISTS (", sql.session_claim("sub"));
    assert!(member.body.starts_with(&own), "only a rule that asks about a row's principal needs the scope side:\n{}", member.body);
}

fn the_chains_example_with(change: impl Fn(&str) -> String) -> (String, Vec<GenFn>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/chains.demesne");
    let example = std::fs::read_to_string(&path).expect("the example reads");
    let changed = change(&example);
    let s = demesne_syntax::parse(&changed).unwrap_or_else(|e| panic!("the example parses: {e}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("the example validates: {e}"));
    let sql = Sql::new(&s);
    let policies = sql.emit_rls().expect("the policies compile").policy_sql("authenticated");
    (policies, sql.emit_definers().expect("the definers compile"))
}

fn the_chains_example() -> (String, Vec<GenFn>) {
    the_chains_example_with(str::to_string)
}

fn all_sql(defs: &[GenFn]) -> String {
    defs.iter().map(GenFn::create_sql).collect::<Vec<_>>().join("\n")
}

#[test]
fn a_function_with_a_second_side_remembers_nothing_and_has_no_copy() {
    let (_, defs) = the_chains_example();
    let member = defs.iter().find(|d| d.name == "keeper_memberin_space").expect("the membership check");
    assert_eq!(member.bound, None, "one remembered argument cannot stand for a check that reads two");
    assert!(defs.iter().find(|d| d.name == "doc_shared_keyed").expect("the keyed edge").bound.is_some());
}

#[test]
fn a_name_no_setting_can_hold_is_verified_on_every_call() {
    let (_, defs) = the_chains_example_with(|example| format!("definers schema \"Auth\"\n{example}"));
    let sql = all_sql(&defs);
    assert!(!sql.contains("'demesne."), "a setting's name is folded to lower case, so two schemas could share one");
    assert!(sql.contains("  RETURN p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub') AND (EXISTS ("), "{sql}");
    assert!(sql.contains("  IF p_object IS NULL OR NOT (p_values IS NOT DISTINCT FROM (SELECT (NULLIF(current_setting('request.jwt.claims', true), '')::json -> 'facts')::jsonb)) THEN"));
}

#[test]
fn a_copy_is_emitted_only_under_a_name_postgres_keeps_whole_and_nothing_else_has() {
    let long = "r".repeat(52);
    let (_, defs) = the_chains_example_with(|example| example.replace("shared", &long));
    let keyed = format!("doc_{long}_keyed");
    assert!(defs.iter().any(|d| d.name == keyed) && !defs.iter().any(|d| d.name == format!("{keyed}_inside")), "a name past 63 bytes is cut short by Postgres");
    assert!(all_sql(&defs).contains(&format!("auth.{keyed}((SELECT current_setting(")), "so a chain function asks the bound function");

    let taken = |example: &str| example.replace("live_skin", "doc_shared_keyed_inside");
    let (_, defs) = the_chains_example_with(taken);
    let named: Vec<&GenFn> = defs.iter().filter(|d| d.name == "doc_shared_keyed_inside").collect();
    assert_eq!(named.len(), 1, "the name is the lookup's");
    assert_eq!(named[0].sig, "p_node text");
    assert!(all_sql(&defs).contains("auth.doc_shared_keyed((SELECT current_setting("), "so a chain function asks the bound function");
}

#[test]
fn inside_a_chain_a_bound_function_remembers_the_claim_only_while_the_claims_keep_their_text() {
    let (_, defs) = the_chains_example();
    let claims = "current_setting('request.jwt.claims', true)";
    let own = "p_principal = (SELECT NULLIF(current_setting('request.jwt.claims', true), '')::json ->> 'sub')";
    let keyed = defs.iter().find(|d| d.name == "doc_shared_keyed").expect("the keyed edge").create_sql();
    let remembered = format!(
        "  IF current_setting('demesne.auth.doc_shared_keyed.seen', true) = {claims} AND current_setting('demesne.auth.doc_shared_keyed.own', true) = p_principal::text THEN\n    RETURN p_principal = p_principal AND (EXISTS ("
    );
    assert!(keyed.contains(&remembered), "the remembered value counts only for the same claims text and the same argument:\n{keyed}");
    let kept = format!(
        "  IF {own} THEN\n    PERFORM set_config('demesne.auth.doc_shared_keyed.own', p_principal::text, true), set_config('demesne.auth.doc_shared_keyed.seen', coalesce({claims}, ''), true);\n  END IF;\n  RETURN {own} AND (EXISTS ("
    );
    assert!(keyed.contains(&kept), "it is kept only once verified against the claims, and any other call is judged against them:\n{keyed}");

    let terms = defs.iter().find(|d| d.name == "doc_terms_hold").expect("the conditions check").create_sql();
    let verified = format!(
        "  IF (current_setting('demesne.auth.doc_terms_hold.seen', true) = {claims} AND current_setting('demesne.auth.doc_terms_hold.own', true) = coalesce(p_values::text, '')) IS NOT TRUE THEN\n    IF NOT (p_values IS NOT DISTINCT FROM (SELECT (NULLIF({claims}, '')::json -> 'facts')::jsonb)) THEN\n      RETURN NULL;\n    END IF;\n    PERFORM set_config("
    );
    assert!(terms.contains(&verified), "{terms}");
}

#[test]
fn a_copy_public_cannot_run_is_called_only_with_the_callers_own_claim_and_never_by_a_policy() {
    let (policies, defs) = the_chains_example();
    assert!(!policies.contains("_inside("), "a policy runs as the caller, so it calls the bound function");
    assert!(policies.contains("auth.doc_shared_keyed(") && policies.contains("auth.doc_terms_hold("), "{policies}");
    let mut calls = 0;
    for (copy, position) in [("doc_shared_keyed_inside", 0), ("doc_terms_hold_inside", 2)] {
        let f = defs.iter().find(|d| d.name == copy).unwrap_or_else(|| panic!("{copy} is emitted"));
        assert_eq!(f.execute, Execute::Revoked, "{copy}");
        assert!(!f.create_sql().contains("demesne.auth."), "{copy} reads no remembered value:\n{}", f.create_sql());
        let call = format!("auth.{copy}(");
        let texts: Vec<String> = defs.iter().filter(|d| d.name != copy).map(GenFn::create_sql).collect();
        for after in texts.iter().flat_map(|text| text.split(call.as_str()).skip(1)) {
            let passed = after.split(", ").nth(position).unwrap_or_default();
            assert!(passed.starts_with("(SELECT current_setting(") || passed.starts_with("(SELECT (current_setting("), "{copy} is asked about {passed:.80}");
            calls += 1;
        }
    }
    assert_eq!(calls, 8, "every call a chain function makes with the claim goes to the copy");
    let direct = defs.iter().filter(|d| d.name != "doc_shared_keyed" && d.create_sql().contains("auth.doc_shared_keyed(")).count();
    assert_eq!(direct, 0, "no generated function pays for the binding it already satisfies");
}

#[test]
fn a_spec_with_no_chain_gets_no_copy() {
    for e in emitted() {
        let chained = e.defs.iter().any(|d| d.name.contains("_composition_"));
        let copies: Vec<&str> = e.defs.iter().filter(|d| d.name.ends_with("_inside")).map(|d| d.name.as_str()).collect();
        assert!(chained || copies.is_empty(), "{}: {copies:?}", e.path);
    }
}
