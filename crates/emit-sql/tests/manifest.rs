use demesne_emit_sql::{Execute, Manifest, Sql, validate};
use demesne_gocompat::json::{self, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn spec(name: &str) -> demesne_syntax::Spec {
    let path = format!("{}/../../testdata/gaps/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = demesne_syntax::parse(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("the fixture parses");
    validate(&s).expect("the fixture validates");
    s
}

fn all_sql(s: &demesne_syntax::Spec) -> String {
    let mut b = String::new();
    Sql::new(s).write_all_sql(&mut b).expect("the SQL compiles");
    b
}

#[test]
fn a_migration_drops_exactly_what_the_previous_surface_had_and_this_one_does_not() {
    let previous = Sql::new(&spec("migrate-before.demesne")).manifest().expect("a manifest");
    let after = spec("migrate-after.demesne");
    let migration = Sql::new(&after).migration(&previous).expect("a migration");
    let plain = all_sql(&after);
    let drops = migration.strip_prefix(plain.as_str()).expect("the migration starts with the spec's whole SQL");
    let lines: Vec<&str> = drops.lines().filter(|l| l.starts_with("DROP ")).collect();
    assert_eq!(
        lines,
        [
            "DROP TRIGGER IF EXISTS docs_obj_changelog ON public.docs;",
            "DROP POLICY IF EXISTS docs_select ON public.docs;",
            "DROP INDEX IF EXISTS auth._authz_changelog_principal_idx;",
            "DROP INDEX IF EXISTS auth._authz_changelog_seq_idx;",
            "DROP FUNCTION IF EXISTS auth.docs_obj_changelog();",
            "DROP FUNCTION IF EXISTS auth.note_acl_grants(text, text, text);",
            "DROP FUNCTION IF EXISTS auth.notes_accessors_conditional(text);",
            "DROP FUNCTION IF EXISTS auth.notes_admits(text, jsonb);",
        ]
    );
    assert!(drops.contains("WHERE (n.nspname, p.proname) IN (('auth'::name, 'docs_obj_changelog'::name), ('auth'::name, 'note_acl_grants'::name), ('auth'::name, 'notes_accessors_conditional'::name), ('auth'::name, 'notes_admits'::name))"), "{drops}");
    assert!(drops.contains("AND p.oid <> ALL (array_remove(ARRAY[to_regprocedure('auth.notes_accessors_conditional(uuid)')::oid, to_regprocedure('auth.notes_admits(uuid, jsonb)')::oid]::oid[], NULL))"), "{drops}");
    assert!(drops.contains("-- table auth._authz_changelog is no longer emitted; it is not dropped, as it holds data"), "{drops}");
    assert!(drops.contains("-- table public.docs is no longer governed; row level security stays enabled and forced"), "{drops}");
}

#[test]
fn a_migration_from_its_own_surface_is_the_plain_sql() {
    let after = spec("migrate-after.demesne");
    let own = Sql::new(&after).manifest().expect("a manifest");
    assert_eq!(Sql::new(&after).migration(&own), Ok(all_sql(&after)));
}

#[test]
fn the_manifest_reads_back_what_it_wrote() {
    let m = Sql::new(&spec("migrate-before.demesne")).manifest().expect("a manifest");
    assert_eq!(m.functions.len(), 4, "{m:?}");
    assert_eq!(Manifest::from_json(&m.to_json()), Ok(m));
}

#[test]
fn the_manifest_skips_what_a_function_body_or_a_string_holds() {
    let m = Manifest::from_sql(
        "CREATE OR REPLACE FUNCTION auth.f(p_id text, p_n uuid) RETURNS void LANGUAGE plpgsql AS $body$ BEGIN PERFORM 1; CREATE TEMP TABLE t (x int); END $body$;
         -- CREATE VIEW in a comment;
         SELECT 'it''s a string; CREATE VIEW v';
         CREATE POLICY p ON public.t FOR SELECT USING ($$;$$ = ';');",
    )
    .expect("a manifest");
    assert_eq!(m.functions.into_iter().collect::<Vec<_>>(), ["auth.f(text, uuid)"]);
    assert_eq!(m.policies.into_iter().collect::<Vec<_>>(), [("public.t".to_string(), "p".to_string())]);
    assert!(m.tables.is_empty());
}

#[test]
fn the_manifest_refuses_what_it_cannot_drop_exactly() {
    for (sql, want) in [
        ("CREATE VIEW v AS SELECT 1;", "does not record this kind of object: CREATE VIEW v AS SELECT 1"),
        ("CREATE OR REPLACE FUNCTION f(p text) RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;", "needs a schema-qualified function name"),
        ("CREATE OR REPLACE FUNCTION auth.f(OUT p text) AS $$ SELECT '' $$ LANGUAGE sql;", "reads only arguments written as `name type`"),
        ("CREATE OR REPLACE FUNCTION auth.f(p text DEFAULT '') RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;", "reads only arguments written as `name type`"),
    ] {
        let err = Manifest::from_sql(sql).expect_err(sql).to_string();
        assert!(err.contains(want), "{sql}: {err}");
    }
}

#[test]
fn a_manifest_of_another_format_is_refused() {
    assert_eq!(
        Manifest::from_json(r#"{"manifest": 2}"#).map_err(|e| e.to_string()),
        Err("manifest: format 2 is not one this demesne reads (it reads format 1)".into())
    );
    assert_eq!(Manifest::from_json("{}").map_err(|e| e.to_string()), Err("manifest: not a demesne manifest (no \"manifest\" format field)".into()));
}

#[test]
fn every_corpus_spec_that_emits_records_each_create_once() {
    let root = format!("{}/../../testdata/corpus", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    let mut dirs = vec![std::path::PathBuf::from(root), format!("{}/../../examples", env!("CARGO_MANIFEST_DIR")).into()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).expect("the corpus reads") {
            let p = e.expect("an entry").path();
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "demesne") {
                continue;
            }
            let Ok(s) = demesne_syntax::parse(&std::fs::read_to_string(&p).expect("the spec reads")) else { continue };
            if validate(&s).is_err() {
                continue;
            }
            let mut b = String::new();
            if Sql::new(&s).write_all_sql(&mut b).is_err() {
                continue;
            }
            let m = Manifest::from_sql(&b).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            let creates = b.lines().filter(|l| l.starts_with("CREATE ")).count();
            let entries = m.functions.len() + m.policies.len() + m.triggers.len() + m.indexes.len() + m.tables.len();
            assert_eq!(entries, creates, "{}: the manifest records {entries} objects of {creates} CREATE statements", p.display());
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} corpus specs emitted");
}

#[test]
fn the_survivor_check_spells_each_name_as_the_catalog_does() {
    let previous = Manifest::from_sql(
        r#"CREATE POLICY "Readers" ON app."Docs" FOR SELECT USING (true);
           CREATE TRIGGER Audit AFTER UPDATE ON app.docs FOR EACH ROW EXECUTE FUNCTION App."Audit"();
           CREATE OR REPLACE FUNCTION App."Audit"() RETURNS trigger AS $$ BEGIN RETURN NEW; END $$ LANGUAGE plpgsql;"#,
    )
    .expect("a manifest");
    let drops = Manifest::default().drops_since(&previous);
    assert!(drops.contains(r#"DROP POLICY IF EXISTS "Readers" ON app."Docs";"#), "{drops}");
    assert!(drops.contains(r#"(to_regclass('app."Docs"')::oid, 'Readers'::name)"#), "{drops}");
    assert!(drops.contains("(to_regclass('app.docs')::oid, 'audit'::name)"), "{drops}");
    assert!(drops.contains("('app'::name, 'Audit'::name)"), "{drops}");
}

#[test]
fn a_migration_drops_each_kind_of_object_on_its_own() {
    let all = Manifest::from_sql(
        "CREATE POLICY p ON s.t FOR SELECT USING (true);
         CREATE TRIGGER tr AFTER UPDATE ON s.t FOR EACH ROW EXECUTE FUNCTION s.f();
         CREATE INDEX i ON s.t (x);
         CREATE OR REPLACE FUNCTION s.f() RETURNS trigger AS $$ BEGIN RETURN NEW; END $$ LANGUAGE plpgsql;
         CREATE TABLE s.log (x int);
         ALTER TABLE s.t ENABLE ROW LEVEL SECURITY;",
    )
    .expect("a manifest");
    let without = |strip: fn(&mut Manifest)| {
        let mut kept = all.clone();
        strip(&mut kept);
        kept.drops_since(&all)
    };
    for (kind, drops, line, catalog) in [
        ("policy", without(|m| m.policies.clear()), "DROP POLICY IF EXISTS p ON s.t;", Some("FROM pg_policy")),
        ("trigger", without(|m| m.triggers.clear()), "DROP TRIGGER IF EXISTS tr ON s.t;", Some("FROM pg_trigger")),
        ("index", without(|m| m.indexes.clear()), "DROP INDEX IF EXISTS s.i;", Some("FROM pg_class")),
        ("function", without(|m| m.functions.clear()), "DROP FUNCTION IF EXISTS s.f();", Some("FROM pg_proc")),
        ("table", without(|m| m.tables.clear()), "-- table s.log is no longer emitted", None),
        ("rls", without(|m| m.rls.clear()), "-- table s.t is no longer governed", None),
    ] {
        assert!(drops.contains(line), "{kind}: {drops}");
        assert_eq!(drops.contains("DO $demesne$"), catalog.is_some(), "{kind}: a survivor check only follows drops: {drops}");
        for arm in ["FROM pg_policy", "FROM pg_trigger", "FROM pg_class", "FROM pg_proc"] {
            assert_eq!(drops.contains(arm), catalog == Some(arm), "{kind}: the survivor check looks only for what was dropped: {drops}");
        }
    }
    assert_eq!(all.drops_since(&all), "");
}

#[test]
fn a_function_signature_keeps_a_type_with_its_own_commas_and_refuses_an_unnamed_argument() {
    let m = Manifest::from_sql("CREATE OR REPLACE FUNCTION s.g(a numeric(10, 2), b text) RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;").expect("a manifest");
    assert_eq!(m.functions.into_iter().collect::<Vec<_>>(), ["s.g(numeric(10, 2), text)"]);
    let err = Manifest::from_sql("CREATE OR REPLACE FUNCTION s.g(text) RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;").expect_err("no argument name").to_string();
    assert!(err.contains("reads only arguments written as `name type`: \"text\""), "{err}");
    let err = Manifest::from_sql("CREATE FUNCTION s.f RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;").expect_err("no argument list").to_string();
    assert_eq!(err, "the manifest cannot read the identity of: CREATE FUNCTION s.f RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql");
}

#[test]
fn a_quoted_name_with_a_dot_is_one_identifier() {
    let previous = Manifest::from_sql(
        r#"CREATE OR REPLACE FUNCTION "a.b".f(x int) RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;
           CREATE INDEX i ON "a.b".t (x);
           CREATE INDEX j ON s."t.x" (y);"#,
    )
    .expect("a manifest");
    let drops = Manifest::default().drops_since(&previous);
    assert!(drops.contains(r#"DROP INDEX IF EXISTS "a.b".i;"#), "{drops}");
    assert!(drops.contains("DROP INDEX IF EXISTS s.j;"), "{drops}");
    assert!(drops.contains("WHERE (n.nspname, p.proname) IN (('a.b'::name, 'f'::name))"), "{drops}");
}

#[test]
fn a_positional_parameter_does_not_open_a_dollar_quote() {
    let m = Manifest::from_sql("CREATE POLICY a ON s.t USING ($1$ = 1); CREATE POLICY b ON s.t USING (true);").expect("a manifest");
    assert_eq!(m.policies.len(), 2, "{:?}", m.policies);
}

fn emitting_specs() -> Vec<(String, demesne_syntax::Spec)> {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let mut dirs: Vec<PathBuf> = ["examples", "testdata/corpus", "testdata/gaps"].iter().map(|d| PathBuf::from(format!("{root}/{d}"))).collect();
    let mut paths = Vec::new();
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).expect("the corpus reads") {
            let p = e.expect("an entry").path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "demesne") {
                paths.push(p);
            }
        }
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| {
            let s = demesne_syntax::parse(&std::fs::read_to_string(&p).ok()?).ok()?;
            validate(&s).ok()?;
            let mut b = String::new();
            Sql::new(&s).write_all_sql(&mut b).ok()?;
            Some((p.display().to_string(), s))
        })
        .collect()
}

fn listed(manifest: &Value, key: &str, path: &str) -> BTreeSet<String> {
    let items = manifest.get(key).and_then(Value::as_array).unwrap_or_else(|| panic!("{path}: the manifest has no {key} list"));
    items.iter().map(|v| v.as_str().unwrap_or_else(|| panic!("{path}: an entry of {key} is not a string")).to_string()).collect()
}

fn identity(f: &demesne_emit_sql::GenFn) -> String {
    let types: Vec<String> = f.sig.split(',').map(|p| p.split_whitespace().skip(1).collect::<Vec<_>>().join(" ")).filter(|t| !t.is_empty()).collect();
    format!("{}.{}({})", f.schema(), f.name, types.join(", "))
}

fn name_of(signature: &str) -> &str {
    signature.split('(').next().and_then(|q| q.rsplit('.').next()).unwrap_or_default()
}

#[test]
fn every_function_the_sql_creates_is_in_exactly_one_of_callable_grantable_internal_and_revoked() {
    let (mut wrong, mut totals, mut specs) = (Vec::new(), [0usize; 4], 0);
    for (path, s) in emitting_specs() {
        let m = Sql::new(&s).manifest().unwrap_or_else(|e| panic!("{path}: {e}"));
        let written = json::parse(&m.to_json()).unwrap_or_else(|e| panic!("{path}: {e}"));
        let functions = listed(&written, "functions", &path);
        let lists = ["callable", "grantable", "internal", "revoked"].map(|key| (key, listed(&written, key, &path)));
        for (total, (key, list)) in totals.iter_mut().zip(&lists) {
            *total += list.len();
            wrong.extend(list.iter().filter(|f| !functions.contains(*f)).map(|f| format!("{path}: {key} lists {f}, which the SQL does not create")));
        }
        for f in &functions {
            let held: Vec<&str> = lists.iter().filter(|(_, list)| list.contains(f)).map(|(key, _)| *key).collect();
            if held.len() != 1 {
                wrong.push(format!("{path}: {f} is in {held:?}"));
            }
        }
        specs += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    let [callable, grantable, internal, revoked] = totals;
    assert!(
        specs > 150 && callable > 30 && grantable > 200 && internal > 300 && revoked > 10,
        "{specs} specs, {callable} callable, {grantable} grantable, {internal} internal, {revoked} revoked"
    );
}

#[test]
fn each_list_holds_the_functions_its_name_says() {
    let mut wrong = Vec::new();
    for (path, s) in emitting_specs() {
        let sql = Sql::new(&s);
        let lists = sql.manifest().unwrap_or_else(|e| panic!("{path}: {e}")).execute.unwrap_or_else(|| panic!("{path}: the manifest records no lists"));
        let declared: BTreeSet<&str> = s
            .objects
            .iter()
            .flat_map(|o| {
                o.exports.iter().map(|e| e.name.as_str()).chain(o.probes.iter().map(|p| p.name.as_str())).chain(o.projections.iter().map(|p| p.name.as_str()))
            })
            .collect();
        for f in sql.emit_definers().unwrap_or_else(|e| panic!("{path}: {e}")) {
            let sig = identity(&f);
            if (f.execute == Execute::Revoked) != lists.revoked.contains(&sig) {
                wrong.push(format!("{path}: {sig} is {:?} and the manifest's revoked list says otherwise", f.execute));
            }
            if (f.execute == Execute::Grantable) != lists.grantable.contains(&sig) {
                wrong.push(format!("{path}: {sig} is {:?} and the manifest's grantable list says otherwise", f.execute));
            }
            if declared.contains(f.name.as_str()) && !lists.callable.contains(&sig) {
                wrong.push(format!("{path}: a spec line declares {sig}, and it is not callable"));
            }
        }
        for c in &lists.callable {
            let name = name_of(c);
            if !(declared.contains(name) || name.contains("_can_access_") || name.ends_with("_resources") || name.contains("_reach_in_")) {
                wrong.push(format!("{path}: {c} is callable, and no spec line makes it so"));
            }
        }
        let nearest: BTreeSet<&str> = s.objects.iter().flat_map(|o| o.nearests.iter().map(|n| n.name.as_str())).collect();
        let family = [
            "_accessors",
            "_accessors_conditional",
            "_direct_accessors",
            "_admits",
            "_path",
            "_async_apply",
            "_async_rebuild",
            "_async_watermark",
            "_reconcile",
        ];
        let for_a_role = |name: &str| !declared.contains(name) && (family.iter().any(|f| name.ends_with(f)) || nearest.contains(name));
        for g in &lists.grantable {
            if !for_a_role(name_of(g)) {
                wrong.push(format!("{path}: {g} is grantable, and it is not an interface for a role"));
            }
        }
        for f in lists.callable.iter().chain(&lists.internal).chain(&lists.revoked) {
            if for_a_role(name_of(f)) {
                wrong.push(format!("{path}: {f} is meant for a role you grant, and it is not grantable"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_manifest_written_before_it_recorded_who_may_run_each_function_reads_with_that_unrecorded() {
    let earlier = r#"{"manifest": 1, "functions": ["auth.f(text)"], "policies": [], "triggers": [], "indexes": [], "tables": [], "rls": []}"#;
    let m = Manifest::from_json(earlier).expect("a manifest from before");
    assert_eq!(m.execute, None, "{m:?}");
    assert!(!m.to_json().contains("\"callable\""), "{}", m.to_json());
}

#[test]
fn a_manifest_whose_lists_do_not_hold_each_function_once_is_refused() {
    let with = |lists: &str| {
        format!(
            r#"{{"manifest": 1, "functions": ["auth.f(text)", "auth.g(text)"], {lists} "policies": [], "triggers": [], "indexes": [], "tables": [], "rls": []}}"#
        )
    };
    for (lists, want) in [
        (r#""callable": ["auth.f(text)"], "grantable": [], "internal": ["auth.g(text)"],"#, r#"no "revoked" list"#),
        (r#""callable": ["auth.f(text)"], "internal": ["auth.g(text)"], "revoked": [],"#, r#"no "grantable" list"#),
        (r#""revoked": ["auth.f(text)", "auth.g(text)"],"#, r#"no "callable" or "grantable" or "internal" list"#),
        (
            r#""callable": ["auth.f(text)"], "grantable": [], "internal": ["auth.f(text)"], "revoked": ["auth.g(text)"],"#,
            r#""auth.f(text)" is in more than one"#,
        ),
        (r#""callable": [], "grantable": ["auth.f(text)"], "internal": [], "revoked": ["auth.f(text)"],"#, r#""auth.f(text)" is in more than one"#),
        (r#""callable": ["auth.f(text)"], "grantable": [], "internal": [], "revoked": [],"#, r#""auth.g(text)" is in none"#),
        (
            r#""callable": ["auth.f(text)", "auth.h(text)"], "grantable": [], "internal": ["auth.g(text)"], "revoked": [],"#,
            r#""callable" lists "auth.h(text)", which functions does not"#,
        ),
    ] {
        let err = Manifest::from_json(&with(lists)).map(|m| m.to_json()).expect_err(lists).to_string();
        assert!(err.contains(want), "{lists}: {err}");
    }
    let whole =
        Manifest::from_json(&with(r#""callable": [], "grantable": ["auth.f(text)"], "internal": [], "revoked": ["auth.g(text)"],"#)).expect("a whole manifest");
    let lists = whole.execute.expect("the lists");
    assert_eq!(
        (lists.grantable.into_iter().collect::<Vec<_>>(), lists.revoked.into_iter().collect::<Vec<_>>()),
        (vec!["auth.f(text)".to_string()], vec!["auth.g(text)".to_string()])
    );
}

#[test]
fn a_checked_changelogs_constraint_triggers_are_recorded_and_dropped_like_any_trigger() {
    let src = "changelog checked
topology { level estate level space parent estate }
subject member { anchor space; reach self; identifies sub; roles none; binds owner }
object doc {
  table docs
  scoped estate > space
  relation owner: member via owner_id where owner_kind = \"member\"
  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access) tracked
  permission view = owner + mode visibility = \"public\" + grantee:read @rls maps select
  track owner
  track visibility
}
";
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}"));
    validate(&s).unwrap_or_else(|e| panic!("{e}"));
    let sql = all_sql(&s);
    let created: BTreeSet<(String, String)> = sql
        .lines()
        .filter_map(|l| l.strip_prefix("CREATE CONSTRAINT TRIGGER "))
        .map(|rest| {
            let words: Vec<&str> = rest.split_whitespace().collect();
            let on = words.iter().position(|w| *w == "ON").expect("a trigger names its table");
            (words[on + 1].to_string(), words[0].to_string())
        })
        .collect();
    assert_eq!(created.len(), 2, "{sql}");
    let m = Sql::new(&s).manifest().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(m.triggers, created, "{sql}");
    let drops = Manifest::default().drops_since(&m);
    for (table, name) in &created {
        assert!(drops.contains(&format!("DROP TRIGGER IF EXISTS {name} ON {table};")), "{drops}");
    }
}

fn renaming(subject: &str) -> demesne_syntax::Spec {
    let src = format!(
        "topology {{ level tenant }}
subject {subject} {{ anchor tenant; reach self; identifies member_id; roles none; binds owner }}
object doc {{
  table docs
  scoped tenant
  relation owner: {subject} via owner_id
  relation grantee: {subject} via grant acl(doc_id, principal_kind, principal_id, access)
  permission view = owner + grantee:read @rls maps select
}}
object note {{
  table notes
  scoped tenant
  relation owner: {subject} via owner_id
  permission view = owner @rls maps select
}}
"
    );
    let s = demesne_syntax::parse(&src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    s
}

#[test]
fn a_migration_drops_first_a_function_whose_parameters_changed_and_only_the_policies_that_call_it() {
    let (before, after) = (Sql::new(&renaming("member")).manifest().expect("a manifest"), Sql::new(&renaming("customer")).manifest().expect("a manifest"));
    let read = Manifest::from_json(&after.to_json()).expect("the manifest reads back");
    assert_eq!(read.heads, after.heads, "the heads round-trip");
    let prologue = after.renamed_since(&before);
    assert_eq!(
        prologue, "DROP POLICY IF EXISTS docs_select ON public.docs;\nDROP FUNCTION IF EXISTS auth.acl_grants(text, text, text);\n",
        "only the check whose parameter is named after the subject, and the one policy that calls it"
    );
    assert_eq!(after.renamed_since(&after), "", "nothing changed, nothing dropped");
    let older = Manifest { heads: None, ..before };
    assert!(after.renamed_since(&older).starts_with("-- the previous manifest records no parameters"), "{}", after.renamed_since(&older));
}
