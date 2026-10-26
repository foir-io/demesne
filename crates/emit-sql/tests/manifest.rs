use demesne_emit_sql::{Manifest, Sql, validate};

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
    let previous = Sql::new(&spec("d15-before.demesne")).manifest().expect("a manifest");
    let after = spec("d15-after.demesne");
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
    let after = spec("d15-after.demesne");
    let own = Sql::new(&after).manifest().expect("a manifest");
    assert_eq!(Sql::new(&after).migration(&own), Ok(all_sql(&after)));
}

#[test]
fn the_manifest_reads_back_what_it_wrote() {
    let m = Sql::new(&spec("d15-before.demesne")).manifest().expect("a manifest");
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
