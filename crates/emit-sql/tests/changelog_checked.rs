use demesne_emit_sql::Sql;

const SPEC: &str = "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\nobject doc {\n  table docs\n  scoped estate > space\n  relation owner: member via owner_id where owner_kind = \"member\"\n  relation grantee: member via grant doc_acl(doc_id, principal_kind, principal_id, access) tracked\n  permission view = owner + mode visibility = \"public\" + grantee:read @rls maps select\n  permission edit = owner @rls maps update\n  track owner\n  track visibility\n}\n";

fn changelog(src: &str) -> String {
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    Sql::new(&s).changelog_sql()
}

#[test]
fn the_declaration_parses_once() {
    assert_eq!(demesne_syntax::parse(&format!("changelog checked\n{SPEC}")).expect("parses").changelog, Some(demesne_syntax::Changelog::Checked));
    assert_eq!(demesne_syntax::parse(SPEC).expect("parses").changelog, None);
    assert!(
        demesne_syntax::parse(&format!("changelog checked\nchangelog checked\n{SPEC}"))
            .expect_err("twice")
            .to_string()
            .contains("duplicate changelog declaration")
    );
    demesne_syntax::parse(&format!("changelog written\n{SPEC}")).expect_err("`checked` is the one form");
}

#[test]
fn without_the_declaration_the_triggers_write_and_notify_as_before() {
    let sql = changelog(SPEC);
    assert!(sql.contains("INSERT INTO auth._authz_changelog") && sql.contains("pg_notify('demesne_authz_changelog'"), "{sql}");
    assert!(!sql.contains("CONSTRAINT TRIGGER") && !sql.contains("RAISE") && !sql.contains("txid"), "{sql}");
}

#[test]
fn a_checked_changelog_only_refuses_at_commit() {
    let sql = changelog(&format!("changelog checked\n{SPEC}"));
    for acting in ["INSERT INTO", "pg_notify", "UPDATE auth", "DELETE FROM"] {
        assert!(!sql.contains(acting), "a checked changelog writes nothing, but emits {acting:?}:\n{sql}");
    }
    let event = |rel: &str, resource: &str, kind: &str, principal: &str, op: &str| {
        format!(
            "IF NOT EXISTS (SELECT 1 FROM auth._authz_changelog WHERE txid = pg_current_xact_id() AND rel = '{rel}' AND resource_id = ({resource})::text AND principal_kind = {kind} AND principal_id = ({principal})::text AND op = '{op}') THEN"
        )
    };
    let wanted = [
        "txid xid8 NOT NULL DEFAULT pg_current_xact_id()\n);".to_string(),
        "ALTER TABLE auth._authz_changelog ADD COLUMN IF NOT EXISTS txid xid8 NOT NULL DEFAULT pg_current_xact_id();".to_string(),
        "CREATE INDEX IF NOT EXISTS _authz_changelog_rel_txid_idx ON auth._authz_changelog (rel, txid);".to_string(),
        event("doc_acl", "NEW.doc_id", "NEW.principal_kind", "NEW.principal_id", "grant"),
        event("doc_acl", "OLD.doc_id", "OLD.principal_kind", "OLD.principal_id", "revoke"),
        event("doc", "NEW.id", "COALESCE(OLD.owner_kind, '')", "OLD.owner_id", "revoke"),
        event("doc", "NEW.id", "COALESCE(NEW.owner_kind, '')", "NEW.owner_id", "grant"),
        event("doc", "NEW.id", "''", "''", "visibility"),
        "USING ERRCODE = 'check_violation', CONSTRAINT = 'doc_acl_changelog_written', TABLE = 'doc_acl';".to_string(),
        "USING ERRCODE = 'check_violation', CONSTRAINT = 'docs_changelog_written', TABLE = 'docs';".to_string(),
        "CREATE CONSTRAINT TRIGGER doc_acl_changelog AFTER INSERT OR DELETE ON public.doc_acl DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.doc_acl_changelog();".to_string(),
        "CREATE CONSTRAINT TRIGGER docs_obj_changelog AFTER UPDATE OF owner_id, owner_kind, visibility ON public.docs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.docs_obj_changelog();".to_string(),
        "DROP TRIGGER IF EXISTS doc_acl_changelog ON public.doc_acl;".to_string(),
    ];
    let lacking: Vec<&String> = wanted.iter().filter(|w| !sql.contains(w.as_str())).collect();
    assert!(lacking.is_empty(), "lacks {lacking:#?}:\n{sql}");
}
