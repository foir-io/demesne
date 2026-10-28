#![cfg(feature = "db")]

use postgres::{Client, NoTls};
use std::process::Command;

const SPEC: &str = r#"
topology {
  level tenant    col tenant_id claim tenant
  level workspace parent tenant col ws_id claim ws
}

vocabulary staff {
  permission docs:read
  preset viewer @ workspace = docs:read
}

rolestore staff {
  assignments d16cli_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id ws_id
  rolejoin    role_id d16cli_roles id key
  revoked     revoked_at
  permissions permissions
}

subject staff  { anchor tenant; reach descendants; identifies sub; roles configurable staff; binds admin }
subject member { anchor workspace; reach self; identifies member_id; roles none; binds owner }

object doc {
  table  d16cli_docs
  pk     id
  scoped tenant > workspace
  relation owner: member via owner_id
  permission view = owner @rls maps select
}
"#;

const SCHEMA: &str = "
DROP VIEW IF EXISTS d16cli_open; DROP TABLE IF EXISTS d16cli_docs, d16cli_grants, d16cli_roles;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
CREATE TABLE d16cli_docs (id text PRIMARY KEY, tenant_id text NOT NULL, ws_id text, owner_id text, title text);
CREATE TABLE d16cli_roles (id text PRIMARY KEY, key text, permissions text[]);
CREATE TABLE d16cli_grants (grantee_kind text, grantee_id text, tenant_id text NOT NULL, ws_id text, role_id text, revoked_at timestamptz);
CREATE UNIQUE INDEX d16cli_docs_title ON d16cli_docs (tenant_id, ws_id, title);
CREATE UNIQUE INDEX d16cli_grants_once ON d16cli_grants (grantee_id, role_id, tenant_id, ws_id);
CREATE VIEW d16cli_open AS SELECT * FROM d16cli_docs;
";

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn check_reports_the_traps_around_the_specs_own_tables() {
    let url =
        std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to run check against a live Postgres"));
    let mut db = Client::connect(&url, NoTls).expect("connect");
    db.batch_execute(SCHEMA).expect("the schema");
    let spec = format!("{}/check_pg.demesne", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&spec, SPEC).expect("the spec writes");

    let out = Command::new(env!("CARGO_BIN_EXE_demesne")).args(["check", &spec, &url]).output().expect("the CLI runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let traps: Vec<&str> =
        stdout.lines().filter(|l| l.starts_with("DANGER:") || l.starts_with("warning:")).map(|l| l.split(", so").next().unwrap_or_default()).collect();
    assert_eq!(
        traps,
        [
            "DANGER: view public.d16cli_open over governed public.d16cli_docs reads as its owner postgres, who bypasses row level security",
            "warning: unique index public.d16cli_docs_title on public.d16cli_docs includes the nullable scope column ws_id without NULLS NOT DISTINCT",
            "warning: unique index public.d16cli_grants_once on public.d16cli_grants includes the nullable scope column ws_id without NULLS NOT DISTINCT",
        ],
        "{stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "a DANGER trap fails check");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "demesne: 1 schema trap(s) let rows past the policies\n");

    db.batch_execute("DROP VIEW d16cli_open; DROP INDEX d16cli_docs_title, d16cli_grants_once").expect("the traps go");
    let out = Command::new(env!("CARGO_BIN_EXE_demesne")).args(["check", &spec, &url]).output().expect("the CLI runs");
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok: no schema traps"), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.status.code(), Some(0));
    db.batch_execute("DROP TABLE d16cli_docs, d16cli_grants, d16cli_roles").expect("clean up");
}
