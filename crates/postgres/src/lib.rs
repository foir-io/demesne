#![doc = "Live-database support for demesne: introspection into a `Schema`, the policy surface `diff` compares, the global-assignment audit and the RLS role check."]

use demesne_model::Schema;
use postgres::{Client, Config};
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntrospectMeta {
    pub tables: usize,
    pub columns: usize,
    pub fks: usize,
}

fn tls() -> tokio_postgres_rustls::MakeRustlsConnect {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(config)
}

pub fn describe(e: &postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("server error: {}: {} (SQLSTATE {})", db.severity(), db.message(), db.code().code());
    }
    let mut out = e.to_string();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(c) = cur {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cur = c.source();
    }
    out
}

pub fn connect(dsn: &str) -> Result<Client, String> {
    let config: Config = dsn.parse().map_err(|e: postgres::Error| describe(&e))?;
    config.connect(tls()).map_err(|e| {
        let user = config.get_user().unwrap_or("");
        let db = config.get_dbname().unwrap_or(user);
        let host = match config.get_hosts().first() {
            Some(postgres::config::Host::Tcp(h)) => h.clone(),
            Some(postgres::config::Host::Unix(p)) => p.display().to_string(),
            None => "localhost".into(),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        format!("failed to connect to `user={user} database={db}`: {host}:{port}: {}", describe(&e))
    })
}

pub fn introspect(client: &mut Client) -> Result<(Schema, IntrospectMeta), String> {
    let mut sc = Schema::new();
    let mut meta = IntrospectMeta::default();
    let mut tables = BTreeSet::new();
    let rows = client
        .query(
            "SELECT table_name::text, column_name::text, data_type::text, (is_nullable = 'YES')
             FROM information_schema.columns WHERE table_schema = 'public'",
            &[],
        )
        .map_err(|e| describe(&e))?;
    for row in rows {
        let (table, col, typ, nullable): (String, String, String, bool) = (row.get(0), row.get(1), row.get(2), row.get(3));
        sc.add_column(&table, &col, &typ, nullable);
        meta.columns += 1;
        tables.insert(table);
    }
    meta.tables = tables.len();
    let fks = client
        .query(
            "SELECT tc.table_name::text, kcu.column_name::text, ccu.table_name::text, ccu.column_name::text
             FROM information_schema.table_constraints tc
             JOIN information_schema.key_column_usage kcu
               ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
             JOIN information_schema.constraint_column_usage ccu
               ON tc.constraint_name = ccu.constraint_name
             WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'",
            &[],
        )
        .map_err(|e| describe(&e))?;
    for row in fks {
        let (table, col, ref_table, ref_col): (String, String, String, String) = (row.get(0), row.get(1), row.get(2), row.get(3));
        sc.add_foreign_key(&table, &col, &ref_table, &ref_col);
        meta.fks += 1;
    }
    Ok((sc, meta))
}

pub fn role_bypasses_rls(client: &mut Client, role: &str) -> Result<(bool, bool), String> {
    let rows = client.query("SELECT rolbypassrls FROM pg_roles WHERE rolname = $1", &[&role]).map_err(|e| describe(&e))?;
    match rows.first() {
        Some(row) => Ok((true, row.get(0))),
        None => Ok((false, false)),
    }
}

pub fn count_global_assignments(client: &mut Client, query: &str) -> Result<i64, String> {
    let row = client.query_one(&format!("SELECT count(*) FROM ({query}) q"), &[]).map_err(|e| describe(&e))?;
    Ok(row.get(0))
}

pub fn live_policy_surface(client: &mut Client, governed: &[String]) -> Result<BTreeSet<String>, String> {
    let tset: BTreeSet<&str> = governed.iter().map(String::as_str).collect();
    let rows = client
        .query("SELECT tablename::text, policyname::text FROM pg_policies WHERE schemaname = 'public'", &[])
        .map_err(|e| describe(&e))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let (table, pol): (String, String) = (row.get(0), row.get(1));
        if tset.contains(table.as_str()) {
            out.insert(format!("{table}.{pol}"));
        }
    }
    Ok(out)
}
