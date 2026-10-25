#![doc = "Live-database support for demesne: introspection into a `Schema`, the drift `diff` reports, the schema traps, the global-assignment audit and the RLS role check."]

mod connect;
mod drift;
mod dsn;
mod goerr;
mod lint;

pub use connect::connect;
pub use drift::{Drift, DriftKind, Finding, drift};
pub use dsn::parse_config_dump;
pub use lint::{Severity, Trap, schema_traps};

use demesne_model::Schema;
use postgres::Client;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntrospectMeta {
    pub tables: usize,
    pub columns: usize,
    pub fks: usize,
}

#[must_use]
pub fn query_error(e: &postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("{}: {} (SQLSTATE {})", db.severity(), db.message(), db.code().code());
    }
    let mut out = e.to_string();
    let mut cur = std::error::Error::source(e);
    while let Some(c) = cur {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cur = c.source();
    }
    out
}

/// Reads the `public` schema's tables, columns, keys and foreign keys.
///
/// # Errors
///
/// A catalog query fails.
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
        .map_err(|e| query_error(&e))?;
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
        .map_err(|e| query_error(&e))?;
    for row in fks {
        let (table, col, ref_table, ref_col): (String, String, String, String) = (row.get(0), row.get(1), row.get(2), row.get(3));
        sc.add_foreign_key(&table, &col, &ref_table, &ref_col);
        meta.fks += 1;
    }
    Ok((sc, meta))
}

/// Returns whether `role` exists and, if it does, whether it bypasses row-level security.
///
/// # Errors
///
/// The catalog query fails.
pub fn role_bypasses_rls(client: &mut Client, role: &str) -> Result<(bool, bool), String> {
    let rows = client.query("SELECT rolbypassrls FROM pg_roles WHERE rolname = $1", &[&role]).map_err(|e| query_error(&e))?;
    match rows.first() {
        Some(row) => Ok((true, row.get(0))),
        None => Ok((false, false)),
    }
}

/// Counts the rows `query` returns.
///
/// # Errors
///
/// The query fails.
pub fn count_global_assignments(client: &mut Client, query: &str) -> Result<i64, String> {
    let row = client.query_one(&format!("SELECT count(*) FROM ({query}) q"), &[]).map_err(|e| query_error(&e))?;
    Ok(row.get(0))
}
