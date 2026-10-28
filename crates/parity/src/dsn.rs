use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

pub const PG_ENV: &[&str] = &[
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGAPPNAME",
    "PGCONNECT_TIMEOUT",
    "PGSSLMODE",
    "PGSSLKEY",
    "PGSSLCERT",
    "PGSSLSNI",
    "PGSSLROOTCERT",
    "PGSSLPASSWORD",
    "PGSSLNEGOTIATION",
    "PGTARGETSESSIONATTRS",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGTZ",
    "PGOPTIONS",
    "PGMINPROTOCOLVERSION",
    "PGMAXPROTOCOLVERSION",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub env: Vec<(String, String)>,
    pub dsn: String,
}

#[must_use]
pub fn parse_cases(text: &str) -> Vec<Case> {
    let mut out: Vec<Case> = Vec::new();
    for line in text.split('\n') {
        if let Some(name) = line.strip_prefix("--- ") {
            out.push(Case { name: name.to_string(), env: Vec::new(), dsn: String::new() });
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kv) = line.strip_prefix("env ") {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            cur.env.push((k.to_string(), v.to_string()));
        } else if line == "dsn" {
            cur.dsn.clear();
        } else if let Some(d) = line.strip_prefix("dsn ") {
            cur.dsn = d.to_string();
        }
    }
    out
}

/// Parses each connection-string case in a clean child process and returns the results.
///
/// # Errors
///
/// The current executable cannot be found or a child cannot be run.
pub fn dump_cases(cases: &[Case], work: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut out = String::new();
    for c in cases {
        let mut cmd = Command::new(&exe);
        cmd.arg("dsn-one").arg(&c.dsn);
        for k in PG_ENV {
            cmd.env_remove(k);
        }
        cmd.env("PGPASSFILE", work.join("no-passfile"));
        cmd.env("PGSERVICEFILE", work.join("no-servicefile"));
        for (k, v) in &c.env {
            cmd.env(k, v);
        }
        let o = cmd.output().map_err(|e| format!("dsn-one: {e}"))?;
        if !o.status.success() {
            return Err(format!("dsn-one {}: {}", c.name, String::from_utf8_lossy(&o.stderr)));
        }
        write!(out, "--- {}\n{}", c.name, String::from_utf8_lossy(&o.stdout)).expect("fmt::Write for String never fails");
    }
    Ok(out)
}

#[must_use]
pub fn split_dump(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split_inclusive('\n') {
        if let Some(name) = line.strip_prefix("--- ") {
            out.push((name.trim_end_matches('\n').to_string(), String::new()));
        } else if let Some(cur) = out.last_mut() {
            cur.1.push_str(line);
        }
    }
    out
}
