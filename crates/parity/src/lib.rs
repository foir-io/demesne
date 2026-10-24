#![doc = "The differential harness that proves demesne-rs byte-identical to the frozen Go engine."]

pub mod api;
pub mod corpus;
pub mod dsn;
pub mod fuzz;
pub mod goast;
pub mod oracle;
pub mod runner;

use demesne_gocompat::json::{self, Value};
use std::path::Path;

pub fn oracle_manifest(dir: &Path) -> Result<String, String> {
    let order = std::fs::read_to_string(dir.join("ORDER")).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    for name in order.lines().filter(|l| !l.is_empty()) {
        let src = std::fs::read_to_string(dir.join(format!("{name}.demesne"))).map_err(|e| e.to_string())?;
        let spec = demesne_syntax::parse(&src).map_err(|e| format!("{name}: parse: {e}"))?;
        entries.push((name.to_string(), oracle::build_oracle_entry(&spec).map_err(|e| format!("{name}: buildOracleEntry: {e}"))?));
    }
    Ok(json::marshal_indent(&Value::Map(entries), "", "  ") + "\n")
}
