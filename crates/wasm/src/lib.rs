#![doc = "demesne's compiler as WebAssembly. `run` is the CLI's pure commands over in-memory files, byte-identical to the native binary; `validate` parses and validates one spec."]

use demesne_cli::{Files, LIVE_COMMANDS, Output, run_pure};
use demesne_gocompat::json::{self, Value};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::wasm_bindgen;

struct MemFiles(BTreeMap<String, Vec<u8>>);

impl Files for MemFiles {
    fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        self.0.get(path).cloned().ok_or_else(|| format!("open {path}: no such file or directory"))
    }
}

#[wasm_bindgen]
pub struct RunResult {
    code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[wasm_bindgen]
impl RunResult {
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> u8 {
        self.code
    }

    #[wasm_bindgen(getter)]
    pub fn stdout(&self) -> Vec<u8> {
        self.stdout.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn stderr(&self) -> Vec<u8> {
        self.stderr.clone()
    }
}

pub fn run_native(args: &[String], files: BTreeMap<String, Vec<u8>>) -> Output {
    run_pure(args, &MemFiles(files)).unwrap_or_else(|| Output {
        code: 1,
        stdout: Vec::new(),
        stderr: format!("demesne: {} needs a database connection, which the WebAssembly build does not have; use the native CLI\n", args[0]).into_bytes(),
    })
}

#[wasm_bindgen]
pub fn run(args: Vec<String>, paths: Vec<String>, blob: Vec<u8>, lengths: Vec<u32>) -> RunResult {
    let mut files = BTreeMap::new();
    let mut at = 0usize;
    for (p, n) in paths.into_iter().zip(lengths) {
        let end = (at + n as usize).min(blob.len());
        files.insert(p, blob[at..end].to_vec());
        at = end;
    }
    let o = run_native(&args, files);
    RunResult { code: o.code, stdout: o.stdout, stderr: o.stderr }
}

#[wasm_bindgen]
pub fn validate(source: &str) -> Option<String> {
    let spec = match demesne_syntax::parse(source) {
        Ok(s) => s,
        Err(e) => return Some(format!("parse: {e}")),
    };
    demesne_emit_sql::validate(&spec).err().map(|e| format!("validate: {e}"))
}

/// Returns every problem in `source`, or for a valid spec the warnings it still earns, as a JSON array of `{"severity": "error" | "warning", "line": number | null, "message": string}`. The line is the one a message names with its `line N:` prefix.
#[wasm_bindgen]
#[must_use]
pub fn diagnostics(source: &str) -> String {
    let found: Vec<Value> = match demesne_syntax::parse(source) {
        Err(e) => e.message().lines().map(|m| finding("error", m)).collect(),
        Ok(spec) => match demesne_emit_sql::validate(&spec) {
            Err(e) => e.lines().map(|m| finding("error", m)).collect(),
            Ok(()) => demesne_emit_sql::validate_warnings(&spec).iter().map(|w| finding("warning", w)).collect(),
        },
    };
    json::marshal(&Value::Array(found))
}

fn finding(severity: &str, text: &str) -> Value {
    let located = text.strip_prefix("line ").and_then(|rest| rest.split_once(": ")).and_then(|(n, message)| n.parse::<i64>().ok().map(|n| (n, message)));
    let (line, message) = located.map_or((Value::Null, text), |(n, message)| (Value::Int(n), message));
    Value::Struct(vec![("severity".into(), Value::str(severity)), ("line".into(), line), ("message".into(), Value::str(message))])
}

#[wasm_bindgen]
pub fn version() -> String {
    demesne_cli::build_version().to_string()
}

#[wasm_bindgen]
pub fn live_commands() -> Vec<String> {
    LIVE_COMMANDS.iter().map(|c| c.to_string()).collect()
}
