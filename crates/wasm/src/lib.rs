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
#[derive(Debug)]
pub struct RunResult {
    code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[wasm_bindgen]
impl RunResult {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn code(&self) -> u8 {
        self.code
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn stdout(&self) -> Vec<u8> {
        self.stdout.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn stderr(&self) -> Vec<u8> {
        self.stderr.clone()
    }
}

#[must_use]
pub fn run_native(args: &[String], files: BTreeMap<String, Vec<u8>>) -> Output {
    run_pure(args, &MemFiles(files)).unwrap_or_else(|| Output {
        code: 1,
        stdout: Vec::new(),
        stderr: format!("demesne: {} needs a database connection, which the WebAssembly build does not have; use the native CLI\n", args[0]).into_bytes(),
    })
}

#[wasm_bindgen]
#[must_use]
#[expect(clippy::needless_pass_by_value, reason = "wasm-bindgen hands a JavaScript string array over only by value")]
pub fn run(args: Vec<String>, paths: Vec<String>, blob: &[u8], lengths: Vec<u32>) -> RunResult {
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
#[must_use]
pub fn validate(source: &str) -> Option<String> {
    let spec = match demesne_syntax::parse(source) {
        Ok(s) => s,
        Err(e) => return Some(format!("parse: {e}")),
    };
    demesne_emit_sql::validate(&spec).err().map(|e| format!("validate: {e}"))
}

/// Returns every problem in `source`, or for a valid spec the warnings it still earns, as a JSON array of `{"severity": "error" | "warning", "line": number | null, "message": string}`. The line is the finding's own, or null when it belongs to no single line.
#[wasm_bindgen]
#[must_use]
pub fn diagnostics(source: &str) -> String {
    let found: Vec<Value> = match demesne_syntax::parse(source) {
        Err(e) => vec![located("error", e.finding())],
        Ok(spec) => match demesne_emit_sql::validate(&spec) {
            Err(e) => e.findings().iter().map(|f| located("error", f)).collect(),
            Ok(()) => demesne_emit_sql::validate_warnings(&spec).iter().map(|w| located("warning", w)).collect(),
        },
    };
    json::marshal(&Value::Array(found))
}

fn located(severity: &str, f: &demesne_syntax::Finding) -> Value {
    let line = f.line().map_or(Value::Null, |n| Value::Int(i64::try_from(n).expect("a spec's line count fits in i64")));
    Value::Struct(vec![("severity".into(), Value::str(severity)), ("line".into(), line), ("message".into(), Value::str(f.message()))])
}

#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    demesne_cli::build_version().to_string()
}

#[wasm_bindgen]
#[must_use]
pub fn live_commands() -> Vec<String> {
    LIVE_COMMANDS.iter().map(ToString::to_string).collect()
}
