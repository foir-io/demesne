#![doc = "demesne's compiler as WebAssembly. `run` is the CLI's pure commands over in-memory files, byte-identical to the native binary; `validate` parses and validates one spec."]

use demesne_cli::{Files, LIVE_COMMANDS, Output, run_pure};
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

#[wasm_bindgen]
pub fn version() -> String {
    demesne_cli::build_version().to_string()
}

#[wasm_bindgen]
pub fn live_commands() -> Vec<String> {
    LIVE_COMMANDS.iter().map(|c| c.to_string()).collect()
}
