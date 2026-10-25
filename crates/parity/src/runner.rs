use crate::corpus::Entry;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct CliOutput {
    pub name: &'static str,
    pub args: &'static [&'static str],
}

pub const CLI_OUTPUTS: &[CliOutput] = &[
    CliOutput { name: "validate", args: &["validate", "{spec}"] },
    CliOutput { name: "emit-rls", args: &["emit", "{spec}", "rls"] },
    CliOutput { name: "emit-definers", args: &["emit", "{spec}", "definers"] },
    CliOutput { name: "emit-enablement", args: &["emit", "{spec}", "enablement"] },
    CliOutput { name: "emit-triggers", args: &["emit", "{spec}", "triggers"] },
    CliOutput { name: "emit-claims", args: &["emit", "{spec}", "claims"] },
    CliOutput { name: "emit-pdp", args: &["emit", "{spec}", "pdp"] },
    CliOutput { name: "emit-framework", args: &["emit", "{spec}", "framework"] },
    CliOutput { name: "emit-framework-pkg", args: &["emit", "{spec}", "framework", "policy"] },
    CliOutput { name: "emit-all", args: &["emit", "{spec}", "all"] },
    CliOutput { name: "ts-claims", args: &["emit", "--target", "ts", "{spec}", "claims"] },
    CliOutput { name: "ts-pdp", args: &["emit", "--target", "ts", "{spec}", "pdp"] },
    CliOutput { name: "ts-projections", args: &["emit", "--target=ts", "{spec}", "projections"] },
    CliOutput { name: "ts-framework", args: &["emit", "{spec}", "framework", "--target", "ts"] },
    CliOutput { name: "supabase", args: &["emit", "--profile", "supabase", "{spec}"] },
];

#[must_use]
pub fn run_cli(bin: &Path, spec: &Path, args: &[&str]) -> Vec<u8> {
    let cli_args: Vec<String> = args.iter().map(|a| if *a == "{spec}" { spec.to_string_lossy().into_owned() } else { a.to_string() }).collect();
    let out = Command::new(bin).args(&cli_args).env_remove("DATABASE_URL").output();
    let mut rec = Vec::new();
    match out {
        Ok(o) => {
            rec.extend_from_slice(format!("exit: {}\n--- stdout ---\n", o.status.code().unwrap_or(-1)).as_bytes());
            rec.extend_from_slice(&o.stdout);
            rec.extend_from_slice(b"\n--- stderr ---\n");
            rec.extend_from_slice(&o.stderr);
        }
        Err(e) => rec.extend_from_slice(format!("spawn failed: {e}\n").as_bytes()),
    }
    rec
}

/// Runs `f` over `items` on every core and returns the first error any call reports.
///
/// # Errors
///
/// The first error `f` returned; the remaining items are skipped once one fails.
///
/// # Panics
///
/// When `f` panics; the panic is raised again once every worker has stopped.
pub fn parallel<T: Sync>(items: &[T], f: impl Fn(&T) -> Result<(), String> + Sync) -> Result<(), String> {
    let next = AtomicUsize::new(0);
    let failed: Mutex<Option<String>> = Mutex::new(None);
    let n = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    std::thread::scope(|scope| {
        for _ in 0..n {
            scope.spawn(|| drain(items, &next, &failed, &f));
        }
    });
    match failed.into_inner().expect("parallel error slot poisoned") {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn drain<T>(items: &[T], next: &AtomicUsize, failed: &Mutex<Option<String>>, f: &impl Fn(&T) -> Result<(), String>) {
    loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        if i >= items.len() || failed.lock().expect("parallel error slot poisoned").is_some() {
            return;
        }
        if let Err(e) = f(&items[i]) {
            failed.lock().expect("parallel error slot poisoned").get_or_insert(e);
        }
    }
}

/// Runs every CLI invocation in [`CLI_OUTPUTS`] over every entry and writes each record under `out`.
///
/// # Errors
///
/// A directory or record under `out` that cannot be written.
pub fn dump_cli(bin: &Path, entries: &[Entry], out: &Path) -> Result<(), String> {
    let jobs: Vec<(&Entry, &CliOutput)> = entries.iter().flat_map(|e| CLI_OUTPUTS.iter().map(move |c| (e, c))).collect();
    parallel(&jobs, |(e, c)| {
        let dir = out.join(&e.id);
        fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        let path = dir.join(format!("cli-{}.txt", c.name));
        fs::write(&path, run_cli(bin, &e.path, c.args)).map_err(|err| format!("{}: {err}", path.display()))
    })
}

/// Writes the entry list the Go dump reads: each id and its spec's canonical path.
///
/// # Errors
///
/// A spec path that cannot be canonicalised, or a list file that cannot be written.
pub fn write_list(entries: &[Entry], path: &Path) -> Result<(), String> {
    let mut s = String::new();
    for e in entries {
        let full = fs::canonicalize(&e.path).map_err(|err| format!("{}: {err}", e.path.display()))?;
        writeln!(s, "{}\t{}", e.id, full.display()).expect("fmt::Write for String never fails");
    }
    fs::write(path, s).map_err(|err| format!("{}: {err}", path.display()))
}

fn files_under(dir: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).expect("the walk only visits paths under its root").to_string_lossy().replace('\\', "/");
                out.insert(rel, p);
            }
        }
    }
    out
}

#[derive(Debug)]
pub struct Mismatch {
    pub key: String,
    pub detail: String,
}

#[derive(Debug)]
pub struct Summary {
    pub outputs: usize,
    pub identical: usize,
    pub missing_rust: usize,
    pub mismatches: Vec<Mismatch>,
    pub by_output: BTreeMap<String, (usize, usize)>,
}

fn first_difference(a: &[u8], b: &[u8]) -> String {
    let al: Vec<&[u8]> = a.split(|c| *c == b'\n').collect();
    let bl: Vec<&[u8]> = b.split(|c| *c == b'\n').collect();
    for i in 0..al.len().max(bl.len()) {
        let x = al.get(i).copied();
        let y = bl.get(i).copied();
        if x != y {
            let show = |l: Option<&[u8]>| l.map_or_else(|| "<eof>".into(), |l| String::from_utf8_lossy(l).into_owned());
            return format!("line {}:\n    go:   {}\n    rust: {}", i + 1, show(x), show(y));
        }
    }
    "identical".into()
}

/// Compares every output under `go` with the same path under `rust`, byte for byte.
///
/// # Errors
///
/// An output file that exists but cannot be read.
pub fn compare(go: &Path, rust: &Path, only: Option<&dyn Fn(&str) -> bool>) -> Result<Summary, String> {
    let g = files_under(go);
    let r = files_under(rust);
    let mut sum = Summary { outputs: 0, identical: 0, missing_rust: 0, mismatches: Vec::new(), by_output: BTreeMap::new() };
    for (key, gp) in &g {
        if let Some(f) = only
            && !f(key)
        {
            continue;
        }
        let kind = key.rsplit('/').next().unwrap_or(key).to_string();
        let slot = sum.by_output.entry(kind).or_insert((0, 0));
        slot.0 += 1;
        sum.outputs += 1;
        let Some(rp) = r.get(key) else {
            sum.missing_rust += 1;
            continue;
        };
        let a = fs::read(gp).map_err(|err| format!("{}: {err}", gp.display()))?;
        let b = fs::read(rp).map_err(|err| format!("{}: {err}", rp.display()))?;
        if a == b {
            sum.identical += 1;
            slot.1 += 1;
        } else {
            sum.mismatches.push(Mismatch { key: key.clone(), detail: first_difference(&a, &b) });
        }
    }
    Ok(sum)
}
