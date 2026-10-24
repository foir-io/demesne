use crate::corpus::Entry;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

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

pub fn run_cli(bin: &Path, spec: &Path, args: &[&str]) -> Vec<u8> {
    let argv: Vec<String> = args
        .iter()
        .map(|a| if *a == "{spec}" { spec.to_string_lossy().into_owned() } else { a.to_string() })
        .collect();
    let out = Command::new(bin).args(&argv).env_remove("DATABASE_URL").output();
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

pub fn parallel<T: Sync>(items: &[T], f: impl Fn(&T) + Sync) {
    let next = AtomicUsize::new(0);
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    std::thread::scope(|scope| {
        for _ in 0..n {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    f(&items[i]);
                }
            });
        }
    });
}

pub fn dump_cli(bin: &Path, entries: &[Entry], out: &Path) {
    let jobs: Vec<(&Entry, &CliOutput)> = entries.iter().flat_map(|e| CLI_OUTPUTS.iter().map(move |c| (e, c))).collect();
    parallel(&jobs, |(e, c)| {
        let dir = out.join(&e.id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("cli-{}.txt", c.name)), run_cli(bin, &e.path, c.args)).unwrap();
    });
}

pub fn write_list(entries: &[Entry], path: &Path) {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!("{}\t{}\n", e.id, fs::canonicalize(&e.path).unwrap().display()));
    }
    fs::write(path, s).unwrap();
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
                let rel = p.strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/");
                out.insert(rel, p);
            }
        }
    }
    out
}

pub struct Mismatch {
    pub key: String,
    pub detail: String,
}

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
            let show = |l: Option<&[u8]>| l.map(|l| String::from_utf8_lossy(l).into_owned()).unwrap_or_else(|| "<eof>".into());
            return format!("line {}:\n    go:   {}\n    rust: {}", i + 1, show(x), show(y));
        }
    }
    "identical".into()
}

pub fn compare(go: &Path, rust: &Path, only: Option<&dyn Fn(&str) -> bool>) -> Summary {
    let g = files_under(go);
    let r = files_under(rust);
    let mut sum = Summary { outputs: 0, identical: 0, missing_rust: 0, mismatches: Vec::new(), by_output: BTreeMap::new() };
    let mismatches = Mutex::new(Vec::new());
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
        let a = fs::read(gp).unwrap();
        let b = fs::read(rp).unwrap();
        if a == b {
            sum.identical += 1;
            slot.1 += 1;
        } else {
            mismatches.lock().unwrap().push(Mismatch { key: key.clone(), detail: first_difference(&a, &b) });
        }
    }
    sum.mismatches = mismatches.into_inner().unwrap();
    sum
}
