use demesne_parity::{api, corpus, dsn, fuzz, goast, oracle, runner};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "demesne-parity: the differential runner against the frozen Go engine

USAGE:
  demesne-parity corpus
  demesne-parity fuzz --seed <n> --count <n> --mutate <n> --out <dir>
  demesne-parity run --go-tag <tag> --go-cli <path> [--rust-cli <path>] --out <dir> [--extra <prefix>=<dir>]... [--only <substr>] [--show <n>]
  demesne-parity dsn --cases <file> --work <dir> --go <go-dump> --out <rust-dump>
  demesne-parity cli-table
";

fn dsn_cmd(args: &[String]) -> Result<bool, String> {
    let mut cases = None;
    let mut work = None;
    let mut go = None;
    let mut out = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let v = it.next().ok_or_else(|| format!("{flag} needs a value"))?.clone();
        match flag.as_str() {
            "--cases" => cases = Some(v),
            "--work" => work = Some(v),
            "--go" => go = Some(v),
            "--out" => out = Some(v),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let (Some(cases), Some(work), Some(go), Some(out)) = (cases, work, go, out) else { return Err("dsn needs --cases, --work, --go and --out".into()) };
    let text = fs::read_to_string(&cases).map_err(|e| format!("{cases}: {e}"))?;
    let parsed = dsn::parse_cases(&text);
    let rust = dsn::dump_cases(&parsed, Path::new(&work))?;
    fs::write(&out, &rust).map_err(|e| format!("{out}: {e}"))?;
    let go_text = fs::read_to_string(&go).map_err(|e| format!("{go}: {e}"))?;
    let go_cases = dsn::split_dump(&go_text);
    let rust_cases = dsn::split_dump(&rust);
    if go_cases.len() != parsed.len() || rust_cases.len() != parsed.len() {
        return Err(format!("case counts differ: cases {} go {} rust {}", parsed.len(), go_cases.len(), rust_cases.len()));
    }
    let (mut same, mut named, mut differ) = (0, 0, 0);
    for ((name, g), (_, r)) in go_cases.iter().zip(rust_cases.iter()) {
        let expected_divergence = name.starts_with("named ");
        match (g == r, expected_divergence) {
            (true, false) => same += 1,
            (false, true) => {
                named += 1;
                println!("NAMED {name}\n  go:   {}\n  rust: {}", g.trim_end().replace('\n', "\n        "), r.trim_end().replace('\n', "\n        "));
            }
            (true, true) => {
                differ += 1;
                println!("UNEXPECTED MATCH {name}: a named divergence no longer diverges");
            }
            (false, false) => {
                differ += 1;
                println!("DIFF {name}\n  go:   {}\n  rust: {}", g.trim_end().replace('\n', "\n        "), r.trim_end().replace('\n', "\n        "));
            }
        }
    }
    println!("dsn: cases {}  identical {same}  named-divergence {named}  differ {differ}", parsed.len());
    Ok(differ == 0)
}

struct Args {
    go_tag: String,
    go_cli: Option<PathBuf>,
    rust_cli: Option<PathBuf>,
    out: PathBuf,
    extra: Vec<(String, PathBuf)>,
    only: Option<String>,
    show: usize,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { go_tag: "v0.93.1".into(), go_cli: None, rust_cli: None, out: PathBuf::new(), extra: Vec::new(), only: None, show: 20 };
    let mut i = 0;
    while i < argv.len() {
        let v = argv.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", argv[i]))?;
        match argv[i].as_str() {
            "--go-tag" => a.go_tag = v,
            "--go-cli" => a.go_cli = Some(PathBuf::from(v)),
            "--rust-cli" => a.rust_cli = Some(PathBuf::from(v)),
            "--out" => a.out = PathBuf::from(v),
            "--only" => a.only = Some(v),
            "--show" => a.show = v.parse().map_err(|_| "--show takes a number")?,
            "--extra" => {
                let (p, d) = v.split_once('=').ok_or("--extra takes <prefix>=<dir>")?;
                a.extra.push((p.to_string(), PathBuf::from(d)));
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    if a.out.as_os_str().is_empty() {
        return Err("--out is required".into());
    }
    Ok(a)
}

fn repo_root() -> PathBuf {
    let out = Command::new("git").args(["rev-parse", "--show-toplevel"]).output().expect("git");
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

fn dump_rust_lib(entries: &[corpus::Entry], out: &Path) {
    runner::parallel(entries, |e| {
        let dir = out.join(&e.id);
        fs::create_dir_all(&dir).unwrap();
        let src = fs::read(&e.path).unwrap();
        let spec = match demesne_syntax::parse_bytes(&src) {
            Ok(s) => s,
            Err(err) => {
                fs::write(dir.join("ast.json"), format!("parse error: {err}\n")).unwrap();
                return;
            }
        };
        fs::write(dir.join("ast.json"), demesne_gocompat::json::marshal(&goast::spec(&spec)) + "\n").unwrap();
        if demesne_emit_sql::validate(&spec).is_err() {
            return;
        }
        let oracle = match oracle::build_oracle_entry(&spec) {
            Ok(v) => demesne_gocompat::json::marshal_indent(&v, "", "  ") + "\n",
            Err(e) => format!("error: {e}\n"),
        };
        fs::write(dir.join("oracle.json"), oracle).unwrap();
        fs::write(dir.join("api.txt"), api::api_dump(&spec)).unwrap();
    });
}

fn run(a: Args) -> Result<bool, String> {
    let root = repo_root();
    let mut entries = corpus::collect(&root);
    for (prefix, dir) in &a.extra {
        corpus::add_dir(&mut entries, prefix, dir);
    }
    let _ = fs::remove_dir_all(&a.out);
    let go = a.out.join("go");
    let rust = a.out.join("rust");
    fs::create_dir_all(&go).map_err(|e| e.to_string())?;
    fs::create_dir_all(&rust).map_err(|e| e.to_string())?;
    let list = a.out.join("list.tsv");
    runner::write_list(&entries, &list);

    let status = Command::new(root.join("scripts/parity/go-dump.sh"))
        .args([a.go_tag.as_str(), list.to_str().unwrap(), go.to_str().unwrap()])
        .env("DEMESNE_PARITY_ORACLE_SPECS", a.out.join("oracle-specs"))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("the Go dump failed".into());
    }
    dump_rust_lib(&entries, &rust);
    if let Some(cli) = &a.go_cli {
        runner::dump_cli(cli, &entries, &go);
    }
    if let Some(cli) = &a.rust_cli {
        runner::dump_cli(cli, &entries, &rust);
    }

    let mut nondeterministic = 0usize;
    if let Some(gocli) = &a.go_cli {
        let by_id: std::collections::HashMap<&str, &corpus::Entry> = entries.iter().map(|e| (e.id.as_str(), e)).collect();
        sum_retry(&mut nondeterministic, gocli, &by_id, &go, &rust);
    }
    let only = a.only.clone();
    let filter = move |k: &str| only.as_deref().is_none_or(|o| k.contains(o));
    let sum = runner::compare(&go, &rust, Some(&filter));
    let mut report = String::new();
    if nondeterministic > 0 {
        report.push_str(&format!("go-nondeterministic outputs reconciled by rerun: {nondeterministic}\n"));
    }
    report.push_str(&format!(
        "specs {}  outputs {}  zero-diff {}  differ {}  missing-in-rust {}\n",
        entries.len(),
        sum.outputs,
        sum.identical,
        sum.mismatches.len(),
        sum.missing_rust
    ));
    for (kind, (n, ok)) in &sum.by_output {
        report.push_str(&format!("  {kind:<28} {ok:>6}/{n}\n"));
    }
    fs::write(a.out.join("report.txt"), {
        let mut full = report.clone();
        for m in &sum.mismatches {
            full.push_str(&format!("\nDIFF {}\n  {}\n", m.key, m.detail));
        }
        full
    })
    .map_err(|e| e.to_string())?;
    print!("{report}");
    for m in sum.mismatches.iter().take(a.show) {
        println!("DIFF {}\n  {}", m.key, m.detail);
    }
    Ok(sum.mismatches.is_empty() && sum.missing_rust == 0)
}

fn sum_retry(
    count: &mut usize,
    gocli: &Path,
    by_id: &std::collections::HashMap<&str, &corpus::Entry>,
    go: &Path,
    rust: &Path,
) {
    let pre = runner::compare(go, rust, None);
    for m in pre.mismatches {
        let Some((id, file)) = m.key.rsplit_once('/') else { continue };
        let Some(name) = file.strip_prefix("cli-").and_then(|f| f.strip_suffix(".txt")) else { continue };
        let (Some(entry), Some(out)) = (by_id.get(id), runner::CLI_OUTPUTS.iter().find(|c| c.name == name)) else { continue };
        let want = fs::read(rust.join(&m.key)).unwrap();
        for _ in 0..10 {
            let again = runner::run_cli(gocli, &entry.path, out.args);
            if again == want {
                fs::write(go.join(&m.key), &again).unwrap();
                *count += 1;
                break;
            }
        }
    }
}

fn fuzz_cmd(argv: &[String]) -> Result<(), String> {
    let mut seed = 1u64;
    let mut count = 100usize;
    let mut mutate = 0usize;
    let mut out = PathBuf::new();
    let mut i = 0;
    while i + 1 < argv.len() {
        let v = &argv[i + 1];
        match argv[i].as_str() {
            "--seed" => seed = v.parse().map_err(|_| "--seed takes a number")?,
            "--count" => count = v.parse().map_err(|_| "--count takes a number")?,
            "--mutate" => mutate = v.parse().map_err(|_| "--mutate takes a number")?,
            "--out" => out = PathBuf::from(v),
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    for n in 0..count {
        let s = seed.wrapping_mul(1_000_003).wrapping_add(n as u64);
        fs::write(out.join(format!("gen-{seed}-{n:05}.demesne")), fuzz::generate(s)).map_err(|e| e.to_string())?;
    }
    let base = corpus::collect(&repo_root());
    let mut r = fuzz::Rng::new(seed ^ 0xA5A5);
    for n in 0..mutate {
        let e = &base[r.below(base.len())];
        let src = fs::read_to_string(&e.path).map_err(|e| e.to_string())?;
        fs::write(out.join(format!("mut-{seed}-{n:05}.demesne")), fuzz::mutate(r.next_u64(), &src)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("corpus") => {
            for e in corpus::collect(&repo_root()) {
                println!("{}\t{}", e.id, e.path.display());
            }
            ExitCode::SUCCESS
        }
        Some("fuzz") => match fuzz_cmd(&argv[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("demesne-parity: {e}");
                ExitCode::from(2)
            }
        },
        Some("cli-table") => {
            let rows: Vec<String> = runner::CLI_OUTPUTS
                .iter()
                .map(|c| {
                    let args: Vec<String> = c.args.iter().map(|a| format!("{a:?}")).collect();
                    format!("{{\"name\":{:?},\"args\":[{}]}}", c.name, args.join(","))
                })
                .collect();
            println!("[{}]", rows.join(","));
            ExitCode::SUCCESS
        }
        Some("dsn-one") => {
            print!("{}", demesne_postgres::parse_config_dump(argv.get(1).map(String::as_str).unwrap_or("")));
            ExitCode::SUCCESS
        }
        Some("dsn") => match dsn_cmd(&argv[1..]) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("demesne-parity: {e}");
                ExitCode::from(2)
            }
        },
        Some("run") => match parse_args(&argv[1..]).and_then(run) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("demesne-parity: {e}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
