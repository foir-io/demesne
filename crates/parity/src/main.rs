#![expect(clippy::print_stdout, clippy::print_stderr, reason = "a test harness reports by printing")]
#![forbid(unsafe_code)]

use demesne_parity::{api, corpus, dsn, fuzz, goast, oracle, runner};
use std::fmt::Write as _;

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
    let mut parsed = Args { go_tag: "v0.93.1".into(), go_cli: None, rust_cli: None, out: PathBuf::new(), extra: Vec::new(), only: None, show: 20 };
    let mut i = 0;
    while i < argv.len() {
        let v = argv.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", argv[i]))?;
        match argv[i].as_str() {
            "--go-tag" => parsed.go_tag = v,
            "--go-cli" => parsed.go_cli = Some(PathBuf::from(v)),
            "--rust-cli" => parsed.rust_cli = Some(PathBuf::from(v)),
            "--out" => parsed.out = PathBuf::from(v),
            "--only" => parsed.only = Some(v),
            "--show" => parsed.show = v.parse().map_err(|e| format!("--show takes a number: {e}"))?,
            "--extra" => {
                let (p, d) = v.split_once('=').ok_or("--extra takes <prefix>=<dir>")?;
                parsed.extra.push((p.to_string(), PathBuf::from(d)));
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    if parsed.out.as_os_str().is_empty() {
        return Err("--out is required".into());
    }
    Ok(parsed)
}

fn repo_root() -> Result<PathBuf, String> {
    let out = Command::new("git").args(["rev-parse", "--show-toplevel"]).output().map_err(|e| format!("git rev-parse: {e}"))?;
    if !out.status.success() {
        return Err("demesne-parity runs inside the demesne checkout".into());
    }
    let top = String::from_utf8(out.stdout).map_err(|e| format!("git rev-parse: {e}"))?;
    Ok(PathBuf::from(top.trim()))
}

fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("{}: {e}", path.display()))
}

fn dump_rust_lib(entries: &[corpus::Entry], out: &Path) -> Result<(), String> {
    runner::parallel(entries, |e| {
        let dir = out.join(&e.id);
        fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        let src = fs::read(&e.path).map_err(|err| format!("{}: {err}", e.path.display()))?;
        let spec = match demesne_syntax::parse_bytes(&src) {
            Ok(s) => s,
            Err(err) => return write(&dir.join("ast.json"), format!("parse error: {err}\n")),
        };
        write(&dir.join("ast.json"), demesne_gocompat::json::marshal(&goast::spec(&spec)) + "\n")?;
        if demesne_emit_sql::validate(&spec).is_err() {
            return Ok(());
        }
        let oracle = match oracle::build_oracle_entry(&spec) {
            Ok(v) => demesne_gocompat::json::marshal_indent(&v, "", "  ") + "\n",
            Err(e) => format!("error: {e}\n"),
        };
        write(&dir.join("oracle.json"), oracle)?;
        write(&dir.join("api.txt"), api::api_dump(&spec))
    })
}

fn run(a: &Args) -> Result<bool, String> {
    let root = repo_root()?;
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
    runner::write_list(&entries, &list)?;

    let status = Command::new(root.join("scripts/parity/go-dump.sh"))
        .arg(&a.go_tag)
        .arg(&list)
        .arg(&go)
        .env("DEMESNE_PARITY_ORACLE_SPECS", a.out.join("oracle-specs"))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("the Go dump failed".into());
    }
    dump_rust_lib(&entries, &rust)?;
    if let Some(cli) = &a.go_cli {
        runner::dump_cli(cli, &entries, &go)?;
    }
    if let Some(cli) = &a.rust_cli {
        runner::dump_cli(cli, &entries, &rust)?;
    }

    let nondeterministic = match &a.go_cli {
        Some(gocli) => {
            let by_id: std::collections::HashMap<&str, &corpus::Entry> = entries.iter().map(|e| (e.id.as_str(), e)).collect();
            sum_retry(gocli, &by_id, &go, &rust)?
        }
        None => 0,
    };
    let only = a.only.clone();
    let filter = move |k: &str| only.as_deref().is_none_or(|o| k.contains(o));
    let sum = runner::compare(&go, &rust, Some(&filter))?;
    let mut report = String::new();
    if nondeterministic > 0 {
        writeln!(report, "go-nondeterministic outputs reconciled by rerun: {nondeterministic}").expect("fmt::Write for String never fails");
    }
    writeln!(
        report,
        "specs {}  outputs {}  zero-diff {}  differ {}  missing-in-rust {}",
        entries.len(),
        sum.outputs,
        sum.identical,
        sum.mismatches.len(),
        sum.missing_rust
    )
    .expect("fmt::Write for String never fails");
    for (kind, (n, ok)) in &sum.by_output {
        writeln!(report, "  {kind:<28} {ok:>6}/{n}").expect("fmt::Write for String never fails");
    }
    fs::write(a.out.join("report.txt"), {
        let mut full = report.clone();
        for m in &sum.mismatches {
            write!(full, "\nDIFF {}\n  {}\n", m.key, m.detail).expect("fmt::Write for String never fails");
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

fn sum_retry(gocli: &Path, by_id: &std::collections::HashMap<&str, &corpus::Entry>, go: &Path, rust: &Path) -> Result<usize, String> {
    let mut count = 0;
    let pre = runner::compare(go, rust, None)?;
    for m in pre.mismatches {
        let Some((id, file)) = m.key.rsplit_once('/') else { continue };
        let Some(name) = file.strip_prefix("cli-").and_then(|f| f.strip_suffix(".txt")) else { continue };
        let (Some(entry), Some(out)) = (by_id.get(id), runner::CLI_OUTPUTS.iter().find(|c| c.name == name)) else { continue };
        let want_path = rust.join(&m.key);
        let want = fs::read(&want_path).map_err(|e| format!("{}: {e}", want_path.display()))?;
        for _ in 0..10 {
            let again = runner::run_cli(gocli, &entry.path, out.args);
            if again == want {
                write(&go.join(&m.key), &again)?;
                count += 1;
                break;
            }
        }
    }
    Ok(count)
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
            "--seed" => seed = v.parse().map_err(|e| format!("--seed takes a number: {e}"))?,
            "--count" => count = v.parse().map_err(|e| format!("--count takes a number: {e}"))?,
            "--mutate" => mutate = v.parse().map_err(|e| format!("--mutate takes a number: {e}"))?,
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
    let base = corpus::collect(&repo_root()?);
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
        Some("corpus") => match repo_root() {
            Ok(root) => {
                for e in corpus::collect(&root) {
                    println!("{}\t{}", e.id, e.path.display());
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("demesne-parity: {e}");
                ExitCode::from(2)
            }
        },
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
                    let quoted: Vec<String> = c.args.iter().map(|a| format!("{a:?}")).collect();
                    format!("{{\"name\":{:?},\"args\":[{}]}}", c.name, quoted.join(","))
                })
                .collect();
            println!("[{}]", rows.join(","));
            ExitCode::SUCCESS
        }
        Some("dsn-one") => {
            print!("{}", demesne_postgres::parse_config_dump(argv.get(1).map_or("", String::as_str)));
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
        Some("run") => match parse_args(&argv[1..]).and_then(|a| run(&a)) {
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
