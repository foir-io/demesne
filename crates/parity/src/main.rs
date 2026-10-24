use demesne_parity::{api, corpus, goast, oracle, runner};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "demesne-parity: the differential runner against the frozen Go engine

USAGE:
  demesne-parity corpus
  demesne-parity run --go-tag <tag> --go-cli <path> [--rust-cli <path>] --out <dir> [--extra <prefix>=<dir>]... [--only <substr>] [--show <n>]
";

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

    let only = a.only.clone();
    let filter = move |k: &str| only.as_deref().is_none_or(|o| k.contains(o));
    let sum = runner::compare(&go, &rust, Some(&filter));
    let mut report = String::new();
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

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("corpus") => {
            for e in corpus::collect(&repo_root()) {
                println!("{}\t{}", e.id, e.path.display());
            }
            ExitCode::SUCCESS
        }
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
