use demesne_cli::{Files, go_read_error, run_pure};
use demesne_parity::corpus::{self, Entry};
use demesne_parity::runner::CLI_OUTPUTS;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const LATER_OUTPUTS: &[(&str, &[&str])] = &[("emit-manifest", &["emit", "{spec}", "manifest"])];

struct Repo(PathBuf);

impl Files for Repo {
    fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.0.join(path)).map_err(|e| go_read_error(path, &e))
    }
}

fn repo() -> Repo {
    Repo(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn outputs() -> impl Iterator<Item = (&'static str, &'static [&'static str])> {
    CLI_OUTPUTS.iter().map(|c| (c.name, c.args)).chain(LATER_OUTPUTS.iter().copied())
}

fn relative(repo: &Repo, e: &Entry) -> String {
    e.path.strip_prefix(&repo.0).expect("corpus entries sit under the repository root").to_string_lossy().replace('\\', "/")
}

fn record(repo: &Repo, spec: &str, args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|a| if *a == "{spec}" { spec.to_string() } else { (*a).to_string() }).collect();
    let out = run_pure(&args, repo).expect("validate and emit run without a database");
    let text = |b: Vec<u8>| String::from_utf8(b).expect("the CLI writes UTF-8");
    format!("exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}\n--- end ---\n", out.code, text(out.stdout), text(out.stderr))
}

#[test]
fn every_example_output_matches_its_snapshot() {
    let repo = repo();
    let examples: Vec<Entry> = corpus::collect(&repo.0).into_iter().filter(|e| e.id.starts_with("examples/")).collect();
    for e in &examples {
        let spec = relative(&repo, e);
        for (name, args) in outputs() {
            insta::assert_snapshot!(format!("{}__{name}", e.id.replace('/', "__")), record(&repo, &spec, args));
        }
    }
}

#[test]
fn every_corpus_output_matches_the_checksum_manifest() {
    let repo = repo();
    let mut entries: Vec<Entry> = corpus::collect(&repo.0).into_iter().filter(|e| !e.id.starts_with("examples/")).collect();
    corpus::add_dir(&mut entries, "gaps", &repo.0.join("testdata/gaps"));
    corpus::add_dir(&mut entries, "oracle", &repo.0.join("testdata/parity/oracle"));
    let mut manifest = String::new();
    for e in &entries {
        let spec = relative(&repo, e);
        for (name, args) in outputs() {
            let digest = Sha256::digest(record(&repo, &spec, args));
            let hex: String = digest.iter().fold(String::new(), |mut s, b| {
                write!(s, "{b:02x}").expect("fmt::Write for String never fails");
                s
            });
            writeln!(manifest, "{hex}  {}/{name}", e.id).expect("fmt::Write for String never fails");
        }
    }
    insta::assert_snapshot!("corpus_checksums", manifest);
}
