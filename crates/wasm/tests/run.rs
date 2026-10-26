use demesne_wasm::run_native;
use std::collections::BTreeMap;

fn files(path: &str) -> BTreeMap<String, Vec<u8>> {
    let src = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/example.demesne")).expect("example spec");
    BTreeMap::from([(path.to_string(), src)])
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(ToString::to_string).collect()
}

#[test]
fn run_matches_the_native_cli_on_a_pure_command() {
    let o = run_native(&args(&["validate", "spec.demesne"]), files("spec.demesne"));
    assert_eq!(
        (o.code, String::from_utf8_lossy(&o.stdout).as_ref(), o.stderr.as_slice()),
        (0, "ok: 2 objects, 3 levels, 6 policies, 1 reachability grants\n", &b""[..])
    );
}

#[test]
fn a_missing_file_reads_as_go_reports_it() {
    let o = run_native(&args(&["emit", "nope.demesne"]), BTreeMap::new());
    assert_eq!((o.code, String::from_utf8_lossy(&o.stderr).as_ref()), (1, "demesne: open nope.demesne: no such file or directory\n"));
}

#[test]
fn a_live_command_says_it_needs_the_native_cli() {
    for cmd in demesne_cli::LIVE_COMMANDS {
        let o = run_native(&args(&[cmd, "postgres://x"]), BTreeMap::new());
        assert_eq!(o.code, 1);
        assert!(String::from_utf8_lossy(&o.stderr).contains("needs a database connection"), "{cmd}");
    }
}
