use std::path::Path;

#[test]
fn rust_regenerates_the_committed_oracle_byte_for_byte() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let got = demesne_parity::oracle_manifest(&root.join("testdata/parity/oracle")).unwrap();
    let path = root.join("ts/packages/runtime/test/generated/oracle.json");
    if std::env::var_os("UPDATE_ORACLE").is_some() {
        std::fs::write(&path, &got).expect("the oracle writes");
    }
    let want = std::fs::read_to_string(&path).unwrap();
    assert!(got.len() > 10_000, "the regenerated manifest is implausibly small ({} bytes)", got.len());
    assert!(got == want, "oracle.json differs: regenerated {} bytes, committed {} bytes", got.len(), want.len());
}
