pub(crate) fn corpus() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut dirs = vec![
        std::path::PathBuf::from(format!("{}/../../testdata/corpus", env!("CARGO_MANIFEST_DIR"))),
        format!("{}/../../examples", env!("CARGO_MANIFEST_DIR")).into(),
    ];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).expect("the corpus reads") {
            let p = e.expect("an entry").path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "demesne") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}
