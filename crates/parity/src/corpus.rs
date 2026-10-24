use std::fs;
use std::path::{Path, PathBuf};

pub struct Entry {
    pub id: String,
    pub path: PathBuf,
}

fn specs_in(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    out.retain(|p| p.extension().is_some_and(|e| e == "demesne"));
    out.sort();
    out
}

fn stem(p: &Path) -> String {
    p.file_stem().unwrap().to_string_lossy().into_owned()
}

pub fn collect(root: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    for p in specs_in(&root.join("examples")) {
        out.push(Entry { id: format!("examples/{}", stem(&p)), path: p });
    }
    for p in specs_in(&root.join("examples/canonical")) {
        out.push(Entry { id: format!("examples/canonical/{}", stem(&p)), path: p });
    }
    for p in specs_in(&root.join("testdata/corpus/foir")) {
        out.push(Entry { id: format!("foir/{}", stem(&p)), path: p });
    }
    for p in specs_in(&root.join("testdata/corpus/fixtures")) {
        out.push(Entry { id: format!("fixtures/{}", stem(&p)), path: p });
    }
    out
}

pub fn add_dir(out: &mut Vec<Entry>, prefix: &str, dir: &Path) {
    for p in specs_in(dir) {
        out.push(Entry { id: format!("{prefix}/{}", stem(&p)), path: p });
    }
}
