use demesne_emit_rust::{Builder, Surface, emit_rust, item_path};
use demesne_syntax::Spec;
use std::path::{Path, PathBuf};

fn corpus(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["examples", "testdata/corpus/fixtures", "testdata/corpus/foir", "testdata/parity/oracle"] {
        let Ok(rd) = std::fs::read_dir(root.join(dir)) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "demesne") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn candidates(spec: &Spec) -> Vec<Surface> {
    let mut c = vec![Surface::Session, Surface::ClaimsContract, Surface::ClaimsContractEntries];
    for v in &spec.vocabs {
        c.push(Surface::Vocabulary(v.name.clone()));
    }
    c.push(Surface::HoldsResolver(String::new()));
    for rs in &spec.role_stores {
        c.push(Surface::HoldsResolver(rs.name.clone()));
        c.push(Surface::RoleAssignment(rs.name.clone()));
        c.push(Surface::ExpandedPresets(rs.name.clone()));
    }
    for g in &spec.grants {
        c.push(Surface::Grant(g.name.clone()));
    }
    for o in &spec.objects {
        c.push(Surface::ResourceAccess(o.name.clone()));
        c.push(Surface::ConditionalResourceAccess(o.name.clone()));
        c.push(Surface::PointCheck(o.name.clone()));
        c.push(Surface::AppSurface(o.name.clone()));
        for p in &o.perms {
            c.push(Surface::Check(o.name.clone(), p.verb.clone()));
        }
    }
    if let Ok(pdps) = demesne_model::pdp::emit_pdp(spec) {
        for site in pdps.keys() {
            c.push(Surface::Pdp(site.clone()));
        }
    }
    c
}

fn registry_item(spec: &Spec, m: &str, w: &Surface) -> String {
    let path = format!("{m}::{}", item_path(spec, w).expect("emit_rust accepted it"));
    match w {
        Surface::Vocabulary(n) => format!("Item::Vocabulary({n:?}, &{path})"),
        Surface::HoldsResolver(n) => format!("Item::HoldsResolver({n:?}, &{path})"),
        Surface::RoleAssignment(n) => format!("Item::RoleAssignment({n:?}, &{path})"),
        Surface::ExpandedPresets(n) => format!("Item::ExpandedPresets({n:?}, {path})"),
        Surface::Grant(n) => format!("Item::Grant({n:?}, &{path})"),
        Surface::ResourceAccess(n) => format!("Item::ResourceAccess({n:?}, &{path})"),
        Surface::ConditionalResourceAccess(n) => format!("Item::ConditionalResourceAccess({n:?}, &{path})"),
        Surface::PointCheck(n) => format!("Item::PointCheck({n:?}, {path})"),
        Surface::AppSurface(n) => format!("Item::AppSurface({n:?}, &{path})"),
        Surface::Check(o, v) => format!("Item::Check({o:?}, {v:?}, {path})"),
        Surface::Pdp(n) => format!("Item::Pdp({n:?}, &{path})"),
        Surface::Session => format!("Item::Session(&{path})"),
        Surface::ClaimsContract => format!("Item::ClaimsContract({path})"),
        Surface::ClaimsContractEntries => format!("Item::ClaimsContractEntries({path})"),
    }
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root");
    let mut mods = String::new();
    let mut entries = String::new();
    for (i, path) in corpus(&root).iter().enumerate() {
        let Ok(src) = std::fs::read(path) else { continue };
        let Ok(spec) = demesne_syntax::parse_bytes(&src) else { continue };
        if demesne_emit_sql::validate(&spec).is_err() {
            continue;
        }
        let chosen: Vec<Surface> = candidates(&spec).into_iter().filter(|w| emit_rust(&spec, std::slice::from_ref(w)).is_ok()).collect();
        let mut b = Builder::new(path).file_name(&format!("spec_{i}.rs"));
        for w in &chosen {
            b = b.surface(w.clone());
        }
        b.compile();
        let m = format!("spec_{i}");
        mods.push_str(&format!("#[allow(dead_code)]\nmod {m} {{\n    include!(concat!(env!(\"OUT_DIR\"), \"/{m}.rs\"));\n}}\n"));
        let items: Vec<String> = chosen.iter().map(|w| registry_item(&spec, &m, w)).collect();
        let rel = path.strip_prefix(&root).expect("under the repo root").display().to_string();
        entries.push_str(&format!("        Entry {{ path: {rel:?}, items: vec![{}] }},\n", items.join(", ")));
    }
    let index = format!("{mods}\npub fn registry() -> Vec<Entry> {{\n    vec![\n{entries}    ]\n}}\n");
    std::fs::write(PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("index.rs"), index).expect("write index.rs");
}
