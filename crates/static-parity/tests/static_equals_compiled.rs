use demesne_emit_sql::Sql;
use demesne_model::{SpecExt, SurfaceExt};
use demesne_runtime as rt;
use demesne_static_parity::{Item, registry};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn validating_specs() -> usize {
    let mut n = 0;
    for dir in ["examples", "testdata/corpus/fixtures", "testdata/corpus/foir", "testdata/parity/oracle"] {
        for e in std::fs::read_dir(root().join(dir)).expect("corpus dir").flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "demesne") {
                continue;
            }
            let src = std::fs::read(&p).expect("read spec");
            if let Ok(s) = demesne_syntax::parse_bytes(&src)
                && demesne_emit_sql::validate(&s).is_ok()
            {
                n += 1;
            }
        }
    }
    n
}

fn presets_of(p: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    p.iter().map(|(k, v)| (k.to_string(), v.iter().map(|x| x.to_string()).collect())).collect()
}

#[test]
fn every_emitted_table_equals_the_compiled_surface() {
    let reg = registry();
    assert_eq!(reg.len(), validating_specs(), "build.rs compiled a different number of specs than validate");
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for e in &reg {
        let src = std::fs::read(root().join(e.path)).expect("read spec");
        let s = demesne_syntax::parse_bytes(&src).expect("parse");
        let app = Sql::new(&s).emit_app_surface().ok();
        let pdps = demesne_model::pdp::emit_pdp(&s).ok();
        for item in &e.items {
            let (kind, same) = match *item {
                Item::Vocabulary(n, v) => ("vocabulary", *v == demesne_model::vocab::to_runtime(s.vocabs.iter().find(|x| x.name == n).expect("vocab"))),
                Item::HoldsResolver(n, h) => ("holds_resolver", Ok(h.clone()) == s.holds_resolver(n)),
                Item::RoleAssignment(n, r) => ("role_assignment", Ok(r.clone()) == s.role_assignment_surface(n)),
                Item::ExpandedPresets(n, p) => ("expanded_presets", Ok(presets_of(p)) == s.expanded_presets(n)),
                Item::Grant(n, g) => ("grant", Ok(g.clone()) == s.grant_surface(n)),
                Item::ResourceAccess(n, r) => ("resource_access", Ok(r.clone()) == s.resource_access_surface(n)),
                Item::ConditionalResourceAccess(n, r) => ("conditional_resource_access", Ok(r.clone()) == s.conditional_resource_access_surface(n)),
                Item::PointCheck(n, sql) => ("point_check", Ok(sql.to_string()) == s.point_check_sql(n)),
                Item::AppSurface(n, a) => ("app_surface", app.as_ref().and_then(|x| x.object(n)) == Some(a)),
                Item::Check(o, v, sql) => (
                    "check",
                    app.as_ref().and_then(|x| x.object(o)).and_then(|a| a.checks.iter().find(|c| c.verb == v)).map(|c| c.check_sql.as_ref()) == Some(sql),
                ),
                Item::Pdp(n, p) => ("pdp", pdps.as_ref().and_then(|m| m.get(n)) == Some(p)),
                Item::Session(x) => ("session", *x == s.session()),
                Item::ClaimsContract(keys) => ("claims_contract", Ok(keys.iter().map(|k| k.to_string()).collect()) == s.claims_contract()),
                Item::ClaimsContractEntries(entries) => ("claims_contract_entries", Ok(entries.to_vec()) == s.claims_contract_entries()),
            };
            *by_kind.entry(kind).or_default() += 1;
            if !same {
                failures.push(format!("{}: {item:?}", e.path));
            }
        }
    }
    let total: usize = by_kind.values().sum();
    eprintln!("specs {}  tables {total}  {by_kind:?}", reg.len());
    assert!(failures.is_empty(), "{} of {total} tables differ:\n{}", failures.len(), failures.join("\n"));
    for kind in [
        "vocabulary",
        "holds_resolver",
        "role_assignment",
        "expanded_presets",
        "grant",
        "resource_access",
        "conditional_resource_access",
        "point_check",
        "app_surface",
        "check",
        "pdp",
        "session",
        "claims_contract",
        "claims_contract_entries",
    ] {
        assert!(by_kind.get(kind).copied().unwrap_or(0) > 0, "no {kind} table was compared");
    }
    let _: Option<&rt::Session> = None;
}
