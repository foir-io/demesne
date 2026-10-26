use demesne_emit_sql::Sql;
use std::path::{Path, PathBuf};

fn specs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            specs(&path, out);
        } else if path.extension().is_some_and(|x| x == "demesne") {
            out.push(path);
        }
    }
}

#[test]
fn every_edit_check_inlines_each_update_policy_of_its_table() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    let mut checked = 0;
    for path in &paths {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        let sql = Sql::new(&s);
        let (Ok(rls), Ok(surface)) = (sql.emit_rls(), sql.emit_app_surface()) else { continue };
        for o in surface.objects.iter() {
            let updates: Vec<_> = rls.policies.iter().filter(|p| p.table == o.table.as_ref() && p.cmd == "UPDATE").collect();
            assert_eq!(
                o.edit_check_sql.is_empty(),
                updates.is_empty(),
                "{} {}: edit check {:?}, update policies {updates:#?}",
                path.display(),
                o.object,
                o.edit_check_sql
            );
            for p in updates {
                assert!(
                    o.edit_check_sql.contains(&p.using),
                    "{} {}: the edit check doesn't inline {}:\n{}\n{}",
                    path.display(),
                    o.object,
                    p.name,
                    o.edit_check_sql,
                    p.using
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "only {checked} update policies were checked");
}
