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

#[test]
fn every_listing_has_an_admits_that_runs_each_select_policy_of_its_table() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    let (mut listings, mut checked) = (0, 0);
    for path in &paths {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let Ok(s) = demesne_syntax::parse(&src) else { continue };
        if demesne_emit_sql::validate(&s).is_err() {
            continue;
        }
        let sql = Sql::new(&s);
        let (Ok(rls), Ok(defs)) = (sql.emit_rls(), sql.emit_definers()) else { continue };
        for o in &s.objects {
            let listed = defs.iter().any(|f| f.name == format!("{}_accessors", o.table) || f.name == format!("{}_accessors_conditional", o.table));
            let selects: Vec<_> = rls.policies.iter().filter(|p| p.table == o.table && p.cmd == "SELECT").collect();
            if !listed || selects.is_empty() {
                continue;
            }
            listings += 1;
            let admits = defs
                .iter()
                .find(|f| f.name == format!("{}_admits", o.table))
                .unwrap_or_else(|| panic!("{} {}: a listing and no admits", path.display(), o.name));
            for p in selects {
                let using = by_definer(&p.using, &s, &admits.body);
                assert!(admits.body.contains(&using), "{} {}: admits doesn't run {}:\n{}\n{using}", path.display(), o.name, p.name, admits.body);
                checked += 1;
            }
            assert!(
                admits.create_sql().ends_with(" FROM PUBLIC, authenticated;"),
                "{} {}: admits is executable by PUBLIC:\n{}",
                path.display(),
                o.name,
                admits.create_sql()
            );
        }
    }
    assert!(listings > 100 && checked > listings, "only {listings} listings and {checked} select policies were checked");
}

fn by_definer(sql: &str, s: &demesne_syntax::Spec, known: &str) -> String {
    const OPEN: &str = "EXISTS (SELECT 1 FROM ";
    let mut out = String::new();
    let mut rest = sql;
    while let Some(at) = rest.find(OPEN) {
        let after = &rest[at + OPEN.len()..];
        let parsed = after.split_once(' ').and_then(|(table, tail)| {
            let tail = tail.strip_prefix("AS demesne_borrowed WHERE demesne_borrowed.")?;
            let (_, tail) = tail.split_once(" = ")?;
            let (column, tail) = tail.split_once(')')?;
            Some((table.rsplit('.').next()?, column.rsplit('.').next()?, tail))
        });
        let Some((table, col, tail)) = parsed else {
            out.push_str(&rest[..at + OPEN.len()]);
            rest = after;
            continue;
        };
        let schema = s.definer_schema();
        let call = s
            .objects
            .iter()
            .filter(|o| o.table == table)
            .flat_map(|o| o.perms.iter().filter(|pm| pm.maps() == "select").map(move |pm| (o, pm)))
            .flat_map(|(o, pm)| [format!("{schema}.{}_can_{}({col})", o.name, pm.verb), format!("{schema}.{}_can_{}_for_select({col})", o.name, pm.verb)])
            .find(|call| known.contains(call.as_str()))
            .unwrap_or_else(|| panic!("no definer call stands for the borrow of {table} by {col}"));
        out.push_str(&rest[..at]);
        out.push_str(&call);
        rest = tail;
    }
    out.push_str(rest);
    out
}
