use crate::schema::Schema;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, Default)]
pub struct ScaffoldOptions {
    pub min_container_refs: usize,
}

struct FkGraph {
    refs_to: BTreeMap<String, BTreeSet<String>>,
    col_into: BTreeMap<String, BTreeMap<String, usize>>,
    fk_out: BTreeMap<String, BTreeSet<String>>,
}

fn build_graph(sc: &Schema) -> FkGraph {
    let mut g = FkGraph { refs_to: BTreeMap::new(), col_into: BTreeMap::new(), fk_out: BTreeMap::new() };
    for fk in sc.foreign_keys() {
        if fk.table == fk.ref_table || !fk.column.ends_with("_id") || fk.ref_column != "id" {
            continue;
        }
        g.refs_to.entry(fk.ref_table.clone()).or_default().insert(fk.table.clone());
        *g.col_into.entry(fk.ref_table.clone()).or_default().entry(fk.column.clone()).or_default() += 1;
        g.fk_out.entry(fk.table.clone()).or_default().insert(fk.ref_table.clone());
    }
    g
}

fn compute_depth(
    c: &str,
    g: &FkGraph,
    is_level: &BTreeMap<String, String>,
    depth: &mut BTreeMap<String, usize>,
    parent: &mut BTreeMap<String, String>,
) -> usize {
    if let Some(d) = depth.get(c) {
        return *d;
    }
    depth.insert(c.to_string(), 0);
    let mut best = String::new();
    let mut best_d: Option<usize> = None;
    for r in g.fk_out.get(c).into_iter().flatten() {
        if !is_level.contains_key(r) || r == c {
            continue;
        }
        let d = compute_depth(r, g, is_level, depth, parent);
        if best_d.is_none_or(|b| d > b || (d == b && *r < best)) {
            best.clone_from(r);
            best_d = Some(d);
        }
    }
    let d = best_d.map_or(0, |b| b + 1);
    if !best.is_empty() {
        parent.insert(c.to_string(), best);
    }
    depth.insert(c.to_string(), d);
    d
}

fn scope_path(sc: &Schema, t: &str, kept: &[String], level_name: &BTreeMap<String, String>, parent: &BTreeMap<String, String>) -> Vec<String> {
    let has: BTreeSet<&str> = kept.iter().filter(|c| sc.has_column(t, &format!("{}_id", level_name[*c]))).map(|c| level_name[c].as_str()).collect();
    let mut path: Vec<String> = Vec::new();
    for c in kept {
        let ln = &level_name[c];
        if !has.contains(ln.as_str()) {
            continue;
        }
        let parent_ok = match parent.get(c) {
            None => true,
            Some(p) => path.last().is_some_and(|last| *last == level_name[p]),
        };
        if parent_ok {
            path.push(ln.clone());
        }
    }
    path
}

fn name_containers(g: &FkGraph, threshold: usize) -> BTreeMap<String, String> {
    let mut level_name = BTreeMap::new();
    for (c, refs) in &g.refs_to {
        if refs.len() < threshold {
            continue;
        }
        let mut best = String::new();
        let mut best_n: Option<usize> = None;
        for (col, &n) in &g.col_into[c] {
            if best_n.is_none_or(|b| n > b || (n == b && *col < best)) {
                best.clone_from(col);
                best_n = Some(n);
            }
        }
        let name = best.strip_suffix("_id").unwrap_or(&best).to_string();
        if !name.is_empty() {
            level_name.insert(c.clone(), name);
        }
    }
    level_name
}

fn scoped_object(t: &str, path: &[String]) -> String {
    let mut b = format!("object {t} {{\n  table  {t}\n  scoped {}\n", path.join(" > "));
    b.push_str("  permission view   = @scoped @rls maps select\n");
    b.push_str("  permission edit   = @scoped @rls maps update\n");
    b.push_str("  permission create = @scoped @rls maps insert\n");
    b.push_str("  permission delete = @scoped @rls maps delete\n");
    b.push_str("}\n\n");
    b
}

/// Drafts a `.demesne` spec from a database schema's foreign keys.
///
/// # Errors
///
/// No table is referenced by enough others to be a tenancy container.
pub fn scaffold(sc: &Schema, opts: ScaffoldOptions) -> Result<String, String> {
    let threshold = if opts.min_container_refs == 0 { 3 } else { opts.min_container_refs };
    let g = build_graph(sc);
    let level_name = name_containers(&g, threshold);
    if level_name.is_empty() {
        return Err(format!(
            "scaffold: no tenancy container found (no table referenced by >= {threshold} others via FK) — supply foreign keys, or lower MinContainerRefs"
        ));
    }
    let mut depth = BTreeMap::new();
    let mut parent = BTreeMap::new();
    for c in level_name.keys() {
        compute_depth(c, &g, &level_name, &mut depth, &mut parent);
    }
    let mut roots: Vec<String> = level_name.keys().filter(|c| !parent.contains_key(*c)).cloned().collect();
    let refs_len = |c: &String| g.refs_to.get(c).map_or(0, BTreeSet::len);
    roots.sort_by(|a, b| refs_len(b).cmp(&refs_len(a)).then_with(|| a.cmp(b)));
    let chosen = roots[0].clone();
    let mut in_tree: BTreeSet<String> = BTreeSet::new();
    let mut dropped: Vec<String> = Vec::new();
    for c in level_name.keys() {
        let mut r = c.clone();
        while let Some(p) = parent.get(&r) {
            r = p.clone();
        }
        if r == chosen {
            in_tree.insert(c.clone());
        } else {
            dropped.push(level_name[c].clone());
        }
    }
    let mut kept: Vec<String> = in_tree.iter().cloned().collect();
    kept.sort_by(|a, b| (depth[a], &level_name[a], a).cmp(&(depth[b], &level_name[b], b)));

    let tables = sc.tables();
    let mut b = format!("// Demesne starter spec — GENERATED by Scaffold from {} tables, {} foreign keys.\n", tables.len(), sc.foreign_keys().len());
    b.push_str("// THIS IS A DRAFT. Every line is a heuristic guess from the FK graph — review it.\n");
    b.push_str("// Enforcement here is CONTAINMENT-ONLY (@scoped): a row is visible iff its scope\n");
    b.push_str("// columns match the session. Add owner axes, roles, descriptors, and subjects to\n");
    b.push_str("// express real policy. A 'level' below may actually be an owner PRINCIPAL (e.g. a\n");
    b.push_str("// customers table) — if so, make it an owner relation, not a topology level.\n\n");
    b.push_str("topology {\n");
    for c in &kept {
        match parent.get(c).filter(|p| in_tree.contains(*p)) {
            Some(p) => writeln!(b, "  level {} parent {}", level_name[c], level_name[p]).expect("fmt::Write for String never fails"),
            None => writeln!(b, "  level {}", level_name[c]).expect("fmt::Write for String never fails"),
        }
    }
    b.push_str("}\n");
    if !dropped.is_empty() {
        dropped.sort();
        writeln!(b, "// Other container(s) not in the chosen tree (would fork the root): {}", dropped.join(", ")).expect("fmt::Write for String never fails");
    }
    b.push('\n');
    let mut unscoped: Vec<String> = Vec::new();
    for t in tables.iter().filter(|t| !level_name.contains_key(*t)) {
        let path = scope_path(sc, t, &kept, &level_name, &parent);
        if path.is_empty() {
            unscoped.push(t.clone());
        } else {
            b.push_str(&scoped_object(t, &path));
        }
    }
    if !unscoped.is_empty() {
        let suffix = if unscoped.len() > 20 { format!(", … (+{} more)", unscoped.len() - 20) } else { String::new() };
        let shown: Vec<&str> = unscoped.iter().take(20).map(String::as_str).collect();
        writeln!(b, "// Not scaffolded (no tenancy scope columns found): {}{}", shown.join(", "), suffix).expect("fmt::Write for String never fails");
    }
    Ok(b)
}
