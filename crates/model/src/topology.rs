use demesne_gocompat::quote;
use demesne_syntax::{Level, Spec};
use std::collections::HashMap;

#[must_use]
pub fn level_by_name<'a>(s: &'a Spec, name: &str) -> Option<&'a Level> {
    s.levels().iter().find(|l| l.name == name)
}

/// Returns every level in topological order, root first.
///
/// # Errors
///
/// No levels, a parent that is not a level, zero or several roots, or a level unreachable from the root.
pub fn chain(s: &Spec) -> Result<Vec<&Level>, String> {
    let levels = s.levels();
    if levels.is_empty() {
        return Err("topology: no levels declared".into());
    }
    let mut roots = 0;
    let mut indeg: HashMap<&str, usize> = HashMap::new();
    let mut children: HashMap<&str, Vec<&Level>> = HashMap::new();
    for l in levels {
        if l.is_root() {
            roots += 1;
            continue;
        }
        for par in &l.parents {
            if level_by_name(s, par).is_none() {
                return Err(format!("line {}: level {} has unknown parent {}", l.pos.line, quote(&l.name), quote(par)));
            }
            *indeg.entry(&l.name).or_default() += 1;
            children.entry(par).or_default().push(l);
        }
    }
    if roots != 1 {
        return Err(format!("topology: want exactly one root level (no parent), found {roots}"));
    }
    let mut order = Vec::new();
    let mut queue: std::collections::VecDeque<&Level> = levels.iter().filter(|l| indeg.get(l.name.as_str()).copied().unwrap_or(0) == 0).collect();
    let mut done: HashMap<&str, usize> = HashMap::new();
    while let Some(cur) = queue.pop_front() {
        order.push(cur);
        for ch in children.get(cur.name.as_str()).into_iter().flatten() {
            let d = done.entry(&ch.name).or_default();
            *d += 1;
            if *d == indeg.get(ch.name.as_str()).copied().unwrap_or(0) {
                queue.push_back(ch);
            }
        }
    }
    if order.len() != levels.len() {
        return Err(format!("topology: {} level(s) not reachable from the root (cycle or disconnected)", levels.len() - order.len()));
    }
    Ok(order)
}

/// Returns every path from the root down to level `name`, each ending at `name`.
///
/// # Errors
///
/// `name`, or a level on a path to it, is not a level.
pub fn ancestor_paths<'a>(s: &'a Spec, name: &str) -> Result<Vec<Vec<&'a Level>>, String> {
    let Some(l) = level_by_name(s, name) else {
        return Err(format!("unknown level {}", quote(name)));
    };
    if l.is_root() {
        return Ok(vec![vec![l]]);
    }
    let mut paths = Vec::new();
    for par in &l.parents {
        for mut p in ancestor_paths(s, par)? {
            p.push(l);
            paths.push(p);
        }
    }
    Ok(paths)
}

/// Returns the one path from the root down to level `name`.
///
/// # Errors
///
/// `name` is not a level, or it has more than one ancestor path.
pub fn ancestor_path<'a>(s: &'a Spec, name: &str) -> Result<Vec<&'a Level>, String> {
    match <[Vec<&Level>; 1]>::try_from(ancestor_paths(s, name)?) {
        Ok([path]) => Ok(path),
        Err(paths) => Err(format!("level {} has {} ancestor paths (multi-parent) — only single-path levels can be pinned here", quote(name), paths.len())),
    }
}

/// Returns every level below `name`, in topological order.
///
/// # Errors
///
/// Any error from [`chain`] or [`ancestor_paths`].
pub fn descendants<'a>(s: &'a Spec, name: &str) -> Result<Vec<&'a Level>, String> {
    let order = chain(s)?;
    let mut out = Vec::new();
    for l in order {
        if l.name == name {
            continue;
        }
        for p in ancestor_paths(s, &l.name)? {
            if p.iter().any(|x| x.name == name) {
                out.push(l);
                break;
            }
        }
    }
    Ok(out)
}

pub(crate) fn non_virtual_chain(s: &Spec) -> Result<Vec<&Level>, String> {
    Ok(chain(s)?.into_iter().filter(|l| !l.is_virtual).collect())
}
