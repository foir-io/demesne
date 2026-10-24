use demesne_gocompat::quote;
use demesne_syntax::{Level, Spec};
use std::collections::HashMap;

pub fn level_by_name<'a>(s: &'a Spec, name: &str) -> Option<&'a Level> {
    s.levels().iter().find(|l| l.name == name)
}

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
    let mut queue: std::collections::VecDeque<&Level> =
        levels.iter().filter(|l| indeg.get(l.name.as_str()).copied().unwrap_or(0) == 0).collect();
    let mut done: HashMap<&str, usize> = HashMap::new();
    while let Some(cur) = queue.pop_front() {
        order.push(cur);
        if let Some(kids) = children.get(cur.name.as_str()) {
            for ch in kids {
                let d = done.entry(&ch.name).or_default();
                *d += 1;
                if *d == indeg.get(ch.name.as_str()).copied().unwrap_or(0) {
                    queue.push_back(ch);
                }
            }
        }
    }
    if order.len() != levels.len() {
        return Err(format!(
            "topology: {} level(s) not reachable from the root (cycle or disconnected)",
            levels.len() - order.len()
        ));
    }
    Ok(order)
}

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

pub fn ancestor_path<'a>(s: &'a Spec, name: &str) -> Result<Vec<&'a Level>, String> {
    let mut paths = ancestor_paths(s, name)?;
    if paths.len() != 1 {
        return Err(format!(
            "level {} has {} ancestor paths (multi-parent) — only single-path levels can be pinned here",
            quote(name),
            paths.len()
        ));
    }
    Ok(paths.pop().unwrap())
}

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

pub fn non_virtual_chain(s: &Spec) -> Result<Vec<&Level>, String> {
    Ok(chain(s)?.into_iter().filter(|l| !l.is_virtual).collect())
}
