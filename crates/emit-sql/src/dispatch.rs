use std::fmt::Write as _;

use demesne_runtime::quote_literal;
use demesne_syntax::{Builtin, PermNode, Term, TermKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Family {
    pub(crate) col: String,
    pub(crate) prefix: Option<String>,
}

pub(crate) const MAX_FAMILIES: usize = 8;

fn family_of(t: &Term) -> Option<Family> {
    match &t.kind {
        TermKind::Builtin(Builtin::Some(scope)) => Some(Family { col: scope.col.clone(), prefix: scope.prefix.clone() }),
        _ => None,
    }
}

pub(crate) fn families(node: &PermNode) -> Vec<Family> {
    let mut out = Vec::new();
    collect(node, &mut out);
    out
}

fn collect(node: &PermNode, out: &mut Vec<Family>) {
    match node {
        PermNode::Leaf(t) => {
            if let Some(f) = family_of(t).filter(|f| !out.contains(f)) {
                out.push(f);
            }
        }
        PermNode::Or(nodes) | PermNode::And(nodes) => nodes.iter().for_each(|n| collect(n, out)),
        PermNode::Not(n) => collect(n, out),
    }
}

pub(crate) fn pruned(node: &PermNode, keep: Option<&Family>) -> Option<PermNode> {
    match node {
        PermNode::Leaf(t) => match family_of(t) {
            Some(f) if Some(&f) != keep => None,
            _ => Some(node.clone()),
        },
        PermNode::Or(nodes) => {
            let kept: Vec<PermNode> = nodes.iter().filter_map(|n| pruned(n, keep)).collect();
            (!kept.is_empty()).then_some(PermNode::Or(kept))
        }
        PermNode::And(nodes) => nodes.iter().map(|n| pruned(n, keep)).collect::<Option<Vec<_>>>().map(PermNode::And),
        PermNode::Not(_) => Some(node.clone()),
    }
}

fn present(table: &str, f: &Family) -> String {
    let filter = f.prefix.as_ref().map(|p| format!(" WHERE starts_with(demesne_element.v, {})", quote_literal(p))).unwrap_or_default();
    format!("EXISTS (SELECT 1 FROM unnest({table}.{}) AS demesne_element(v){filter})", f.col)
}

pub(crate) struct Queries {
    pub(crate) single: Vec<String>,
    pub(crate) none: String,
    pub(crate) full: String,
}

pub(crate) fn body(table: &str, key: &str, families: &[Family], q: &Queries) -> String {
    const NEVER_FAILS: &str = "fmt::Write for String never fails";
    let vars: Vec<String> = (1..=families.len()).map(|i| format!("demesne_has_{i}")).collect();
    let checks: Vec<String> = families.iter().map(|f| present(table, f)).collect();
    let only = |i: usize| vars.iter().enumerate().map(|(j, v)| if i == j { v.clone() } else { format!("NOT {v}") }).collect::<Vec<_>>().join(" AND ");
    let nothing = vars.iter().map(|v| format!("NOT {v}")).collect::<Vec<_>>().join(" AND ");
    let mut b = String::from("DECLARE\n");
    for v in &vars {
        writeln!(b, "  {v} boolean;").expect(NEVER_FAILS);
    }
    writeln!(b, "BEGIN\n  SELECT {} INTO {} FROM {table} WHERE {key};", checks.join(", "), vars.join(", ")).expect(NEVER_FAILS);
    b.push_str("  IF NOT FOUND THEN\n    RETURN false;\n  END IF;\n");
    for (i, query) in q.single.iter().enumerate() {
        writeln!(b, "  IF {} THEN\n    RETURN {query};\n  END IF;", only(i)).expect(NEVER_FAILS);
    }
    write!(b, "  IF {nothing} THEN\n    RETURN {};\n  END IF;\n  RETURN {};\nEND", q.none, q.full).expect(NEVER_FAILS);
    b
}
