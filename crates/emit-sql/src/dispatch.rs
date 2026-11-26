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

fn bits(families: &[Family], col: &str) -> String {
    families
        .iter()
        .enumerate()
        .filter(|(_, f)| f.col == col)
        .map(|(i, f)| {
            let bit = 1u32 << i;
            f.prefix
                .as_ref()
                .map_or_else(|| bit.to_string(), |p| format!("CASE WHEN starts_with(demesne_element.v, {}) THEN {bit} ELSE 0 END", quote_literal(p)))
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn presence(table: &str, key: &str, families: &[Family]) -> String {
    let mut columns: Vec<&str> = Vec::new();
    for f in families {
        if !columns.contains(&f.col.as_str()) {
            columns.push(&f.col);
        }
    }
    if let [col] = columns.as_slice() {
        return format!(
            "SELECT coalesce(bit_or({}), 0) INTO demesne_present FROM {table}, unnest({table}.{col}) AS demesne_element(v) WHERE {key};",
            bits(families, col)
        );
    }
    let masks: Vec<String> =
        columns.iter().map(|col| format!("coalesce((SELECT bit_or({}) FROM unnest({table}.{col}) AS demesne_element(v)), 0)", bits(families, col))).collect();
    format!("SELECT {} INTO demesne_present FROM {table} WHERE {key};", masks.join(" | "))
}

pub(crate) struct Queries {
    pub(crate) single: Vec<String>,
    pub(crate) none: String,
    pub(crate) full: String,
}

pub(crate) fn body(table: &str, key: &str, families: &[Family], q: &Queries) -> String {
    const NEVER_FAILS: &str = "fmt::Write for String never fails";
    let mut b = String::from("DECLARE\n  demesne_present integer;\nBEGIN\n");
    writeln!(b, "  {}", presence(table, key, families)).expect(NEVER_FAILS);
    b.push_str("  CASE demesne_present\n");
    for (i, query) in q.single.iter().enumerate() {
        writeln!(b, "    WHEN {} THEN\n      RETURN {query};", 1u32 << i).expect(NEVER_FAILS);
    }
    write!(b, "    WHEN 0 THEN\n      RETURN {};\n    ELSE\n      RETURN {};\n  END CASE;\nEND", q.none, q.full).expect(NEVER_FAILS);
    b
}
