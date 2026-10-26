use crate::ConditionalAdmission;
use crate::analysis::Rels;
use demesne_syntax::{PermNode, Repr};

pub fn accessor_tree_op(n: &PermNode) -> &'static str {
    match n {
        PermNode::Not(_) => "and not",
        PermNode::And(_) => "and",
        PermNode::Leaf(_) => "",
        PermNode::Or(kids) => kids.iter().map(accessor_tree_op).find(|op| !op.is_empty()).unwrap_or(""),
    }
}

#[must_use]
pub fn is_row_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if t.builtin() == "row")
}

#[must_use]
pub fn is_claim_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if t.builtin() == "claim")
}

#[must_use]
pub fn claim_neutral_accessor_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if matches!(t.builtin(), "kind" | "app_scope" | "session" | "within" | "scoped" | "holds" | "claim" | "row"))
}

#[must_use]
pub fn narrowing_accessor_leaf(n: &PermNode) -> bool {
    claim_neutral_accessor_leaf(n) || matches!(n, PermNode::Leaf(t) if t.mode_col().is_some())
}

#[must_use]
pub fn not_kid(n: &PermNode) -> Option<&PermNode> {
    match n {
        PermNode::Not(k) => Some(k),
        _ => None,
    }
}

#[must_use]
pub fn is_composition_leaf(n: &PermNode, rels: &Rels) -> bool {
    match n {
        PermNode::Leaf(t) => rels.get(t.ident()).is_some_and(|r| matches!(r.repr, Repr::Composition(_))),
        _ => false,
    }
}

#[must_use]
pub fn admission_names(adms: &[ConditionalAdmission]) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for a in adms {
        let mut n = a.source.clone();
        let keys: Vec<&str> = a.claims.iter().map(|c| c.key.as_str()).filter(|k| !k.is_empty()).collect();
        if !keys.is_empty() {
            n.push(' ');
            n.push_str(&keys.join(" and "));
        }
        if seen.insert(n.clone()) {
            out.push(n);
        }
    }
    out.join(", ")
}
