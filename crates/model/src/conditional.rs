use crate::ConditionalAdmission;
use crate::analysis::Rels;
use demesne_runtime::quote_literal;
use demesne_syntax::{DeclaredScope, PermNode, Repr, SomeScope, Term};

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
    matches!(n, PermNode::Leaf(t) if matches!(t.builtin(), "row" | "element" | "slot" | "clock"))
}

/// The name a `some` term binds its element to in the SQL it compiles to.
pub const ELEMENT: &str = "demesne_element.v";

/// The name an `every` or `none` term binds its declared row to in the SQL it compiles to.
pub const SLOT: &str = "demesne_slot";

/// Returns the SQL a `@row` term compiles to: true of a row whose column holds the value, or is NULL for `@row(<column>, null)`.
#[must_use]
pub fn row_term_sql(t: &Term) -> String {
    if let Some(col) = t.clock_col() {
        return format!("{col} <= now()");
    }
    if let Some((col, val)) = t.slot_test() {
        return format!("{SLOT}.{col} = {}", quote_literal(val));
    }
    if let Some(prefix) = t.element_prefix() {
        return format!("starts_with({ELEMENT}, {})", quote_literal(prefix));
    }
    if t.row_null() {
        return format!("{} IS NULL", t.row_col());
    }
    format!("{} = {}", t.row_col(), quote_literal(t.row_val()))
}

/// Returns the SQL that holds of a row when its `some` column has an element the term binds by its prefix, the
/// `held` claim aside: what a reader listing applies to the principals the term's brackets name.
#[must_use]
pub fn some_row_sql(scope: &SomeScope) -> String {
    match &scope.prefix {
        Some(prefix) => format!("EXISTS (SELECT 1 FROM unnest({}) AS demesne_element(v) WHERE starts_with({ELEMENT}, {}))", scope.col, quote_literal(prefix)),
        None => format!("cardinality({}) > 0", scope.col),
    }
}

/// Returns the SQL a `mode` term tests on the row, without the plane it may be scoped to.
#[must_use]
pub fn mode_row_sql(t: &Term) -> Option<String> {
    t.mode_col().map(|col| format!("{col} = {}", quote_literal(t.mode_val())))
}

/// Returns `n` with its `@slot` tests taken out, or `None` when nothing else is left: an `every` body as a reader
/// listing names through it, the declared rows' tests set aside.
#[must_use]
pub fn without_slot_tests(n: &PermNode) -> Option<PermNode> {
    let kept = |kids: &[PermNode]| -> Vec<PermNode> { kids.iter().filter_map(without_slot_tests).collect() };
    match n {
        PermNode::Leaf(t) if t.slot_test().is_some() => None,
        PermNode::And(kids) => one_or(kept(kids), PermNode::And),
        PermNode::Or(kids) => one_or(kept(kids), PermNode::Or),
        _ => Some(n.clone()),
    }
}

fn one_or(mut kept: Vec<PermNode>, join: fn(Vec<PermNode>) -> PermNode) -> Option<PermNode> {
    match kept.len() {
        0 => None,
        1 => kept.pop(),
        _ => Some(join(kept)),
    }
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

/// Returns the columns of a declared row an `every` or `none` reads.
///
/// They are its `where`, its `@slot` tests, the `@holds_at` columns a composition's path names, and the columns a
/// slot-bound relation matches, in that order, repeats kept.
#[must_use]
pub fn declared_columns(scope: &DeclaredScope, rels: &Rels) -> Vec<String> {
    let bound = |t: &&Term| {
        rels.get(t.ident()).and_then(|r| match &r.repr {
            Repr::Edge(e) => e.slot.as_ref(),
            Repr::Composition(c) => c.slot.as_ref(),
            _ => None,
        })
    };
    let leaves = scope.body.leaves();
    let tested = leaves.iter().filter_map(|t| t.slot_test().or_else(|| t.slot_held())).map(|(col, _)| col.to_string());
    let hops = leaves.iter().filter_map(|t| t.holds_at()).flat_map(|(record, element, _)| [record.to_string(), element.to_string()]);
    let followed = leaves.iter().filter_map(|t| t.holds_at_slot()).map(str::to_string);
    let matched = leaves.iter().filter_map(bound).map(|(_, from)| from.clone());
    scope.filter.iter().map(|(col, _)| col.clone()).chain(tested).chain(hops).chain(followed).chain(matched).collect()
}
