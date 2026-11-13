use demesne_syntax::{Builtin, DeclaredScope, Object, Perm, PermNode, Pos, Quantifier, Relation, Repr, SomeScope, Term, TermKind, ViaGrant};
use std::collections::HashMap;

pub const ORDERED_TABLE_OPS: [&str; 4] = ["select", "insert", "update", "delete"];

#[must_use]
pub fn op_to_cmd(op: &str) -> &'static str {
    match op {
        "select" => "SELECT",
        "insert" => "INSERT",
        "update" => "UPDATE",
        "delete" => "DELETE",
        _ => "",
    }
}

#[must_use]
pub fn access_for(op: &str) -> &'static str {
    match op {
        "select" => "read",
        "delete" => "delete",
        _ => "write",
    }
}

#[must_use]
pub fn contains(ss: &[String], want: &str) -> bool {
    ss.iter().any(|s| s == want)
}

#[must_use]
pub fn is_perm_key_lit(s: &str) -> bool {
    s.contains(':')
}

#[must_use]
pub fn go_type_name(r: &Repr) -> &'static str {
    match r {
        Repr::Column(_) => "demesne.ViaColumn",
        Repr::Edge(_) => "demesne.ViaEdge",
        Repr::Role => "demesne.ViaRole",
        Repr::Composition(_) => "demesne.ViaComposition",
        Repr::Closure(_) => "demesne.ViaClosure",
        Repr::Group(_) => "demesne.ViaGroup",
        Repr::Object(_) => "demesne.ViaObject",
        Repr::MemberIn(_) => "demesne.ViaMemberIn",
        Repr::Grant(_) => "demesne.ViaGrant",
        Repr::Conditions(_) => "demesne.ViaConditions",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CostClass {
    Inline,
    Definer,
    Closure,
}

impl CostClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CostClass::Inline => "inline",
            CostClass::Definer => "definer",
            CostClass::Closure => "closure",
        }
    }
}

#[must_use]
pub fn cost_class(r: &Relation) -> CostClass {
    match r.repr {
        Repr::Column(_) => CostClass::Inline,
        Repr::Group(_) | Repr::Closure(_) => CostClass::Closure,
        _ => CostClass::Definer,
    }
}

pub type Rels<'a> = HashMap<&'a str, &'a Relation>;

#[must_use]
pub fn rels_of(o: &Object) -> Rels<'_> {
    let mut m = HashMap::new();
    for r in &o.relations {
        m.insert(r.name.as_str(), r);
    }
    m
}

#[must_use]
pub fn grant_relation(o: &Object) -> Option<(&Relation, &ViaGrant)> {
    o.relations.iter().find_map(|r| match &r.repr {
        Repr::Grant(vg) => Some((r, vg)),
        _ => None,
    })
}

#[must_use]
pub fn object_grant_edge(o: &Object) -> Option<&ViaGrant> {
    grant_relation(o).map(|(_, vg)| vg)
}

#[must_use]
pub fn object_uses_store_manage(o: &Object) -> bool {
    o.perms.iter().any(|pm| pm.tree.leaves().iter().any(|t| t.builtin() == "store_manage"))
}

#[must_use]
pub fn object_select_perm(o: &Object) -> Option<&Perm> {
    o.perms.iter().find(|pm| pm.maps() == "select")
}

#[must_use]
pub fn object_select_policy_perm(o: &Object) -> Option<&Perm> {
    object_select_perm(o).filter(|pm| pm.has_layer("rls") && !pm.predicate_only)
}

#[must_use]
pub fn mapped_perm<'a>(o: &'a Object, verb: &str) -> Option<&'a Perm> {
    o.perms.iter().find(|pm| pm.verb == verb && pm.has_layer("rls") && !pm.predicate_only && !op_to_cmd(pm.maps()).is_empty())
}

#[must_use]
pub fn grant_selector<'a>(ident: &'a str, rels: &Rels) -> Option<(&'a str, &'a str)> {
    let i = ident.find(':')?;
    let (rel_name, access) = (&ident[..i], &ident[i + 1..]);
    let r = rels.get(rel_name)?;
    match r.repr {
        Repr::Grant(_) => Some((rel_name, access)),
        _ => None,
    }
}

#[must_use]
pub fn is_grant_selector_term(ident: &str, rels: &Rels) -> bool {
    grant_selector(ident, rels).is_some()
}

#[must_use]
pub fn grant_rel_definer_base(o: &Object, vg: &ViaGrant) -> String {
    if vg.discrim_col.is_some() { format!("{}_grants_{}", vg.table, o.name) } else { format!("{}_grants", vg.table) }
}

#[must_use]
pub fn store_manage_name(table: &str) -> String {
    format!("{table}_manage")
}

#[must_use]
pub fn relation_is_async(r: &Relation) -> bool {
    matches!(&r.repr, Repr::Grant(g) if g.is_async)
}

#[must_use]
pub fn without_composition(o: &Object) -> Object {
    let comp: Vec<&str> = o.relations.iter().filter(|r| matches!(r.repr, Repr::Composition(_))).map(|r| r.name.as_str()).collect();
    let mut cp = o.clone();
    cp.relations = o.relations.iter().filter(|r| !matches!(r.repr, Repr::Composition(_))).cloned().collect();
    cp.perms = o
        .perms
        .iter()
        .map(|pm| {
            let mut pc = pm.clone();
            pc.tree = without_comp_branches(&pm.tree, &comp).unwrap_or_else(PermNode::nil);
            pc
        })
        .collect();
    cp
}

enum Pruned {
    Kept(PermNode),
    Never,
    Always,
}

fn rebuilt(t: &Term, b: Builtin) -> Pruned {
    Pruned::Kept(PermNode::Leaf(Term { kind: TermKind::Builtin(b), pos: t.pos }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bound {
    AtMost,
    AtLeast,
}

impl Bound {
    fn unknown(self) -> Pruned {
        match self {
            Bound::AtMost => Pruned::Never,
            Bound::AtLeast => Pruned::Always,
        }
    }

    fn flipped(self) -> Bound {
        match self {
            Bound::AtMost => Bound::AtLeast,
            Bound::AtLeast => Bound::AtMost,
        }
    }
}

fn pruned_leaf(t: &Term, comp: &[&str], bound: Bound) -> Pruned {
    if comp.contains(&t.ident()) {
        return bound.unknown();
    }
    if let Some(scope) = t.some_scope() {
        return match pruned_branches(&scope.body, comp, bound) {
            Pruned::Kept(body) => rebuilt(t, Builtin::Some(Box::new(SomeScope { body, ..scope.clone() }))),
            Pruned::Never => Pruned::Never,
            Pruned::Always => bound.unknown(),
        };
    }
    let Some(scope) = t.declared_scope() else { return Pruned::Kept(PermNode::Leaf(t.clone())) };
    let rows_decide = |scope: &DeclaredScope, body: PermNode| rebuilt(t, Builtin::Declared(Box::new(DeclaredScope { body, ..scope.clone() })));
    match scope.quantifier {
        Quantifier::Every => match pruned_branches(&scope.body, comp, bound) {
            Pruned::Kept(body) => rows_decide(scope, body),
            Pruned::Always => Pruned::Always,
            Pruned::Never => bound.unknown(),
        },
        Quantifier::None => match pruned_branches(&scope.body, comp, bound.flipped()) {
            Pruned::Kept(body) => rows_decide(scope, body),
            Pruned::Never => Pruned::Always,
            Pruned::Always => bound.unknown(),
        },
    }
}

fn pruned_branches(n: &PermNode, comp: &[&str], bound: Bound) -> Pruned {
    match n {
        PermNode::Leaf(t) => pruned_leaf(t, comp, bound),
        PermNode::Not(k) => match pruned_branches(k, comp, bound.flipped()) {
            Pruned::Kept(pk) => Pruned::Kept(PermNode::Not(Box::new(pk))),
            Pruned::Never => Pruned::Always,
            Pruned::Always => Pruned::Never,
        },
        PermNode::And(kids) => {
            let mut kept = Vec::new();
            for k in kids {
                match pruned_branches(k, comp, bound) {
                    Pruned::Never => return Pruned::Never,
                    Pruned::Always => {}
                    Pruned::Kept(pk) => kept.push(pk),
                }
            }
            if kept.is_empty() { Pruned::Always } else { Pruned::Kept(PermNode::And(kept)) }
        }
        PermNode::Or(kids) => {
            let mut kept = Vec::new();
            for k in kids {
                match pruned_branches(k, comp, bound) {
                    Pruned::Never => {}
                    Pruned::Always => return Pruned::Always,
                    Pruned::Kept(pk) => kept.push(pk),
                }
            }
            match kept.len() {
                0 => Pruned::Never,
                1 => Pruned::Kept(kept.remove(0)),
                _ => Pruned::Kept(PermNode::Or(kept)),
            }
        }
    }
}

fn without_comp_branches(n: &PermNode, comp: &[&str]) -> Option<PermNode> {
    match pruned_branches(n, comp, Bound::AtMost) {
        Pruned::Kept(body) => Some(body),
        Pruned::Never | Pruned::Always => None,
    }
}

#[must_use]
pub fn term_ref(ident: &str) -> Term {
    Term { kind: TermKind::Ref { ident: ident.to_string(), walk_verb: None }, pos: Pos::default() }
}
