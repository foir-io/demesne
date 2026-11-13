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
    composition_cut(o, Cut { upper: false, positive: CutAt::Never, negative: CutAt::Unknown, given: None })
}

/// What a composition term becomes when an object's rule is judged without following it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutAt {
    /// The term stays, to be followed.
    Keep,
    /// The term is false: the rule is the row's own.
    Never,
    /// The term cannot be decided: false in a lower bound, true in an upper bound, and the reverse under a `not` or a `none`.
    Unknown,
}

/// How [`composition_cut`] treats the composition terms of an object's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cut<'a> {
    /// The cut rule is an upper bound of the rule, where it otherwise is a lower bound.
    pub upper: bool,
    /// A composition term that widens the rule.
    pub positive: CutAt,
    /// A composition term under a `not` or inside a `none`, which narrows the rule.
    pub negative: CutAt,
    /// A composition relation whose terms stay whatever the rest says: the one a hop is being followed on.
    pub given: Option<&'a str>,
}

impl Cut<'_> {
    fn root(self) -> Bound {
        if self.upper { Bound::AtLeast } else { Bound::AtMost }
    }

    fn keeps(self) -> bool {
        self.positive == CutAt::Keep || self.negative == CutAt::Keep
    }
}

/// Returns the object with its composition terms cut from every permission as `cut` says, so the rule bounds the object's own.
#[must_use]
pub fn composition_cut(o: &Object, cut: Cut<'_>) -> Object {
    let comp = cut_relations(o, cut);
    let pruning = Pruning { comp: &comp, cut };
    let mut cp = o.clone();
    if !cut.keeps() && cut.given.is_none() {
        cp.relations = o.relations.iter().filter(|r| !matches!(r.repr, Repr::Composition(_))).cloned().collect();
    }
    cp.perms = o
        .perms
        .iter()
        .map(|pm| {
            let mut pc = pm.clone();
            pc.tree = match pruned_branches(&pm.tree, pruning, cut.root()) {
                Pruned::Kept(body) => body,
                Pruned::Never | Pruned::Always => PermNode::nil(),
            };
            pc
        })
        .collect();
    cp
}

/// An expression after its composition terms are cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bounded {
    Kept(PermNode),
    Never,
    Always,
}

/// Returns `n`, an expression of `o` that widens its rule, with its composition terms cut as `cut` says.
#[must_use]
pub fn cut_tree(o: &Object, n: &PermNode, cut: Cut<'_>) -> Bounded {
    let comp = cut_relations(o, cut);
    match pruned_branches(n, Pruning { comp: &comp, cut }, cut.root()) {
        Pruned::Kept(body) => Bounded::Kept(body),
        Pruned::Never => Bounded::Never,
        Pruned::Always => Bounded::Always,
    }
}

fn cut_relations<'a>(o: &'a Object, cut: Cut<'_>) -> Vec<&'a str> {
    let composed = o.relations.iter().filter(|r| matches!(r.repr, Repr::Composition(_))).map(|r| r.name.as_str());
    composed.filter(|name| cut.given != Some(*name)).collect()
}

#[derive(Clone, Copy)]
struct Pruning<'a> {
    comp: &'a [&'a str],
    cut: Cut<'a>,
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

fn pruned_leaf(t: &Term, comp: Pruning<'_>, bound: Bound) -> Pruned {
    if comp.comp.contains(&t.ident()) {
        let at = if bound == comp.cut.root() { comp.cut.positive } else { comp.cut.negative };
        return match at {
            CutAt::Keep => Pruned::Kept(PermNode::Leaf(t.clone())),
            CutAt::Never => Pruned::Never,
            CutAt::Unknown => bound.unknown(),
        };
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

fn pruned_branches(n: &PermNode, comp: Pruning<'_>, bound: Bound) -> Pruned {
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

#[must_use]
pub fn term_ref(ident: &str) -> Term {
    Term { kind: TermKind::Ref { ident: ident.to_string(), walk_verb: None }, pos: Pos::default() }
}
