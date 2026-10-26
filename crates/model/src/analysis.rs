use demesne_syntax::{Object, Perm, PermNode, Pos, Relation, Repr, Term, TermKind, ViaGrant};
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
            pc.tree = prune_comp_leaves(&pm.tree, &comp).unwrap_or_else(PermNode::nil);
            pc
        })
        .collect();
    cp
}

fn prune_comp_leaves(n: &PermNode, comp: &[&str]) -> Option<PermNode> {
    match n {
        PermNode::Leaf(t) => {
            if comp.contains(&t.ident()) {
                None
            } else {
                Some(n.clone())
            }
        }
        PermNode::Or(kids) | PermNode::And(kids) => {
            if kids.is_empty() {
                return None;
            }
            let mut out: Vec<PermNode> = kids.iter().filter_map(|k| prune_comp_leaves(k, comp)).collect();
            if out.is_empty() {
                return None;
            }
            if out.len() == 1 && matches!(n, PermNode::Or(_)) {
                return out.pop();
            }
            Some(if matches!(n, PermNode::Or(_)) { PermNode::Or(out) } else { PermNode::And(out) })
        }
        PermNode::Not(k) => prune_comp_leaves(k, comp).map(|pk| PermNode::Not(Box::new(pk))),
    }
}

#[must_use]
pub fn term_ref(ident: &str) -> Term {
    Term { kind: TermKind::Ref { ident: ident.to_string(), walk_verb: None }, pos: Pos::default() }
}
