use crate::analysis::{Rels, SpecExt, rels_of};
use demesne_syntax::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConditionalAdmission {
    pub source: String,
    pub principal_kind: String,
    pub claim_key: String,
    pub claim_val: String,
    pub claim_val_col: String,
    pub row_cond: String,
}

pub fn accessor_tree_op(n: &PermNode) -> &'static str {
    match n {
        PermNode::Not(_) => "and not",
        PermNode::And(_) => "and",
        PermNode::Leaf(_) => "",
        PermNode::Or(kids) => kids.iter().map(accessor_tree_op).find(|op| !op.is_empty()).unwrap_or(""),
    }
}

pub fn is_row_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if t.builtin() == "row")
}

pub fn is_claim_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if t.builtin() == "claim")
}

pub fn claim_neutral_accessor_leaf(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if matches!(t.builtin(), "kind" | "app_scope" | "session" | "within" | "scoped" | "holds" | "claim" | "row"))
}

pub fn narrowing_accessor_leaf(n: &PermNode) -> bool {
    claim_neutral_accessor_leaf(n) || matches!(n, PermNode::Leaf(t) if t.mode_col().is_some())
}

pub fn not_kid(n: &PermNode) -> Option<&PermNode> {
    match n {
        PermNode::Not(k) => Some(k),
        _ => None,
    }
}

pub fn is_composition_leaf(n: &PermNode, rels: &Rels) -> bool {
    match n {
        PermNode::Leaf(t) if !t.ident().is_empty() => {
            rels.get(t.ident()).is_some_and(|r| matches!(r.repr, Repr::Composition(_)))
        }
        _ => false,
    }
}

pub fn admission_names(adms: &[ConditionalAdmission]) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for a in adms {
        let mut n = a.source.clone();
        if !a.claim_key.is_empty() {
            n.push(' ');
            n.push_str(&a.claim_key);
        }
        if seen.insert(n.clone()) {
            out.push(n);
        }
    }
    out.join(", ")
}

pub trait ConditionalExt: SpecExt {
    fn transient_column<'a>(&self, r: Option<&'a Relation>) -> Option<&'a ViaColumn> {
        let r = r?;
        if r.types.is_empty() {
            return None;
        }
        for t in &r.types {
            match self.subject_by_name(t) {
                Some(st) if st.transient => {}
                _ => return None,
            }
        }
        match &r.repr {
            Repr::Column(vc) => Some(vc),
            _ => None,
        }
    }

    fn transient_admission(&self, r: Option<&Relation>) -> Option<ConditionalAdmission> {
        let vc = self.transient_column(r)?;
        let r = r.unwrap();
        let mut conds = vec![format!("{} IS NOT NULL", vc.column)];
        if let Some(d) = &vc.discrim_col {
            conds.push(format!("{} = '{}'", d, vc.discrim_val.as_deref().unwrap_or("")));
        }
        Some(ConditionalAdmission {
            source: "claim".into(),
            claim_key: self.subject_by_name(&r.types[0]).map(|s| s.identifies().to_string()).unwrap_or_default(),
            claim_val_col: vc.column.clone(),
            row_cond: conds.join(" AND "),
            ..Default::default()
        })
    }

    fn conditional_term(&self, t: &Term, rels: &Rels) -> Option<ConditionalAdmission> {
        if t.builtin() == "claim" {
            return Some(ConditionalAdmission {
                source: "claim".into(),
                claim_key: t.claim_key().into(),
                claim_val: t.claim_val().into(),
                ..Default::default()
            });
        }
        if let Some(col) = t.mode_col() {
            return Some(ConditionalAdmission {
                source: "mode".into(),
                principal_kind: t.mode_scope().into(),
                row_cond: format!("{} = '{}'", col, t.mode_val()),
                ..Default::default()
            });
        }
        if t.builtin() == "app_scope" {
            let mut conds = Vec::new();
            for ex in t.exclude_rels() {
                let Some(r) = rels.get(ex.as_str()) else { continue };
                let Repr::Column(vc) = &r.repr else { continue };
                match &vc.discrim_col {
                    Some(d) => conds.push(format!("{} IS DISTINCT FROM '{}'", d, vc.discrim_val.as_deref().unwrap_or(""))),
                    None => conds.push(format!("{} IS NULL", vc.column)),
                }
            }
            return Some(ConditionalAdmission { source: "app_scope".into(), row_cond: conds.join(" AND "), ..Default::default() });
        }
        if !t.ident().is_empty() {
            return self.transient_admission(rels.get(t.ident()).copied());
        }
        None
    }

    fn is_conditional_leaf(&self, n: &PermNode, rels: &Rels) -> bool {
        match n {
            PermNode::Leaf(t) => self.conditional_term(t, rels).is_some(),
            _ => false,
        }
    }

    fn conditional_conjunction(&self, n: &PermNode, rels: &Rels) -> Option<ConditionalAdmission> {
        let PermNode::And(kids) = n else { return None };
        if kids.is_empty() {
            return None;
        }
        let mut admit: Option<ConditionalAdmission> = None;
        let mut conds: Vec<String> = Vec::new();
        for k in kids {
            if let Some(inner) = not_kid(k) {
                if is_row_leaf(inner) {
                    let t = inner.term().unwrap();
                    conds.push(format!("({} = '{}') IS NOT TRUE", t.row_col(), t.row_val()));
                    continue;
                }
                if narrowing_accessor_leaf(inner) || self.is_conditional_leaf(inner, rels) {
                    continue;
                }
            }
            let PermNode::Leaf(t) = k else { return None };
            if is_row_leaf(k) {
                conds.push(format!("{} = '{}'", t.row_col(), t.row_val()));
                continue;
            }
            if let Some(a) = self.conditional_term(t, rels) {
                if admit.is_none() {
                    admit = Some(a);
                } else if !a.row_cond.is_empty() {
                    conds.push(a.row_cond);
                }
                continue;
            }
            if !narrowing_accessor_leaf(k) {
                return None;
            }
        }
        let mut admit = admit?;
        if !admit.row_cond.is_empty() {
            conds.insert(0, admit.row_cond.clone());
        }
        admit.row_cond = conds.join(" AND ");
        Some(admit)
    }

    fn conditional_accessors(&self, obj: &Object) -> Vec<ConditionalAdmission> {
        let Some(sel) = crate::analysis::object_select_perm(obj) else { return Vec::new() };
        let rels = rels_of(obj);
        if !accessor_tree_op(&sel.tree).is_empty() {
            return self.adding_conditional_terms(&sel.tree, &rels);
        }
        sel.tree.leaves().iter().filter_map(|t| self.conditional_term(t, &rels)).collect()
    }

    fn adding_conditional_terms(&self, n: &PermNode, rels: &Rels) -> Vec<ConditionalAdmission> {
        match n {
            PermNode::Leaf(t) => self.conditional_term(t, rels).into_iter().collect(),
            PermNode::Not(_) => Vec::new(),
            PermNode::And(kids) => {
                if let Some(a) = self.conditional_conjunction(n, rels) {
                    return vec![a];
                }
                let mut out = Vec::new();
                for k in kids {
                    if narrowing_accessor_leaf(k) {
                        continue;
                    }
                    out.extend(self.adding_conditional_terms(k, rels));
                }
                out
            }
            PermNode::Or(kids) => kids.iter().flat_map(|k| self.adding_conditional_terms(k, rels)).collect(),
        }
    }
}

impl<T: SpecExt + ?Sized> ConditionalExt for T {}
