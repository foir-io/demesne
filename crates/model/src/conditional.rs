use crate::analysis::{Rels, SpecExt, rels_of};
use demesne_syntax::{Object, PermNode, Relation, Repr, Term, ViaColumn};

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
        PermNode::Leaf(t) if !t.ident().is_empty() => rels.get(t.ident()).is_some_and(|r| matches!(r.repr, Repr::Composition(_))),
        _ => false,
    }
}

#[must_use]
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
        let r = r?;
        let vc = self.transient_column(Some(r))?;
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
            return Some(ConditionalAdmission { source: "app_scope".into(), row_cond: app_scope_exclusions(t, rels), ..Default::default() });
        }
        if !t.ident().is_empty() {
            return self.transient_admission(rels.get(t.ident()).copied());
        }
        None
    }

    /// Returns the conditional rows a term contributes where it widens a union of readers.
    ///
    /// Beyond what [`ConditionalExt::conditional_term`] names, a union lists `@public`, `@kind`, `@self`,
    /// `@session` and `@within` as conditions: none names a principal, but each admits callers.
    fn union_admissions(&self, obj: &Object, t: &Term, rels: &Rels) -> Vec<ConditionalAdmission> {
        if let Some(a) = self.conditional_term(t, rels) {
            return vec![a];
        }
        let claim = |claim_key: String, claim_val: &str, claim_val_col: String| ConditionalAdmission {
            source: "claim".into(),
            claim_key,
            claim_val: claim_val.into(),
            claim_val_col,
            ..Default::default()
        };
        match t.builtin() {
            "public" => vec![ConditionalAdmission { source: "public".into(), ..Default::default() }],
            "kind" => vec![claim("kind".into(), t.kind_val(), String::new())],
            "self" => vec![claim(self.admin_identify().into(), "", t.self_col().into())],
            "session" if t.session_rel().is_empty() => self.level_admissions(obj, obj.scoped.last().map_or("", String::as_str), false),
            "within" => self.level_admissions(obj, t.within_level(), t.within_nullable()),
            _ => Vec::new(),
        }
    }

    /// Returns the rows for a term that admits callers whose scope claim at `level` matches the row.
    fn level_admissions(&self, obj: &Object, level: &str, nullable: bool) -> Vec<ConditionalAdmission> {
        let col = self.scope_col(obj, level);
        let matched = ConditionalAdmission {
            source: "claim".into(),
            claim_key: self.claim_key_for_level(level),
            claim_val_col: col.clone(),
            row_cond: if nullable { format!("{col} IS NOT NULL") } else { String::new() },
            ..Default::default()
        };
        if !nullable {
            return vec![matched];
        }
        vec![matched, ConditionalAdmission { source: "scope".into(), row_cond: format!("{col} IS NULL"), ..Default::default() }]
    }

    fn is_conditional_leaf(&self, obj: &Object, n: &PermNode, rels: &Rels) -> bool {
        match n {
            PermNode::Leaf(t) => !self.union_admissions(obj, t, rels).is_empty(),
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
            match conjunction_kid(self, k, rels) {
                ConjunctionKid::Unenumerable => return None,
                ConjunctionKid::Narrowing => {}
                ConjunctionKid::RowCond(c) => conds.push(c),
                ConjunctionKid::Admission(a) if admit.is_none() => admit = Some(a),
                ConjunctionKid::Admission(a) => conds.extend((!a.row_cond.is_empty()).then_some(a.row_cond)),
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
            return self.adding_conditional_terms(obj, &sel.tree, &rels);
        }
        sel.tree.leaves().iter().flat_map(|t| self.union_admissions(obj, t, &rels)).collect()
    }

    fn adding_conditional_terms(&self, obj: &Object, n: &PermNode, rels: &Rels) -> Vec<ConditionalAdmission> {
        match n {
            PermNode::Leaf(t) => self.union_admissions(obj, t, rels),
            PermNode::Not(_) => Vec::new(),
            PermNode::And(kids) => match self.conditional_conjunction(n, rels) {
                Some(a) => vec![a],
                None => kids.iter().filter(|k| !narrowing_accessor_leaf(k)).flat_map(|k| self.adding_conditional_terms(obj, k, rels)).collect(),
            },
            PermNode::Or(kids) => kids.iter().flat_map(|k| self.adding_conditional_terms(obj, k, rels)).collect(),
        }
    }
}

impl<T: SpecExt + ?Sized> ConditionalExt for T {}

fn app_scope_exclusions(t: &Term, rels: &Rels) -> String {
    let conds: Vec<String> = t
        .exclude_rels()
        .iter()
        .filter_map(|ex| rels.get(ex.as_str()))
        .filter_map(|r| match &r.repr {
            Repr::Column(vc) => Some(vc),
            _ => None,
        })
        .map(|vc| match &vc.discrim_col {
            Some(d) => format!("{} IS DISTINCT FROM '{}'", d, vc.discrim_val.as_deref().unwrap_or("")),
            None => format!("{} IS NULL", vc.column),
        })
        .collect();
    conds.join(" AND ")
}

enum ConjunctionKid {
    RowCond(String),
    Admission(ConditionalAdmission),
    Narrowing,
    Unenumerable,
}

fn conjunction_kid<S: ConditionalExt + ?Sized>(s: &S, k: &PermNode, rels: &Rels) -> ConjunctionKid {
    if let Some(inner) = not_kid(k) {
        if let Some(t) = inner.term().filter(|_| is_row_leaf(inner)) {
            return ConjunctionKid::RowCond(format!("({} = '{}') IS NOT TRUE", t.row_col(), t.row_val()));
        }
        if narrowing_accessor_leaf(inner) || inner.term().is_some_and(|t| s.conditional_term(t, rels).is_some()) {
            return ConjunctionKid::Narrowing;
        }
    }
    let PermNode::Leaf(t) = k else { return ConjunctionKid::Unenumerable };
    if is_row_leaf(k) {
        return ConjunctionKid::RowCond(format!("{} = '{}'", t.row_col(), t.row_val()));
    }
    if let Some(a) = s.conditional_term(t, rels) {
        return ConjunctionKid::Admission(a);
    }
    if narrowing_accessor_leaf(k) { ConjunctionKid::Narrowing } else { ConjunctionKid::Unenumerable }
}
