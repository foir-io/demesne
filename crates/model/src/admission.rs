use crate::SpecExt;
use crate::analysis::{Rels, rels_of};
use crate::conditional::{accessor_tree_op, is_row_leaf, mode_row_sql, narrowing_accessor_leaf, not_kid, row_term_sql};
use demesne_runtime::quote_literal;
use demesne_syntax::{Object, PermNode, Relation, Repr, Term, ViaColumn};

/// The value a claim must have for a conditional row to admit a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValue {
    /// A value written in the spec.
    Literal(String),
    /// The value of a column on the row.
    Column(String),
}

/// A claim a caller's request must carry, with the value it must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMatch {
    pub key: String,
    pub value: ClaimValue,
}

impl ClaimMatch {
    fn literal(key: impl Into<String>, value: impl Into<String>) -> Self {
        ClaimMatch { key: key.into(), value: ClaimValue::Literal(value.into()) }
    }

    fn column(key: impl Into<String>, column: impl Into<String>) -> Self {
        ClaimMatch { key: key.into(), value: ClaimValue::Column(column.into()) }
    }
}

/// One row of an object's conditional reader listing: callers it admits without naming them.
///
/// A caller is admitted when the row's `row_cond` holds and their request carries every claim in
/// `claims`, each with its value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConditionalAdmission {
    pub source: String,
    pub principal_kind: String,
    pub claims: Vec<ClaimMatch>,
    pub row_cond: String,
}

/// Lists the readers a select permission admits on a condition rather than by name.
///
/// It is implemented for every [`SpecExt`] type, so it is sealed with [`SpecExt`].
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
            conds.push(format!("{} = {}", d, quote_literal(vc.discrim_val.as_deref().unwrap_or(""))));
        }
        let key = self.subject_by_name(&r.types[0]).map(|s| s.identifies().to_string()).unwrap_or_default();
        Some(ConditionalAdmission {
            source: "claim".into(),
            claims: vec![ClaimMatch::column(key, vc.column.clone())],
            row_cond: conds.join(" AND "),
            ..Default::default()
        })
    }

    fn conditional_term(&self, t: &Term, rels: &Rels) -> Option<ConditionalAdmission> {
        if t.builtin() == "claim" {
            return Some(ConditionalAdmission {
                source: "claim".into(),
                claims: vec![ClaimMatch::literal(t.claim_key(), t.claim_val())],
                ..Default::default()
            });
        }
        if let Some(row_cond) = mode_row_sql(t) {
            return Some(ConditionalAdmission { source: "mode".into(), principal_kind: t.mode_scope().into(), row_cond, ..Default::default() });
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
        let claim = |m: ClaimMatch| ConditionalAdmission { source: "claim".into(), claims: vec![m], ..Default::default() };
        match t.builtin() {
            "public" => vec![ConditionalAdmission { source: "public".into(), ..Default::default() }],
            "kind" => vec![claim(ClaimMatch::literal("kind", t.kind_val()))],
            "self" => vec![claim(ClaimMatch::column(self.admin_identify(), t.self_col()))],
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
            claims: vec![ClaimMatch::column(self.claim_key_for_level(level), col.clone())],
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

    /// Returns the single conditional row a conjunction lists, carrying every claim it requires.
    ///
    /// The row takes its source from the conjunction's first admission, or is a `claim` row when
    /// the conjunction is claims alone. A conjunct no row can state exactly, such as a negation,
    /// `@scoped`, a nullable `@within` or `@holds`, is left out, so the row may admit more callers
    /// than the policy does, never fewer. A conjunct naming principals makes the conjunction
    /// relational, and it has no conditional row.
    fn conditional_conjunction(&self, obj: &Object, n: &PermNode, rels: &Rels) -> Option<ConditionalAdmission> {
        let PermNode::And(kids) = n else { return None };
        fold_conjunction(self, obj, kids, rels, Unstated::Refuse)
    }

    /// Returns one conditional row for each select `admit` arm, or for each branch of an arm that is a union.
    ///
    /// An arm names nobody the listing could enumerate, so each row has a NULL principal and the `admit` source. It carries
    /// the claims and row conditions the arm states; a conjunct no row can state, such as a relation confined by a claim,
    /// is left out, so the row may admit more callers than the arm does, never fewer.
    fn admit_admissions(&self, obj: &Object, rels: &Rels) -> Vec<ConditionalAdmission> {
        obj.admits.iter().filter(|a| a.ops.iter().any(|op| op == "select")).flat_map(|a| arm_admissions(self, obj, &a.tree, rels)).collect()
    }

    fn conditional_accessors(&self, obj: &Object) -> Vec<ConditionalAdmission> {
        let Some(sel) = crate::analysis::object_select_perm(obj) else { return Vec::new() };
        let rels = rels_of(obj);
        let mut out = if accessor_tree_op(&sel.tree).is_empty() {
            sel.tree.leaves().iter().flat_map(|t| self.union_admissions(obj, t, &rels)).collect()
        } else {
            self.adding_conditional_terms(obj, &sel.tree, &rels)
        };
        out.extend(self.admit_admissions(obj, &rels));
        out
    }

    fn adding_conditional_terms(&self, obj: &Object, n: &PermNode, rels: &Rels) -> Vec<ConditionalAdmission> {
        match n {
            PermNode::Leaf(t) => self.union_admissions(obj, t, rels),
            PermNode::Not(_) => Vec::new(),
            PermNode::And(kids) => match self.conditional_conjunction(obj, n, rels) {
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
            Some(d) => format!("{} IS DISTINCT FROM {}", d, quote_literal(vc.discrim_val.as_deref().unwrap_or(""))),
            None => format!("{} IS NULL", vc.column),
        })
        .collect();
    conds.join(" AND ")
}

#[derive(Clone, Copy)]
enum Unstated {
    Refuse,
    Drop,
}

fn arm_admissions<S: ConditionalExt + ?Sized>(s: &S, obj: &Object, n: &PermNode, rels: &Rels) -> Vec<ConditionalAdmission> {
    let row = match n {
        PermNode::Or(kids) => return kids.iter().flat_map(|k| arm_admissions(s, obj, k, rels)).collect(),
        PermNode::And(kids) => fold_conjunction(s, obj, kids, rels, Unstated::Drop),
        other => fold_conjunction(s, obj, std::slice::from_ref(other), rels, Unstated::Drop),
    };
    row.into_iter().map(|a| ConditionalAdmission { source: "admit".into(), ..a }).collect()
}

fn fold_conjunction<S: ConditionalExt + ?Sized>(s: &S, obj: &Object, kids: &[PermNode], rels: &Rels, unstated: Unstated) -> Option<ConditionalAdmission> {
    let mut admit: Option<ConditionalAdmission> = None;
    let mut conds: Vec<String> = Vec::new();
    let mut claims: Vec<ClaimMatch> = Vec::new();
    for k in kids {
        match conjunction_kid(s, obj, k, rels) {
            ConjunctionKid::Unenumerable => match unstated {
                Unstated::Refuse => return None,
                Unstated::Drop => {}
            },
            ConjunctionKid::Narrowing => {}
            ConjunctionKid::RowCond(c) => conds.push(c),
            ConjunctionKid::Claims(c) => claims.extend(c),
            ConjunctionKid::Admission(mut a) => {
                claims.append(&mut a.claims);
                match &admit {
                    None => admit = Some(a),
                    Some(_) => conds.extend((!a.row_cond.is_empty()).then_some(a.row_cond)),
                }
            }
        }
    }
    let mut admit = match (admit, unstated) {
        (Some(a), _) => a,
        (None, _) if !claims.is_empty() => ConditionalAdmission { source: "claim".into(), ..Default::default() },
        (None, Unstated::Refuse) => return None,
        (None, Unstated::Drop) => ConditionalAdmission::default(),
    };
    if !admit.row_cond.is_empty() {
        conds.insert(0, std::mem::take(&mut admit.row_cond));
    }
    admit.row_cond = conds.join(" AND ");
    admit.claims = claims;
    Some(admit)
}

enum ConjunctionKid {
    RowCond(String),
    Claims(Vec<ClaimMatch>),
    Admission(ConditionalAdmission),
    Narrowing,
    Unenumerable,
}

fn conjunct_claims<S: ConditionalExt + ?Sized>(s: &S, obj: &Object, t: &Term) -> Option<Vec<ClaimMatch>> {
    let at_level = |level: &str| vec![ClaimMatch::column(s.claim_key_for_level(level), s.scope_col(obj, level))];
    match t.builtin() {
        "kind" => Some(vec![ClaimMatch::literal("kind", t.kind_val())]),
        "session" => obj.scoped.last().map(|leaf| at_level(leaf)),
        "within" if !t.within_nullable() => Some(at_level(t.within_level())),
        _ => None,
    }
}

fn conjunction_kid<S: ConditionalExt + ?Sized>(s: &S, obj: &Object, k: &PermNode, rels: &Rels) -> ConjunctionKid {
    if let Some(inner) = not_kid(k) {
        if let Some(t) = inner.term().filter(|_| is_row_leaf(inner)) {
            return ConjunctionKid::RowCond(format!("({}) IS NOT TRUE", row_term_sql(t)));
        }
        if narrowing_accessor_leaf(inner) || inner.term().is_some_and(|t| s.conditional_term(t, rels).is_some()) {
            return ConjunctionKid::Narrowing;
        }
    }
    let PermNode::Leaf(t) = k else { return ConjunctionKid::Unenumerable };
    if is_row_leaf(k) {
        return ConjunctionKid::RowCond(row_term_sql(t));
    }
    if let Some(a) = s.conditional_term(t, rels) {
        return ConjunctionKid::Admission(a);
    }
    if let Some(c) = conjunct_claims(s, obj, t) {
        return ConjunctionKid::Claims(c);
    }
    if narrowing_accessor_leaf(k) { ConjunctionKid::Narrowing } else { ConjunctionKid::Unenumerable }
}
