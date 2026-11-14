use crate::definers::Definers;
use crate::genfn::{DefinerArm, GenFn, Language};
use crate::rls::{Virtual, leaf};
use crate::{Binds, Sql};
use demesne_gocompat::quote;
use demesne_model::SpecExt;
use demesne_model::analysis::{Bounded, Cut, CutAt, composition_cut, cut_tree, rels_of};
use demesne_model::conditional::{ELEMENT, SLOT, row_term_sql};

pub(crate) const HOP: &str = "demesne_hop";
use demesne_runtime::quote_literal;
use demesne_syntax::{CompPath, Object, Perm, PermNode, Quantifier, Relation, Repr, SomeScope, Subject, Term, ViaComposition};
use std::collections::BTreeSet;
use std::fmt::Write as _;

type R<T> = Result<T, String>;

const ARMS: [(&str, &str); 3] = [("read", "select"), ("write", "update"), ("delete", "delete")];

fn mapped<'a>(obj: &'a Object, op: &str) -> Option<&'a Perm> {
    obj.perms.iter().find(|pm| pm.has_layer("rls") && pm.maps() == op)
}

fn widening_somes(n: &PermNode) -> Vec<&SomeScope> {
    match n {
        PermNode::Leaf(t) => t.some_scope().into_iter().collect(),
        PermNode::Not(_) => Vec::new(),
        PermNode::And(kids) | PermNode::Or(kids) => kids.iter().flat_map(widening_somes).collect(),
    }
}

fn narrowing_refs<'a>(n: &'a PermNode, narrows: bool, out: &mut BTreeSet<&'a str>) {
    match n {
        PermNode::Leaf(t) => narrowing_leaf(t, narrows, out),
        PermNode::Not(k) => narrowing_refs(k, !narrows, out),
        PermNode::And(kids) | PermNode::Or(kids) => kids.iter().for_each(|k| narrowing_refs(k, narrows, out)),
    }
}

fn narrowing_leaf<'a>(t: &'a Term, narrows: bool, out: &mut BTreeSet<&'a str>) {
    if let Some(scope) = t.some_scope() {
        narrowing_refs(&scope.body, narrows, out);
    } else if let Some(scope) = t.declared_scope() {
        narrowing_refs(&scope.body, narrows != (scope.quantifier == Quantifier::None), out);
    } else if narrows && !t.ident().is_empty() {
        out.insert(t.ident());
    }
}

pub(crate) fn evaluator_fn(obj: &Object, op: &str) -> String {
    format!("{}_{op}_holds_at", obj.name)
}

pub(crate) fn reached(fns: Vec<GenFn>, optional: &[String]) -> Vec<GenFn> {
    if optional.is_empty() {
        return fns;
    }
    let texts: Vec<String> = fns.iter().map(GenFn::create_sql).collect();
    let calls: Vec<String> = fns.iter().map(|f| format!("{}.{}(", f.schema(), f.name)).collect();
    let mut kept: Vec<bool> = fns.iter().map(|f| !optional.contains(&f.name)).collect();
    loop {
        let found: Vec<usize> = (0..fns.len()).filter(|&i| !kept[i] && (0..fns.len()).any(|j| kept[j] && texts[j].contains(&calls[i]))).collect();
        if found.is_empty() {
            break;
        }
        for i in found {
            kept[i] = true;
        }
    }
    fns.into_iter().zip(kept).filter_map(|(f, keep)| keep.then_some(f)).collect()
}

fn kept_plan(f: &mut GenFn) {
    if f.language != Language::Sql || !f.arms.is_empty() {
        return;
    }
    if !f.raw_body {
        f.body = format!("#variable_conflict use_column\nBEGIN\n  RETURN {};\nEND", f.body);
    } else if f.returns.starts_with("TABLE") && f.body.trim_start().starts_with("SELECT ") {
        f.body = format!("#variable_conflict use_column\nBEGIN\n  RETURN QUERY {}\nEND", f.body.trim_start());
    } else {
        return;
    }
    f.raw_body = true;
    f.language = Language::Plpgsql;
}

pub(crate) fn plans_kept(mut fns: Vec<GenFn>, chains: &[String]) -> Vec<GenFn> {
    if chains.is_empty() {
        return fns;
    }
    let texts: Vec<String> = fns.iter().map(GenFn::create_sql).collect();
    let calls: Vec<String> = fns.iter().map(|f| format!("{}.{}(", f.schema(), f.name)).collect();
    let mut inside: Vec<bool> = fns.iter().map(|f| chains.contains(&f.name)).collect();
    loop {
        let found: Vec<usize> = (0..fns.len()).filter(|&i| !inside[i] && (0..fns.len()).any(|j| inside[j] && texts[j].contains(&calls[i]))).collect();
        if found.is_empty() {
            break;
        }
        for i in found {
            inside[i] = true;
            kept_plan(&mut fns[i]);
        }
    }
    fns
}

impl<'a> Sql<'a> {
    fn narrowed_by(obj: &Object, r: &Relation) -> bool {
        let mut refs = BTreeSet::new();
        let trees = obj.perms.iter().map(|pm| &pm.tree).chain(obj.admits.iter().map(|a| &a.tree));
        trees.for_each(|tree| narrowing_refs(tree, false, &mut refs));
        refs.contains(r.name.as_str())
    }

    pub(crate) fn chain_fns(&self) -> Vec<String> {
        let mut names = Vec::new();
        for (obj, r) in self.s.relations() {
            let Repr::Composition(vc) = &r.repr else { continue };
            let Some(below) = vc.path.as_ref().map(|_| obj.nested.unwrap_or(0)) else { continue };
            for (level, upper) in (0..=below).flat_map(|level| [(level, false), (level, true)]) {
                names.push(self.judged((level < below).then_some(level), upper).composition_fn(obj, r));
            }
        }
        names
    }

    pub(crate) fn def_emit_composition(&self, defs: &mut Definers, virt: &Virtual) -> R<Vec<String>> {
        let mut optional = Vec::new();
        for (obj, r) in self.s.relations() {
            let Repr::Composition(vc) = &r.repr else { continue };
            let below = if vc.path.is_some() { obj.nested.unwrap_or(0) } else { 0 };
            for (level, upper) in (0..=below).rev().flat_map(|level| [(level, false), (level, true)]) {
                let made = self.composition_definer(defs, virt, (obj, r, vc), (level, below), upper)?;
                optional.extend(made.iter().filter(|_| level < below || (upper && !Self::narrowed_by(obj, r))).map(|f| f.name.clone()));
                defs.fns.extend(made);
            }
        }
        Ok(optional)
    }

    fn composition_definer(
        &self,
        defs: &mut Definers,
        virt: &Virtual,
        (obj, r, vc): (&'a Object, &'a Relation, &ViaComposition),
        (level, below): (usize, usize),
        upper: bool,
    ) -> R<Option<GenFn>> {
        let name = self.judged((level < below).then_some(level), upper).composition_fn(obj, r);
        if !defs.claim(&name) {
            return Ok(None);
        }
        let arms = self.composition_arms(obj, r, vc, virt, level, upper)?;
        if arms.is_empty() {
            return Err(format!("object {} composition relation {}: object has no cascadable @rls verb predicate", quote(&obj.name), quote(&r.name)));
        }
        let slot_arg = if vc.slot.is_some() { ", p_slot text" } else { "" };
        Ok(Some(GenFn {
            name,
            sig: format!("p_{}_id text, p_access text{slot_arg}", obj.name),
            arm_param: "p_access".into(),
            arms,
            strict: true,
            ..Default::default()
        }))
    }

    fn composition_arms(&self, obj: &'a Object, r: &'a Relation, vc: &ViaComposition, virt: &Virtual, level: usize, upper: bool) -> R<Vec<DefinerArm>> {
        let follows = vc.path.is_some() && level > 0;
        let judge = self.judged(level.checked_sub(1), upper);
        let base = composition_cut(obj, Cut { upper, positive: CutAt::Never, negative: if follows { CutAt::Keep } else { CutAt::Unknown }, given: None });
        let mut kind_filter = match &vc.kind_col {
            Some(k) => format!(" AND e.{k} = {}", quote_literal(vc.kind_val.as_deref().unwrap_or(""))),
            None => String::new(),
        };
        if let Some((col, _)) = &vc.slot {
            write!(kind_filter, " AND e.{col}::text = p_slot").expect("fmt::Write for String never fails");
        }
        let possibly = if upper { " IS NOT FALSE" } else { "" };
        let mut arms = Vec::new();
        for (access, op) in ARMS {
            let never = mapped(obj, op).is_some_and(|pm| !pm.tree.is_nil()) && mapped(&base, op).is_some_and(|pm| pm.tree.is_nil());
            let pred = if never { "false".to_string() } else { judge.op_predicate(&base, op, virt)? };
            if pred.is_empty() {
                continue;
            }
            let admits = format!("EXISTS (SELECT 1 FROM {} WHERE {}.{} = e.{} AND ({pred}){possibly})", obj.table, obj.table, obj.pk(), vc.parent_col);
            let reached = match &vc.path {
                Some(path) => format!("CASE WHEN {admits} THEN ({}) ELSE false END", self.judged(None, upper).path_sql((obj, r), path, (level, op), virt)?),
                None => admits,
            };
            arms.push(DefinerArm {
                value: access.into(),
                body: format!("EXISTS (SELECT 1 FROM {} e WHERE e.{} = p_{}_id{kind_filter} AND {reached})", vc.table, vc.child_col, obj.name),
            });
        }
        Ok(arms)
    }

    fn path_sql(&self, on: (&'a Object, &'a Relation), path: &CompPath, at: (usize, &str), virt: &Virtual) -> R<String> {
        let Some(col) = path.col_for(at.1) else {
            return Err(format!("object {}: relation {} names no path column for {}", quote(&on.0.name), quote(&on.1.name), at.1));
        };
        self.path_node(on, &path.along, &format!("e.{col}::text"), at, virt)
    }

    fn path_node(&self, on: (&'a Object, &'a Relation), n: &PermNode, key: &str, at: (usize, &str), virt: &Virtual) -> R<String> {
        let each = |kids: &[PermNode], joint: &str| -> R<String> {
            let parts = kids.iter().map(|k| self.path_node(on, k, key, at, virt).map(|sql| format!("({sql})"))).collect::<R<Vec<_>>>()?;
            Ok(parts.join(joint))
        };
        match n {
            PermNode::Leaf(t) => {
                let Some(scope) = t.declared_scope() else {
                    return Err(format!("object {}: a `path` holds `every` and `none` terms, not {}", quote(&on.0.name), t.display()));
                };
                let judge = if scope.quantifier == Quantifier::None { self.flipped() } else { *self };
                let body = judge.hop_node(on, &scope.body, at, virt)?;
                Ok(self.declared_rows_sql(scope, key, &body))
            }
            PermNode::Not(k) => Ok(format!("({}) IS NOT TRUE", self.flipped().path_node(on, k, key, at, virt)?)),
            PermNode::And(kids) => each(kids, " AND "),
            PermNode::Or(kids) => each(kids, " OR "),
        }
    }

    fn hop_node(&self, on: (&'a Object, &'a Relation), n: &PermNode, at: (usize, &str), virt: &Virtual) -> R<String> {
        let each = |kids: &[PermNode], joint: &str| -> R<String> {
            let parts = kids.iter().map(|k| self.hop_node(on, k, at, virt).map(|sql| format!("({sql})"))).collect::<R<Vec<_>>>()?;
            Ok(parts.join(joint))
        };
        match n {
            PermNode::Leaf(t) => self.hop_leaf(on, t, at, virt),
            PermNode::Not(k) => Ok(format!("({}) IS NOT TRUE", self.flipped().hop_node(on, k, at, virt)?)),
            PermNode::And(kids) => each(kids, " AND "),
            PermNode::Or(kids) => each(kids, " OR "),
        }
    }

    fn hop_leaf(&self, (obj, r): (&'a Object, &'a Relation), t: &Term, (level, op): (usize, &str), virt: &Virtual) -> R<String> {
        if t.slot_test().is_some() {
            return Ok(row_term_sql(t));
        }
        if let Some((col, claim)) = t.slot_held() {
            return Ok(self.held_sql(&format!("{SLOT}.{col}"), claim));
        }
        let Some((record, element, hop_op)) = t.holds_at() else {
            return Err(format!("object {}: a `path` tests its declared rows with `@slot` and `@holds_at`, not {}", quote(&obj.name), t.display()));
        };
        let hop_op = hop_op.unwrap_or(op);
        let Some(pm) = mapped(obj, hop_op).filter(|pm| !widening_somes(&pm.tree).is_empty()) else {
            return Err(format!("object {}: {} has no `some` in a permission that maps {hop_op} to judge an element by", quote(&obj.name), t.display()));
        };
        let mut bound = vec![format!("{SLOT}.{record}{} AS record", self.s.id_cast()), format!("{SLOT}.{element} AS element")];
        let mut absent = vec![format!("{HOP}.record IS NULL"), format!("{HOP}.element IS NULL")];
        if let Some(col) = t.holds_at_slot() {
            bound.push(format!("{SLOT}.{col} AS slot"));
            absent.push(format!("{HOP}.slot IS NULL"));
        }
        let judge = Sql { given: Some((r.name.as_str(), level == 0)), binds: Binds::HopRow, ..self.judged(level.checked_sub(1), self.bounds_above()) };
        let holds = judge.evaluator_body(obj, pm, virt)?;
        Ok(format!("(SELECT CASE WHEN {} THEN NULL ELSE {holds} END FROM (SELECT {}) AS {HOP})", absent.join(" OR "), bound.join(", ")))
    }

    pub(crate) fn def_emit_evaluators(&self, defs: &mut Definers, virt: &Virtual) -> R<()> {
        let judged = self.s.objects.iter().filter(|obj| obj.nested.is_some());
        for (obj, (_, op)) in judged.flat_map(|o| ARMS.map(|arm| (o, arm))) {
            let Some(pm) = mapped(obj, op).filter(|pm| !widening_somes(&pm.tree).is_empty()) else { continue };
            let name = evaluator_fn(obj, op);
            if defs.claim(&name) {
                let body = self.judged(None, false).evaluator_body(obj, pm, virt)?;
                defs.fns.push(GenFn { name, sig: format!("p_record {}, p_element text", self.s.id_type()), body, strict: true, ..Default::default() });
            }
        }
        Ok(())
    }

    fn evaluator_body(&self, obj: &Object, pm: &Perm, virt: &Virtual) -> R<String> {
        let rels = rels_of(obj);
        let cust_claim = self.s.owner_subject(leaf(obj)).map_or("", Subject::identifies);
        let mut held = Vec::new();
        for scope in widening_somes(&pm.tree) {
            let mut bound = vec![format!("{ELEMENT} = {}", self.hop_arg("element"))];
            bound.extend(self.some_bounds(scope));
            let cut = if let Some((given, true)) = self.given {
                cut_tree(obj, &scope.body, Cut { upper: self.upper, positive: CutAt::Unknown, negative: CutAt::Unknown, given: Some(given) })
            } else {
                Bounded::Kept(scope.body.clone())
            };
            match cut {
                Bounded::Never => continue,
                Bounded::Always => {}
                Bounded::Kept(body) => bound.push(self.some_body(&self.node_frags(obj, pm, &body, &rels, cust_claim)?)),
            }
            held.push(format!("EXISTS (SELECT 1 FROM unnest({}.{}) AS demesne_element(v) WHERE {})", obj.table, scope.col, bound.join(" AND ")));
        }
        if held.is_empty() {
            return Ok("false".into());
        }
        let obj_leaf = leaf(obj);
        let (_, inject) = self.rls_subject_branches(obj, virt, obj_leaf, virt.contains(obj_leaf), self.s.object_references_staff(obj), pm.maps());
        let mut conds = vec![format!("{}.{} = {}", obj.table, obj.pk(), self.hop_arg("record"))];
        let block = self.rls_containment_block(obj, obj_leaf, &inject, pm.maps())?;
        if !block.is_empty() {
            conds.push(block);
        }
        conds.push(format!("({})", held.join(" OR ")));
        Ok(format!("EXISTS (SELECT 1 FROM {} WHERE {})", obj.table, conds.join(" AND ")))
    }
}
