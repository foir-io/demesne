use crate::Sql;
use crate::error::Error;
use demesne_gocompat::{fmt_slice, quote};
use demesne_model::SpecExt;
use demesne_model::analysis::{
    Rels, access_for, contains, grant_selector, is_perm_key_lit, object_grant_edge, op_to_cmd, rels_of, store_manage_name, term_ref,
};
use demesne_model::conditional::{mode_row_sql, row_term_sql};
use demesne_model::topology;
use demesne_runtime::quote_literal;
use demesne_syntax::{
    Admit, ArgSrc, Grant, Guard, GuardOp, Level, Membership, Object, Perm, PermNode, Relation, Repr, Require, Subject, Term, ViaClosure, ViaColumn,
    ViaComposition, ViaGrant, ViaGroup, ViaObject,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;

pub(crate) type Virtual = HashSet<String>;
type Inject = BTreeMap<String, Vec<String>>;
type R<T> = Result<T, String>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub object: String,
    pub table: String,
    pub name: String,
    pub cmd: String,
    pub using: String,
    pub check: String,
    pub restrictive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RlsResult {
    pub policies: Vec<Policy>,
    pub unsupported: Vec<String>,
    pub table_schema: String,
}

impl RlsResult {
    fn schema(&self) -> &str {
        if self.table_schema.is_empty() { "public" } else { &self.table_schema }
    }

    pub fn governed_tables(&self) -> Vec<String> {
        let set: BTreeSet<&str> = self.policies.iter().map(|p| p.table.as_str()).collect();
        set.into_iter().map(String::from).collect()
    }

    #[must_use]
    pub fn enablement_sql(&self) -> String {
        let sch = self.schema();
        let mut b = String::new();
        for t in self.governed_tables() {
            writeln!(b, "ALTER TABLE {sch}.{t} ENABLE ROW LEVEL SECURITY;").expect("fmt::Write for String never fails");
            writeln!(b, "ALTER TABLE {sch}.{t} FORCE ROW LEVEL SECURITY;").expect("fmt::Write for String never fails");
        }
        b
    }

    #[must_use]
    pub fn policy_sql(&self, role: &str) -> String {
        let mut pols = self.policies.clone();
        pols.sort_by(|a, b| {
            (&a.table, &a.name, &a.object, &a.cmd, a.restrictive, &a.using, &a.check).cmp(&(
                &b.table,
                &b.name,
                &b.object,
                &b.cmd,
                b.restrictive,
                &b.using,
                &b.check,
            ))
        });
        let sch = self.schema();
        let mut b = String::new();
        for p in &pols {
            let kind = if p.restrictive { " AS RESTRICTIVE" } else { "" };
            writeln!(b, "DROP POLICY IF EXISTS {} ON {}.{};", p.name, sch, p.table).expect("fmt::Write for String never fails");
            write!(b, "CREATE POLICY {} ON {}.{}{} FOR {} TO {}", p.name, sch, p.table, kind, p.cmd, role).expect("fmt::Write for String never fails");
            if !p.using.is_empty() {
                write!(b, "\n    USING ({})", p.using).expect("fmt::Write for String never fails");
            }
            if !p.check.is_empty() {
                write!(b, "\n    WITH CHECK ({})", p.check).expect("fmt::Write for String never fails");
            }
            b.push_str(";\n\n");
        }
        b
    }
}

fn op_policy(obj: &Object, op: &str, name: String, pred: &str, restrictive: bool) -> Policy {
    let mut pol = Policy { object: obj.name.clone(), table: obj.table.clone(), name, cmd: op_to_cmd(op).to_string(), restrictive, ..Default::default() };
    match op {
        "select" | "delete" => pol.using = pred.to_string(),
        "insert" => pol.check = pred.to_string(),
        "update" => {
            pol.using = pred.to_string();
            pol.check = pred.to_string();
        }
        _ => {}
    }
    pol
}

#[must_use]
pub fn scan_definers(sql: &str, schema: &str) -> Vec<String> {
    let mut out = Vec::new();
    let marker = format!("{schema}.");
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i + marker.len() <= sql.len() {
        let Some(idx) = sql[i..].find(&marker) else { break };
        let start = i + idx + marker.len();
        let mut j = start;
        while j < bytes.len() && (bytes[j] == b'_' || bytes[j].is_ascii_alphanumeric()) {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            out.push(format!("{marker}{}", &sql[start..j]));
        }
        i = j;
    }
    out
}

pub(crate) fn guard_sql(g: &Guard) -> String {
    match g.op {
        GuardOp::Ne => format!("({} IS NULL OR {} <> {})", g.col, g.col, quote_literal(&g.val)),
        GuardOp::Eq => format!("{} = {}", g.col, quote_literal(&g.val)),
    }
}

fn req_claim(cust_claim: &str, obj: &Object, what: &str) -> R<()> {
    if cust_claim.is_empty() {
        return Err(format!(
            "object {}: {} references the owner axis, but no owner subject (a subject `binds owner` at level {}) resolves a claim — refusing to emit an empty-claim predicate",
            quote(&obj.name),
            what,
            quote(obj.scoped.last().map_or("", String::as_str))
        ));
    }
    Ok(())
}

pub(crate) fn membership_fn(m: &Membership) -> &str {
    &m.flag_col
}

pub(crate) fn platform_role_fn(anchor: &str) -> String {
    format!("has_{anchor}_role")
}

fn owner_col_present(vc: &ViaColumn) -> String {
    let base = format!("{} IS NOT NULL", vc.column);
    match &vc.discrim_col {
        None => base,
        Some(d) => format!("{base} AND {d} = {}", quote_literal(vc.discrim_val.as_deref().unwrap_or(""))),
    }
}

pub(crate) fn owner_col_present_pub(vc: &ViaColumn) -> String {
    owner_col_present(vc)
}

#[derive(Debug)]
enum GrantReach {
    Contained { level: String, predicate: String },
    Top(String),
}

impl GrantReach {
    fn place(self, top: &mut Vec<String>, inject: &mut Inject) {
        match self {
            Self::Contained { level, predicate } => inject.entry(level).or_default().push(predicate),
            Self::Top(predicate) => top.push(predicate),
        }
    }
}

pub(crate) fn leaf(obj: &Object) -> &str {
    obj.scoped.last().map_or("", String::as_str)
}

impl Sql<'_> {
    #[must_use]
    pub fn claim(&self, key: &str) -> String {
        let (setting, cast) = self.claims_setting();
        format!("(current_setting({}, true)::{cast} ->> {})", quote_literal(setting), quote_literal(key))
    }

    pub(crate) fn claims_setting(&self) -> (&str, &str) {
        match &self.s.claims {
            Some(c) => (c.setting.as_str(), c.cast.as_str()),
            None => ("request.jwt.claims", "json"),
        }
    }

    #[must_use]
    pub fn id_claim(&self, key: &str) -> String {
        self.claim(key) + &self.s.id_cast()
    }

    #[must_use]
    pub fn id_claim_set(&self, key: &str) -> String {
        format!("ARRAY(SELECT e{} FROM jsonb_array_elements_text({}::jsonb) e)", self.s.id_cast(), self.claim(key))
    }

    #[must_use]
    pub fn session_claim(&self, key: &str) -> String {
        let (setting, cast) = self.claims_setting();
        format!("(NULLIF(current_setting({}, true), '')::{cast} ->> {})", quote_literal(setting), quote_literal(key)) + &self.s.id_cast()
    }

    pub(crate) fn virtual_levels(&self) -> R<Virtual> {
        Ok(topology::chain(self.s).map_err(|e| e.to_string())?.into_iter().filter(|l| l.is_virtual).map(|l| l.name.clone()).collect())
    }

    /// Compiles the row-level security policies for every `@rls` permission.
    ///
    /// # Errors
    ///
    /// The topology is invalid, or a permission cannot be compiled to a policy predicate.
    pub fn emit_rls(&self) -> Result<RlsResult, Error> {
        self.rls_result().map_err(Error::unplaced)
    }

    fn rls_result(&self) -> R<RlsResult> {
        let virt = self.virtual_levels()?;
        let mut res = RlsResult { table_schema: self.s.table_schema().to_string(), ..Default::default() };
        for obj in &self.s.objects {
            let cust = self.s.owner_subject(leaf(obj));
            for pm in obj.perms.iter().filter(|pm| pm.has_layer("rls") && !pm.predicate_only) {
                self.rls_perm_policies(&mut res, obj, pm, cust, &virt);
            }
        }
        Ok(res)
    }

    fn rls_perm_policies(&self, res: &mut RlsResult, obj: &Object, pm: &Perm, cust: Option<&Subject>, virt: &Virtual) {
        let pred = match self.admission_predicate(obj, pm, cust, virt) {
            Ok(p) => p,
            Err(e) => {
                res.unsupported.push(format!("{}.{}: {}", obj.name, pm.verb, e));
                return;
            }
        };
        let op = pm.maps();
        if op_to_cmd(op).is_empty() {
            res.unsupported.push(format!("{}.{}: @rls permission has no table-op maps", obj.name, pm.verb));
            return;
        }
        res.policies.push(op_policy(obj, op, format!("{}_{}", obj.table, op), &pred, false));
        match self.perm_require_sql(obj, pm, cust) {
            Err(e) => res.unsupported.push(format!("{}.{}: {}", obj.name, pm.verb, e)),
            Ok(req) if !req.is_empty() => res.policies.push(op_policy(obj, op, format!("{}_{}_require", obj.table, op), &req, true)),
            Ok(_) => {}
        }
    }

    pub(crate) fn edit_point_check_sql(&self, o: &Object) -> R<String> {
        match o.perms.iter().find(|pm| pm.has_layer("rls") && pm.maps() == "update") {
            Some(upd) => self.perm_point_check_sql(o, upd),
            None => Ok(String::new()),
        }
    }

    pub(crate) fn perm_point_check_sql(&self, o: &Object, pm: &Perm) -> R<String> {
        let virt = self.virtual_levels()?;
        let cust = self.s.owner_subject(leaf(o));
        let pred = self.admission_with_require(o, pm, cust, &virt)?;
        if pred.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("SELECT EXISTS (SELECT 1 FROM {} WHERE {} = $1 AND ({}))", o.table, o.pk(), pred))
    }

    pub(crate) fn admission_predicate(&self, obj: &Object, pm: &Perm, cust: Option<&Subject>, virt: &Virtual) -> R<String> {
        let pred = self.rls_predicate(obj, pm, cust, virt)?;
        let arms = self.admit_arms(obj, pm.maps(), cust, virt)?;
        if arms.is_empty() {
            return Ok(pred);
        }
        Ok(format!("({}) OR {}", pred, arms.join(" OR ")))
    }

    fn admit_arms(&self, obj: &Object, op: &str, cust: Option<&Subject>, virt: &Virtual) -> R<Vec<String>> {
        let mut arms = Vec::new();
        for a in &obj.admits {
            if !contains(&a.ops, op) {
                continue;
            }
            arms.push(format!("({})", self.admit_arm_predicate(obj, a, op, cust, virt)?));
        }
        Ok(arms)
    }

    pub(crate) fn admit_arm_predicate(&self, obj: &Object, a: &Admit, op: &str, cust: Option<&Subject>, virt: &Virtual) -> R<String> {
        let cust_claim = cust.map_or("", demesne_syntax::Subject::identifies);
        let rels = rels_of(obj);
        let obj_leaf = leaf(obj);
        let (_, inject) = self.rls_subject_branches(obj, virt, obj_leaf, virt.contains(obj_leaf), self.s.object_references_staff(obj), op);
        let perm = a.perm(op);
        let terms = self.node_frags(obj, &perm, &a.tree, &rels, cust_claim)?;
        if terms.is_empty() {
            return Err(format!("object {} admit {}: no emittable term", quote(&obj.name), op));
        }
        let block = self.rls_containment_block(obj, obj_leaf, &inject, op)?;
        if block.is_empty() {
            return Ok(terms.join(" OR "));
        }
        Ok(format!("{} AND ({})", block, terms.join(" OR ")))
    }

    pub(crate) fn admission_with_require(&self, obj: &Object, pm: &Perm, cust: Option<&Subject>, virt: &Virtual) -> R<String> {
        let pred = self.admission_predicate(obj, pm, cust, virt)?;
        let req = self.perm_require_sql(obj, pm, cust)?;
        if req.is_empty() {
            return Ok(pred);
        }
        Ok(format!("({pred}) AND ({req})"))
    }

    pub(crate) fn rls_predicate(&self, obj: &Object, pm: &Perm, cust: Option<&Subject>, virt: &Virtual) -> R<String> {
        let cust_claim = cust.map_or("", demesne_syntax::Subject::identifies);
        let rels = rels_of(obj);
        let obj_leaf = leaf(obj);
        let obj_is_global = virt.contains(obj_leaf);
        let has_staff = self.s.object_references_staff(obj);
        let (top, inject) = self.rls_subject_branches(obj, virt, obj_leaf, obj_is_global, has_staff, pm.maps());
        let (top, scoped_grant) = self.rls_expr_top_branches(obj, pm, top, &inject)?;
        let block_terms = self.node_frags(obj, pm, &pm.tree, &rels, cust_claim)?;
        let mut block = self.rls_containment_block(obj, obj_leaf, &inject, pm.maps())?;
        if !block_terms.is_empty() {
            if block.is_empty() {
                block = block_terms.join(" OR ");
            } else {
                block = format!("{} AND ({})", block, block_terms.join(" OR "));
            }
        }
        let containment_bearing = scoped_grant || !block_terms.is_empty();
        if top.is_empty() && !containment_bearing {
            return Err("no emittable grant terms".into());
        }
        let mut branches = top;
        if !block.is_empty() && containment_bearing {
            branches.push(format!("({block})"));
        }
        if branches.is_empty() {
            return Err(format!(
                "object {} permission {}: no emittable grant — a global object needs a platform-role subject",
                quote(&obj.name),
                quote(&pm.verb)
            ));
        }
        let mut pred = branches.join(" OR ");
        if let Some(sc) = &pm.self_check {
            let guard = format!("({sc} IS NULL OR {sc} = {})", self.id_claim(self.s.admin_identify()));
            pred = format!("{guard} AND ({pred})");
        }
        Ok(pred)
    }

    pub(crate) fn structural_branches(&self, obj: &Object, virt: &Virtual, op: &str) -> Vec<String> {
        let obj_leaf = leaf(obj);
        let obj_is_global = virt.contains(obj_leaf);
        let has_staff = self.s.object_references_staff(obj);
        self.rls_subject_branches(obj, virt, obj_leaf, obj_is_global, has_staff, op).0
    }

    fn rls_subject_branches(&self, obj: &Object, virt: &Virtual, obj_leaf: &str, obj_is_global: bool, has_staff: bool, op: &str) -> (Vec<String>, Inject) {
        let mut top = Vec::new();
        let mut inject = Inject::new();
        let schema = self.s.definer_schema();
        for sub in &self.s.subjects {
            if let Some(m) = &sub.membership
                && virt.contains(sub.anchor())
            {
                top.push(self.membership_branch(obj, sub, m, obj_leaf, obj_is_global));
            } else if self.s.is_platform_role_subject(sub) && (has_staff || (obj_is_global && sub.anchor() == obj_leaf)) {
                top.push(format!("{}.{}({})", schema, platform_role_fn(sub.anchor()), self.id_claim(sub.identifies())));
            } else if sub.reach() == "grant"
                && let Some(reach) = self.grant_reach_for_subject(obj, sub, obj_leaf, obj_is_global, op)
            {
                reach.place(&mut top, &mut inject);
            }
        }
        self.rls_apply_claim_reach(obj, obj_is_global, &mut inject, op);
        (top, inject)
    }

    fn membership_branch(&self, obj: &Object, sub: &Subject, m: &Membership, obj_leaf: &str, obj_is_global: bool) -> String {
        let f = format!("{}.{}({})", self.s.definer_schema(), membership_fn(m), self.id_claim(sub.identifies()));
        if obj.is_level_entity() || obj_is_global {
            return f;
        }
        format!("({} AND {} IS NULL)", f, self.claim(&self.s.claim_key_for_level(obj_leaf)))
    }

    fn rls_apply_claim_reach(&self, obj: &Object, obj_is_global: bool, inject: &mut Inject, op: &str) {
        if obj_is_global {
            return;
        }
        for g in &self.s.grants {
            if g.claim_key.is_none() || !g.confers(op) || !contains(&obj.scoped, &g.level) {
                continue;
            }
            inject.entry(g.level.clone()).or_default().push(self.claim_reach_predicate(g));
        }
    }

    fn grant_reach_for_subject(&self, obj: &Object, sub: &Subject, obj_leaf: &str, obj_is_global: bool, op: &str) -> Option<GrantReach> {
        let g = self.s.grant_by_name(sub.reach_grant())?;
        if !contains(&obj.scoped, &g.level) || !g.confers(op) || g.table() == obj.table {
            return None;
        }
        let predicate = self.grant_reach_predicate(obj, g, sub.identifies(), op)?;
        Some(if Self::grant_reach_is_contained(obj, sub, g, obj_leaf, obj_is_global) {
            GrantReach::Contained { level: g.level.clone(), predicate }
        } else {
            GrantReach::Top(predicate)
        })
    }

    fn grant_reach_is_contained(obj: &Object, sub: &Subject, g: &Grant, obj_leaf: &str, obj_is_global: bool) -> bool {
        if obj.is_level_entity() || obj_is_global {
            return false;
        }
        if g.level != obj_leaf {
            return true;
        }
        sub.anchor() == g.level
    }

    fn rls_expr_top_branches(&self, obj: &Object, pm: &Perm, mut top: Vec<String>, inject: &Inject) -> R<(Vec<String>, bool)> {
        let leaves = pm.tree.leaves();
        let scoped_grant = leaves.iter().any(|t| t.builtin() == "scoped");
        for t in &leaves {
            if t.grant_ref().is_empty() {
                continue;
            }
            if let Some(g) = self.s.grant_by_name(t.grant_ref())
                && !g.confers(pm.maps())
            {
                continue;
            }
            let reach = self.grant_ref_reach(obj, t.grant_ref(), pm.maps())?;
            if reach.is_empty() {
                continue;
            }
            if inject.values().any(|rs| rs.contains(&reach)) {
                continue;
            }
            if !top.contains(&reach) {
                top.push(reach);
            }
        }
        for t in &leaves {
            if t.builtin() == "public" && !top.iter().any(|x| x == "true") {
                top.push("true".into());
            }
        }
        for t in &leaves {
            if t.builtin() != "self" {
                continue;
            }
            let frag = format!("{} = {}", t.self_col(), self.id_claim(self.s.admin_identify()));
            if !top.contains(&frag) {
                top.push(frag);
            }
        }
        Ok((top, scoped_grant))
    }

    pub(crate) fn rls_containment_block(&self, obj: &Object, obj_leaf: &str, inject: &Inject, op: &str) -> R<String> {
        let paths = topology::ancestor_paths(self.s, obj_leaf).map_err(|e| e.to_string())?;
        let mut path_preds = Vec::new();
        for path in &paths {
            let cols: Vec<String> = path
                .iter()
                .filter(|lvl| !(lvl.is_virtual || (obj.is_level_entity() && lvl.name == obj.level())))
                .map(|lvl| self.containment_col_pred(obj, lvl, inject, op))
                .collect();
            path_preds.push(cols.join(" AND "));
        }
        if path_preds.len() == 1
            && let Some(only) = path_preds.pop()
        {
            return Ok(only);
        }
        Ok(path_preds.iter().map(|p| format!("({p})")).collect::<Vec<_>>().join(" OR "))
    }

    fn containment_col_pred(&self, obj: &Object, lvl: &Level, inject: &Inject, op: &str) -> String {
        let col = self.s.scope_col(obj, &lvl.name);
        let mut col_pred = format!("{} = {}", col, self.id_claim(&lvl.claim_key()));
        if obj.scope_is_wildcard_for(&lvl.name, op) {
            col_pred = format!("({col} IS NULL OR {col_pred})");
        } else if obj.scope_is_wildcard(&lvl.name) {
            col_pred = format!("{} IS NOT DISTINCT FROM {}", col, self.id_claim(&lvl.claim_key()));
        }
        if let Some(reaches) = inject.get(&lvl.name).filter(|r| !r.is_empty()) {
            col_pred = format!("({} OR {})", col_pred, reaches.join(" OR "));
        }
        col_pred
    }

    fn grant_ref_reach(&self, obj: &Object, grant_name: &str, op: &str) -> R<String> {
        let Some(g) = self.s.grant_by_name(grant_name) else {
            return Err(format!("object {}: permission references unknown grant {} (via grant)", quote(&obj.name), quote(grant_name)));
        };
        if !contains(&obj.scoped, &g.level) {
            return Err(format!(
                "object {}: `via grant {}` confers reach at level {}, not in the object's scope {}",
                quote(&obj.name),
                grant_name,
                quote(&g.level),
                fmt_slice(&obj.scoped)
            ));
        }
        let claim =
            self.s.subjects.iter().find(|sub| sub.reach() == "grant" && sub.reach_grant() == grant_name).map_or("", demesne_syntax::Subject::identifies);
        if claim.is_empty() {
            return Err(format!(
                "object {}: grant {} has no reaching subject (a `subject … reach via grant {}`) to supply a claim",
                quote(&obj.name),
                quote(grant_name),
                grant_name
            ));
        }
        Ok(self.grant_reach_predicate(obj, g, claim, op).unwrap_or_default())
    }

    fn grant_reach_predicate(&self, obj: &Object, g: &Grant, claim: &str, op: &str) -> Option<String> {
        let col = self.s.scope_col(obj, &g.level);
        let schema = self.s.definer_schema();
        let member = |f: String| format!("{} IN (SELECT {}.{}({}))", col, schema, f, self.id_claim(claim));
        match obj.grant_use(&g.name, op) {
            None => Some(member(format!("{}_reach_set", g.definer_base()))),
            Some(demesne_syntax::GrantUse { via: Some(via_name), .. }) => {
                let via = self.s.grant_by_name(via_name)?;
                if !via.confers(op) {
                    return None;
                }
                Some(member(format!("{}_reach_set", via.definer_base())))
            }
            Some(u) if u.unscoped => Some(member(format!("{}_reach_unscoped_set", g.definer_base()))),
            Some(u) => {
                let bound = u.bound.as_deref().unwrap_or("");
                Some(format!(
                    "({} OR ({} AND {} = {}))",
                    member(format!("{}_reach_unscoped_set", g.definer_base())),
                    member(format!("{}_reach_set", g.definer_base())),
                    self.s.scope_col(obj, bound),
                    self.id_claim(&self.s.claim_key_for_level(bound))
                ))
            }
        }
    }

    fn claim_reach_predicate(&self, g: &Grant) -> String {
        format!("{} = {}", self.claim(g.claim_key()), quote_literal(g.claim_value()))
    }

    pub(crate) fn object_verb_predicate(&self, obj: &Object, verb: &str, virt: &Virtual) -> R<String> {
        self.object_verb_predicate_for(obj, verb, "", virt)
    }

    pub(crate) fn object_verb_predicate_for(&self, obj: &Object, verb: &str, op: &str, virt: &Virtual) -> R<String> {
        let Some(pm) = obj.perms.iter().find(|pm| pm.verb == verb && pm.has_layer("rls")) else {
            return Err(format!("object {} has no @rls permission {} for a cross-object reference", quote(&obj.name), quote(verb)));
        };
        let cust = self.s.owner_subject(leaf(obj));
        if op.is_empty() {
            return self.perm_predicate(obj, pm, cust, virt);
        }
        let mut borrowed = pm.clone();
        borrowed.maps = Some(op.to_string());
        self.perm_predicate(obj, &borrowed, cust, virt)
    }

    fn arg_src_sql(&self, a: &ArgSrc) -> String {
        match a {
            ArgSrc::Claim(c) if !c.is_empty() => self.id_claim(c),
            _ => a.col().to_string(),
        }
    }

    fn mode_plane_scope(&self, scope: &str, cust_claim: &str) -> String {
        if self.s.subject_by_name(scope).is_some_and(|sub| sub.identifies() == cust_claim) {
            return format!("{} IS NOT NULL", self.claim(cust_claim));
        }
        format!("{} IS NULL", self.claim(cust_claim))
    }

    fn guardable(&self, t: &Term, rels: &Rels) -> bool {
        if t.builtin() == "session" {
            return true;
        }
        if !t.walk_verb().is_empty() {
            return false;
        }
        match rels.get(t.ident()) {
            Some(r) => match &r.repr {
                Repr::Role => !r.types.first().and_then(|t| self.s.subject_by_name(t)).is_some_and(|st| self.s.is_platform_role_subject(st)),
                Repr::MemberIn(_) => true,
                _ => false,
            },
            None => false,
        }
    }

    fn rls_leaf_frags(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        let b = t.builtin();
        if b == "scoped" || !t.grant_ref().is_empty() || b == "public" || b == "self" {
            return Ok(Vec::new());
        }
        let frags = self.emit_term(obj, pm, t, rels, cust_claim)?;
        Ok(frags
            .into_iter()
            .map(|f| match &pm.guard {
                Some(g) if self.guardable(t, rels) => format!("({} AND {})", f, guard_sql(g)),
                _ => f,
            })
            .collect())
    }

    pub(crate) fn node_frags(&self, obj: &Object, pm: &Perm, n: &PermNode, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        self.node_frags_mode(obj, pm, n, rels, cust_claim, false)
    }

    fn node_frags_mode(&self, obj: &Object, pm: &Perm, n: &PermNode, rels: &Rels, cust_claim: &str, require: bool) -> R<Vec<String>> {
        match n {
            PermNode::Leaf(t) => {
                if require {
                    self.require_leaf_frags(obj, pm, t, rels, cust_claim)
                } else {
                    self.rls_leaf_frags(obj, pm, t, rels, cust_claim)
                }
            }
            PermNode::Or(kids) => {
                let mut out = Vec::new();
                for k in kids {
                    out.extend(self.node_frags_mode(obj, pm, k, rels, cust_claim, require)?);
                }
                Ok(out)
            }
            PermNode::And(kids) => {
                let frags = kids.iter().map(|k| self.node_frags_mode(obj, pm, k, rels, cust_claim, require)).collect::<R<Vec<_>>>()?;
                let parts: Vec<String> = frags.iter().filter(|kf| !kf.is_empty()).map(|kf| format!("({})", kf.join(" OR "))).collect();
                if parts.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![parts.join(" AND ")])
            }
            PermNode::Not(k) => {
                let kf = self.node_frags_mode(obj, pm, k, rels, cust_claim, require)?;
                if kf.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![format!("({}) IS NOT TRUE", kf.join(" OR "))])
            }
        }
    }

    fn emit_term(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        if let Some(mut frag) = mode_row_sql(t) {
            if !t.mode_scope().is_empty() {
                frag = format!("{} AND {}", frag, self.mode_plane_scope(t.mode_scope(), cust_claim));
            }
            return Ok(vec![frag]);
        }
        if !t.walk_verb().is_empty() {
            return self.rls_emit_walk(obj, t, rels);
        }
        if let Some((rel_name, access)) = grant_selector(t.ident(), rels) {
            let r = rels[rel_name];
            let Repr::Grant(vg) = &r.repr else { unreachable!() };
            return self.emit_grant_frags(obj, r, vg, access, cust_claim);
        }
        if let Some(res) = self.rls_emit_builtin(obj, pm, t, rels, cust_claim) {
            return res;
        }
        self.rls_emit_relation(obj, pm, t, rels, cust_claim)
    }

    fn rls_emit_walk(&self, obj: &Object, t: &Term, rels: &Rels) -> R<Vec<String>> {
        let Some(parent) = rels.get(t.ident()) else {
            return Err(format!("role-walk references unknown relation {}", quote(t.ident())));
        };
        let Repr::Column(col) = &parent.repr else {
            return Err(format!("role-walk parent {} must be a column relation", quote(t.ident())));
        };
        let level = &parent.types[0];
        let path = topology::ancestor_path(self.s, level).map_err(|e| format!("role-walk {}->{}: {e}", quote(t.ident()), t.walk_verb()))?;
        let non_virtual: Vec<&Level> = path.into_iter().filter(|l| !l.is_virtual).collect();
        let mut args = vec![self.id_claim(self.s.admin_identify())];
        for (i, lvl) in non_virtual.iter().enumerate() {
            if i == non_virtual.len() - 1 {
                args.push(col.column.clone());
            } else {
                args.push(self.s.scope_col(obj, &lvl.name));
            }
        }
        Ok(vec![format!("{}.is_{}_{}({})", self.s.definer_schema(), level, self.s.admin_name(), args.join(", "))])
    }

    fn memberin_reach_frag(&self, level: &str, member: bool) -> R<String> {
        let schema = self.s.definer_schema();
        if member {
            let name = format!("{}_memberin_{}", self.s.admin_name(), level);
            return Ok(format!("{}.{}({}, {})", schema, name, self.id_claim(self.s.admin_identify()), self.id_claim(&self.s.claim_key_for_level(level))));
        }
        let path = topology::ancestor_path(self.s, level).map_err(|e| format!("memberin {level} reachedby: {e}"))?;
        let mut args = vec![self.id_claim(self.s.admin_identify())];
        for lvl in path {
            if lvl.is_virtual {
                continue;
            }
            args.push(self.id_claim(&self.s.claim_key_for_level(&lvl.name)));
        }
        Ok(format!("{}.is_{}_{}({})", schema, level, self.s.admin_name(), args.join(", ")))
    }

    fn rls_emit_builtin(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> Option<R<Vec<String>>> {
        let b = t.builtin();
        Some(match b {
            "open" => Ok(vec!["true".into()]),
            "app_scope" => self.rls_emit_app_scope(obj, t, rels, cust_claim),
            "store_manage" => self.rls_emit_store_manage(obj),
            "session" => self.rls_emit_session(obj, pm, t, rels, cust_claim),
            "kind" => Ok(vec![format!("{} = {}", self.claim("kind"), quote_literal(t.kind_val()))]),
            "claim" => Ok(vec![format!("{} = {}", self.claim(t.claim_key()), quote_literal(t.claim_val()))]),
            "row" => Ok(vec![row_term_sql(t)]),
            "within" => {
                let col = self.s.scope_col(obj, t.within_level());
                let claim = self.id_claim(&self.s.claim_key_for_level(t.within_level()));
                if t.within_nullable() { Ok(vec![format!("({col} IS NULL OR {col} = {claim})")]) } else { Ok(vec![format!("{col} = {claim}")]) }
            }
            "holds" => self.rls_emit_holds(obj, t),
            "" => {
                if is_perm_key_lit(t.ident()) {
                    Err(format!("capability term {} belongs to the PDP, not RLS", quote(t.ident())))
                } else {
                    return None;
                }
            }
            other => Err(format!("builtin @{other} is not emittable in RLS")),
        })
    }

    fn rls_emit_holds(&self, obj: &Object, t: &Term) -> R<Vec<String>> {
        let perm = t.holds_perm();
        let rs = self.s.holds_role_store(perm).map_err(|e| format!("@holds({}) on {}: {e}", quote(perm), quote(&obj.name)))?;
        if rs.perms_col.is_none() {
            return Err(format!("@holds({}) on {}: rolestore {} declares no `permissions` column", quote(perm), quote(&obj.name), quote(&rs.name)));
        }
        let chain = topology::chain(self.s).map_err(|e| e.to_string())?;
        let plane_depth = self.s.rolestore_plane_depth(rs);
        let mut args = vec![self.id_claim(self.s.admin_identify())];
        let mut i = 0;
        for l in chain {
            if l.is_virtual {
                continue;
            }
            if i >= rs.scope_cols.len() || i >= plane_depth {
                break;
            }
            if contains(&obj.scoped, &l.name) {
                args.push(self.s.scope_col(obj, &l.name));
            } else {
                args.push("NULL".into());
            }
            i += 1;
        }
        args.push(quote_literal(perm));
        Ok(vec![format!("{}.{}({})", self.s.definer_schema(), self.s.holds_perm_fn(rs), args.join(", "))])
    }

    fn rls_emit_app_scope(&self, obj: &Object, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        req_claim(cust_claim, obj, "@app_scope")?;
        let mut base = format!("{} IS NULL", self.claim(cust_claim));
        for ex in t.exclude_rels() {
            let Some(r) = rels.get(ex.as_str()) else {
                return Err(format!("@app_scope(exclude {}): unknown relation", quote(ex)));
            };
            let Repr::Column(vc) = &r.repr else {
                return Err(format!("@app_scope(exclude {}): excluded relation must be an owner column", quote(ex)));
            };
            base = match &vc.discrim_col {
                Some(d) => format!("({} AND {} IS DISTINCT FROM {})", base, d, quote_literal(vc.discrim_val.as_deref().unwrap_or(""))),
                None => format!("({} AND {} IS NULL)", base, vc.column),
            };
        }
        Ok(vec![base])
    }

    fn rls_emit_store_manage(&self, obj: &Object) -> R<Vec<String>> {
        let descs = self.s.store_descriptors(&obj.table);
        let Some(first) = descs.first() else {
            return Err(format!("@store_manage on {}: no object uses table {} as a grant store", quote(&obj.name), quote(&obj.table)));
        };
        let g = object_grant_edge(first).expect("a store descriptor is an object with a grant edge on this table");
        let Some(d) = &g.discrim_col else {
            return Err(format!(
                "@store_manage on {}: store {} is not discriminated (a single-kind store uses `via object <kind>->edit`)",
                quote(&obj.name),
                quote(&obj.table)
            ));
        };
        Ok(vec![format!("{}.{}({}, {})", self.s.definer_schema(), store_manage_name(&obj.table), d, g.record_col)])
    }

    fn rls_emit_session(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        let lf = leaf(obj);
        let me = format!("{} = {}", self.s.scope_col(obj, lf), self.id_claim(&self.s.claim_key_for_level(lf)));
        if t.session_rel().is_empty() {
            return Ok(vec![me]);
        }
        let role_frag = self.emit_term(obj, pm, &term_ref(t.session_rel()), rels, cust_claim)?;
        Ok(vec![format!("{} AND {}", me, role_frag[0])])
    }

    fn rls_closure_frag(&self, obj: &Object, c: &ViaClosure, ident: &str, cust_claim: &str) -> R<Vec<String>> {
        let schema = self.s.definer_schema();
        let Some(claim) = &c.claim else {
            req_claim(cust_claim, obj, &format!("closure relation {ident}"))?;
            return Ok(vec![format!("{}.{}_reachable({}, {})", schema, c.closure, self.id_claim(cust_claim), c.col)]);
        };
        let call = format!("{}.{}_reachable({}, {})", schema, c.closure, self.id_claim(claim), c.col);
        if c.missing.as_deref() == Some("allow") {
            return Ok(vec![format!("({} IS NULL OR {})", self.claim(claim), call)]);
        }
        Ok(vec![call])
    }

    fn rls_emit_relation(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        let Some(r) = rels.get(t.ident()).copied() else {
            return Err(format!("unknown relation {}", quote(t.ident())));
        };
        let access = access_for(pm.maps());
        let pk = format!("{}.{}", obj.table, obj.pk());
        let schema = self.s.definer_schema();
        match &r.repr {
            Repr::Column(vc) => {
                let claim_key = self.s.relation_claim(Some(r), cust_claim);
                req_claim(claim_key, obj, &format!("owner relation {}", t.ident()))?;
                let mut base = format!("{} = {}", vc.column, self.id_claim(claim_key));
                if self.s.transient_set(Some(r)) {
                    base = format!("{} = ANY({})", vc.column, self.id_claim_set(claim_key));
                }
                if let Some(d) = &vc.discrim_col {
                    base = format!("({} AND {} = {})", base, d, quote_literal(vc.discrim_val.as_deref().unwrap_or("")));
                }
                Ok(vec![base])
            }
            Repr::Edge(e) => {
                req_claim(cust_claim, obj, &format!("edge relation {}", t.ident()))?;
                Ok(vec![format!("{}.{}({}, {}, {})", schema, e.table, self.id_claim(cust_claim), pk, quote_literal(access))])
            }
            Repr::Composition(vc) => {
                let call = format!("{}.{}_composition_{}({}, {})", schema, obj.name, r.name, pk, quote_literal(access));
                Ok(vec![self.probed(&composition_probe(obj, vc), call)])
            }
            Repr::Closure(c) => self.rls_closure_frag(obj, c, t.ident(), cust_claim),
            Repr::Group(g) => {
                req_claim(cust_claim, obj, &format!("group relation {}", t.ident()))?;
                if g.materialized {
                    return Ok(vec![format!("{}_member({}, {})", self.group_flat_name(obj, r, g), pk, self.id_claim(cust_claim))]);
                }
                Ok(vec![format!("{}.{}_member({}, {})", schema, g.closure, g.col, self.id_claim(cust_claim))])
            }
            Repr::MemberIn(mi) => {
                let name = format!("{}_memberin_{}", self.s.admin_name(), mi.level);
                let mut frag = format!("{}.{}({}, {})", schema, name, self.arg_src_sql(&mi.principal), self.arg_src_sql(&mi.scope));
                if mi.reached_by {
                    let reach = self.memberin_reach_frag(&mi.level, mi.reach_member)?;
                    frag = format!("({frag} AND {reach})");
                }
                Ok(vec![frag])
            }
            Repr::Object(vo) => {
                let call = format!("{}.{}({})", schema, vo.function_name(), vo.col);
                Ok(vec![self.probed(&self.object_probe(obj, vo), call)])
            }
            Repr::Grant(vg) => self.emit_grant_frags(obj, r, vg, access_for(pm.maps()), cust_claim),
            Repr::Role => Ok(self.rls_emit_role(obj, r)),
        }
    }

    fn probed(&self, probe: &str, call: String) -> String {
        if !self.definer_body || probe.is_empty() {
            return call;
        }
        format!("({probe} AND {call})")
    }

    fn object_probe(&self, obj: &Object, vo: &ViaObject) -> String {
        match self.s.object_by_name(&vo.object) {
            None => String::new(),
            Some(other) => format!("EXISTS (SELECT 1 FROM {} hop WHERE hop.{} = {}.{})", other.table, other.pk(), obj.table, vo.col),
        }
    }

    fn rls_emit_role(&self, obj: &Object, r: &Relation) -> Vec<String> {
        if let Some(st) = self.s.subject_by_name(&r.types[0])
            && self.s.is_platform_role_subject(st)
        {
            return vec![format!("{}.{}({})", self.s.definer_schema(), platform_role_fn(st.anchor()), self.id_claim(st.identifies()))];
        }
        let cols: Vec<String> = obj.scoped.iter().map(|l| self.s.scope_col(obj, l)).collect();
        let f = format!("{}_has_{}_role", self.s.admin_name(), obj.name);
        vec![format!("{}.{}({}, {})", self.s.definer_schema(), f, self.id_claim(self.s.admin_identify()), cols.join(", "))]
    }

    fn emit_grant_frags(&self, obj: &Object, r: &Relation, vg: &ViaGrant, access: &str, cust_claim: &str) -> R<Vec<String>> {
        let mut frags = Vec::new();
        for i in 0..r.types.len() {
            let (name, _, _, claim) = self.s.grant_rel_binding(obj, vg, r, i);
            if claim.is_empty() {
                return Err(format!("grant relation {} kind {}: no subject resolves a claim", quote(&r.name), quote(&r.types[i])));
            }
            let mut frag = format!(
                "{}.{}({}, {}, {})",
                self.s.definer_schema(),
                name,
                self.id_claim(&claim),
                format_args!("{}.{}", obj.table, obj.pk()),
                quote_literal(access)
            );
            if !cust_claim.is_empty() && claim != cust_claim {
                frag = format!("({} AND {} IS NULL)", frag, self.claim(cust_claim));
            }
            frags.push(frag);
        }
        Ok(frags)
    }

    #[must_use]
    pub fn group_flat_name(&self, obj: &Object, r: &Relation, g: &ViaGroup) -> String {
        if !g.materialized {
            return String::new();
        }
        format!("{}.{}_{}_flat", self.s.definer_schema(), obj.table, r.name)
    }

    fn external_call_sql(&self, t: &Term) -> R<String> {
        let f = t.external_fn();
        let Some(ext) = self.s.external_by_name(f) else {
            return Err(format!(
                "@external({f}): no `external predicate {f}(...)` declaration — an adopter-supplied predicate must be declared before it can be required"
            ));
        };
        if ext.arg_types.len() != t.external_args().len() {
            return Err(format!("@external({f}): declared with {} argument(s), called with {}", ext.arg_types.len(), t.external_args().len()));
        }
        let args: Vec<String> = t
            .external_args()
            .iter()
            .map(|a| {
                if !a.claim().is_empty() {
                    self.id_claim(a.claim())
                } else if !a.lit().is_empty() {
                    quote_literal(a.lit())
                } else {
                    a.col().to_string()
                }
            })
            .collect();
        Ok(format!("{}.{}({})", self.s.definer_schema(), ext.name, args.join(", ")))
    }

    fn require_leaf_frags(&self, obj: &Object, pm: &Perm, t: &Term, rels: &Rels, cust_claim: &str) -> R<Vec<String>> {
        let b = t.builtin();
        if b == "external" {
            let frag = self.external_call_sql(t).map_err(|e| format!("object {} require {}: {e}", quote(&obj.name), quote(&pm.verb)))?;
            return Ok(vec![frag]);
        }
        if b == "self" {
            return Ok(vec![format!("{} = {}", t.self_col(), self.id_claim(self.s.admin_identify()))]);
        }
        if !t.grant_ref().is_empty() || matches!(b, "scoped" | "public" | "open") {
            return Err(format!(
                "object {} require {}: term {} widens — a `require` compiles to a RESTRICTIVE policy and can only narrow; a term that confers reach belongs in the `permission` line",
                quote(&obj.name),
                quote(&pm.verb),
                t.display()
            ));
        }
        self.emit_term(obj, pm, t, rels, cust_claim)
    }

    fn require_predicate(&self, obj: &Object, pm: &Perm, rq: &Require, cust: Option<&Subject>) -> R<String> {
        let cust_claim = cust.map_or("", demesne_syntax::Subject::identifies);
        let rels = rels_of(obj);
        let frags = self.node_frags_mode(obj, pm, &rq.tree, &rels, cust_claim, true)?;
        if frags.is_empty() {
            return Err(format!(
                "object {} require {}: compiles to no predicate — a RESTRICTIVE policy with an empty predicate denies every write",
                quote(&obj.name),
                quote(&rq.verb)
            ));
        }
        Ok(frags.join(" OR "))
    }

    pub(crate) fn perm_require_sql(&self, obj: &Object, pm: &Perm, cust: Option<&Subject>) -> R<String> {
        match obj.require_for(&pm.verb) {
            None => Ok(String::new()),
            Some(rq) => self.require_predicate(obj, pm, rq, cust),
        }
    }

    pub(crate) fn perm_predicate(&self, obj: &Object, pm: &Perm, cust: Option<&Subject>, virt: &Virtual) -> R<String> {
        let pred = self.rls_predicate(obj, pm, cust, virt)?;
        let req = self.perm_require_sql(obj, pm, cust)?;
        if req.is_empty() {
            return Ok(pred);
        }
        Ok(format!("({pred}) AND ({req})"))
    }

    /// Returns the sorted names of every definer function the compiled policies call.
    ///
    /// # Errors
    ///
    /// Any error from [`Sql::emit_rls`].
    pub fn definer_names(&self) -> Result<Vec<String>, Error> {
        let res = self.emit_rls()?;
        let mut set = BTreeSet::new();
        for p in &res.policies {
            for body in [&p.using, &p.check] {
                set.extend(scan_definers(body, self.s.definer_schema()));
            }
        }
        Ok(set.into_iter().collect())
    }
}

pub(crate) fn composition_probe(obj: &Object, vc: &ViaComposition) -> String {
    if vc.table == obj.table && vc.child_col == obj.pk() {
        return format!("{}.{} IS NOT NULL", obj.table, vc.parent_col);
    }
    let mut conds = vec![format!("hop.{} = {}.{}", vc.child_col, obj.table, obj.pk())];
    if let Some(k) = &vc.kind_col {
        conds.push(format!("hop.{} = {}", k, quote_literal(vc.kind_val.as_deref().unwrap_or(""))));
    }
    conds.push(format!("hop.{} IS NOT NULL", vc.parent_col));
    format!("EXISTS (SELECT 1 FROM {} hop WHERE {})", vc.table, conds.join(" AND "))
}
