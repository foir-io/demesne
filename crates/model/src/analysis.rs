use crate::topology;
use crate::vocab::to_runtime;
use demesne_gocompat::quote;
use demesne_runtime::{ClaimEntry, Session};
use demesne_syntax::{Grant, Level, Object, Perm, PermNode, Pos, Relation, Repr, RoleStore, Spec, Subject, Term, TermKind, ViaGrant, Vocabulary};
use std::collections::{BTreeMap, HashMap};

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

#[derive(Debug)]
pub struct Principal {
    pub subject: String,
    pub id: String,
    pub scopes: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum ReachGrantRef<'a> {
    Level(&'a Grant),
    Row(&'a ViaGrant),
}

impl ReachGrantRef<'_> {
    #[must_use]
    pub fn edge_table(&self) -> &str {
        match self {
            ReachGrantRef::Level(g) => g.table(),
            ReachGrantRef::Row(vg) => &vg.table,
        }
    }

    #[must_use]
    pub fn grantee_column(&self) -> &str {
        match self {
            ReachGrantRef::Level(g) => g.grantee_col(),
            ReachGrantRef::Row(vg) => &vg.principal_col,
        }
    }

    #[must_use]
    pub fn granularity(&self) -> &'static str {
        match self {
            ReachGrantRef::Level(_) => "level",
            ReachGrantRef::Row(_) => "row",
        }
    }
}

pub trait SpecExt {
    fn spec(&self) -> &Spec;

    fn subject_by_name(&self, name: &str) -> Option<&Subject> {
        self.spec().subjects.iter().find(|s| s.name == name)
    }

    fn object_by_name(&self, name: &str) -> Option<&Object> {
        self.spec().objects.iter().find(|o| o.name == name)
    }

    fn grant_by_name(&self, name: &str) -> Option<&Grant> {
        self.spec().grants.iter().find(|g| g.name == name)
    }

    fn vocab_by_name(&self, name: &str) -> Option<&Vocabulary> {
        self.spec().vocabs.iter().find(|v| v.name == name)
    }

    fn level_by_name(&self, name: &str) -> Option<&Level> {
        topology::level_by_name(self.spec(), name)
    }

    fn level_is_virtual(&self, name: &str) -> bool {
        self.level_by_name(name).is_some_and(|l| l.is_virtual)
    }

    fn default_role_store(&self) -> Option<&RoleStore> {
        self.spec().role_stores.first()
    }

    fn owner_subject(&self, leaf_level: &str) -> Option<&Subject> {
        self.spec().subjects.iter().find(|s| s.binds() == "owner" && s.anchor() == leaf_level)
    }

    fn admin_identify(&self) -> &str {
        self.spec().subjects.iter().find(|s| s.binds() == "admin").map_or("sub", demesne_syntax::Subject::identifies)
    }

    fn admin_name(&self) -> &str {
        self.spec().subjects.iter().find(|s| s.binds() == "admin").map_or("admin", |s| s.name.as_str())
    }

    fn scope_col(&self, obj: &Object, lvl: &str) -> String {
        if obj.is_level_entity() && lvl == obj.level() {
            return obj.pk().to_string();
        }
        match self.level_by_name(lvl) {
            Some(l) => l.scope_column(),
            None => format!("{lvl}_id"),
        }
    }

    fn claim_key_for_level(&self, level: &str) -> String {
        match self.level_by_name(level) {
            Some(l) => l.claim_key(),
            None => format!("{level}_id"),
        }
    }

    fn is_platform_role_subject(&self, sub: &Subject) -> bool {
        !sub.roles().is_empty() && !sub.roles_none && sub.membership.is_none() && sub.reach() != "grant" && self.level_is_virtual(sub.anchor())
    }

    fn preset_level_map(&self) -> HashMap<String, Vec<String>> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for p in self.spec().vocabs.iter().flat_map(|v| &v.presets) {
            if let Some(level) = &p.level {
                out.entry(level.clone()).or_default().push(p.name.clone());
            }
        }
        out
    }

    fn rolestore_plane_depth(&self, rs: &RoleStore) -> usize {
        let Some(plane) = rs.plane.as_deref() else { return rs.scope_cols.len() };
        let Ok(chain) = topology::chain(self.spec()) else { return 0 };
        let mut depth = 0;
        for l in chain {
            if !l.is_virtual {
                depth += 1;
            }
            if l.name == plane {
                return depth.min(rs.scope_cols.len());
            }
        }
        0
    }

    fn is_default_role_store(&self, rs: &RoleStore) -> bool {
        self.spec().role_stores.first().is_some_and(|first| std::ptr::eq(first, rs))
    }

    fn holds_perm_fn(&self, rs: &RoleStore) -> String {
        if self.is_default_role_store(rs) { format!("{}_has_perm", self.admin_name()) } else { format!("{}_has_perm", rs.name) }
    }

    fn perm_implied_by_fn(&self, rs: &RoleStore) -> String {
        if self.is_default_role_store(rs) { format!("{}_perm_implied_by", self.admin_name()) } else { format!("{}_perm_implied_by", rs.name) }
    }

    /// Returns the vocabulary backing rolestore `rs`: the vocabulary of the same name, else the one a `binds admin` subject names in `roles`.
    ///
    /// # Errors
    ///
    /// Neither vocabulary exists.
    fn rolestore_vocab(&self, rs: &RoleStore) -> Result<&Vocabulary, String> {
        if let Some(v) = self.vocab_by_name(&rs.name) {
            return Ok(v);
        }
        for sub in &self.spec().subjects {
            if sub.binds() == "admin"
                && !sub.roles().is_empty()
                && let Some(v) = self.vocab_by_name(sub.roles())
            {
                return Ok(v);
            }
        }
        Err(format!(
            "HoldsResolver: rolestore {} has no vocabulary (expected a vocabulary named {}, or a `binds admin` subject naming one via `roles`)",
            quote(&rs.name),
            quote(&rs.name)
        ))
    }

    /// Returns the rolestore that a `holds` check on `perm` reads.
    ///
    /// # Errors
    ///
    /// The spec declares no rolestore. Or it declares several and `perm` belongs to no rolestore-backed vocabulary, to more than one, or to a vocabulary backing several rolestores.
    fn holds_role_store(&self, perm: &str) -> Result<&RoleStore, String> {
        let s = self.spec();
        match s.role_stores.len() {
            0 => return Err("the spec declares no rolestore".into()),
            1 => return Ok(&s.role_stores[0]),
            _ => {}
        }
        let declaring: Vec<&Vocabulary> = s.vocabs.iter().filter(|v| v.permissions.iter().any(|p| p == perm)).collect();
        if declaring.is_empty() {
            return Err(format!("permission {} is declared by no vocabulary, so it names no rolestore", quote(perm)));
        }
        let mut owners: Vec<(&Vocabulary, Vec<&RoleStore>)> = Vec::new();
        for v in &declaring {
            let matched: Vec<&RoleStore> = s.role_stores.iter().filter(|rs| self.rolestore_vocab(rs).is_ok_and(|rv| std::ptr::eq(rv, *v))).collect();
            if !matched.is_empty() {
                owners.push((v, matched));
            }
        }
        match owners.len() {
            0 => {
                return Err(format!("permission {} belongs to vocabulary {}, which backs no rolestore", quote(perm), quote(&declaring[0].name)));
            }
            1 => {}
            _ => {
                let mut names: Vec<&str> = owners.iter().map(|(v, _)| v.name.as_str()).collect();
                names.sort_unstable();
                return Err(format!(
                    "permission {} is declared by more than one vocabulary that backs a rolestore ({}), so it names no single rolestore — a permission belongs to exactly one rolestore-backed vocabulary",
                    quote(perm),
                    names.join(", ")
                ));
            }
        }
        let (v, matched) = &owners[0];
        if matched.len() > 1 {
            let mut names: Vec<&str> = matched.iter().map(|rs| rs.name.as_str()).collect();
            names.sort_unstable();
            return Err(format!(
                "permission {} belongs to vocabulary {}, which backs more than one rolestore ({})",
                quote(perm),
                quote(&v.name),
                names.join(", ")
            ));
        }
        Ok(matched[0])
    }

    /// Returns every claim key a session may carry, sorted, with the level or subjects that use it.
    ///
    /// # Errors
    ///
    /// The topology has no single root, or a level is unreachable from it.
    fn claims_contract_entries(&self) -> Result<Vec<ClaimEntry>, String> {
        let chain = topology::non_virtual_chain(self.spec())?;
        let mut by_key: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        for l in chain {
            by_key.entry(l.claim_key()).or_default().0.clone_from(&l.name);
        }
        for sub in &self.spec().subjects {
            if let Some(id) = &sub.identifies {
                by_key.entry(id.clone()).or_default().1.push(sub.name.clone());
            }
        }
        Ok(by_key
            .into_iter()
            .map(|(key, (level, mut subjects))| {
                subjects.sort();
                ClaimEntry { key: demesne_runtime::owned(key), level: demesne_runtime::owned(level), subjects: demesne_runtime::owned_list(subjects) }
            })
            .collect())
    }

    /// Returns every claim key a session may carry, sorted.
    ///
    /// # Errors
    ///
    /// The topology has no single root, or a level is unreachable from it.
    fn claims_contract(&self) -> Result<Vec<String>, String> {
        Ok(self.claims_contract_entries()?.into_iter().map(|e| e.key.into_owned()).collect())
    }

    /// Returns the scope claim keys a subject's anchor pins, and whether the anchor is virtual.
    ///
    /// # Errors
    ///
    /// The anchor is not a level, or it has more than one ancestor path.
    fn pinned_columns(&self, sub: &Subject) -> Result<(Vec<String>, bool), String> {
        let path = topology::ancestor_path(self.spec(), sub.anchor())
            .map_err(|e| format!("line {}: subject {} anchor {}: {e}", sub.pos.line, quote(&sub.name), quote(sub.anchor())))?;
        let virtual_anchor = path.last().is_some_and(|l| l.is_virtual);
        let cols = path.iter().filter(|l| !l.is_virtual).map(|l| l.claim_key()).collect();
        Ok((cols, virtual_anchor))
    }

    /// Returns the scope claim keys below a `reach descendants` subject's anchor; other reaches have none.
    ///
    /// # Errors
    ///
    /// The topology has no single root, or a level is unreachable from it.
    fn free_columns(&self, sub: &Subject) -> Result<Vec<String>, String> {
        if sub.reach() != "descendants" {
            return Ok(Vec::new());
        }
        let desc = topology::descendants(self.spec(), sub.anchor()).map_err(|e| format!("subject {}: {e}", quote(&sub.name)))?;
        Ok(desc.iter().filter(|l| !l.is_virtual).map(|l| l.claim_key()).collect())
    }

    fn session(&self) -> Session {
        let s = self.spec();
        let mut out = Session::default();
        if let Some(c) = &s.claims {
            out.setting = demesne_runtime::owned(c.setting.clone());
            out.cast = demesne_runtime::owned(c.cast.clone());
            if let Some(role) = &c.role {
                out.role = demesne_runtime::owned(role.clone());
            }
        }
        out
    }

    /// Builds the claim values that identify principal `p`: its subject's identity key and its scope ids.
    ///
    /// # Errors
    ///
    /// An unknown subject, an id for a subject without `identifies`, or a scope on an unknown or virtual level.
    fn build_claims(&self, p: &Principal) -> Result<BTreeMap<String, String>, String> {
        let Some(sub) = self.subject_by_name(&p.subject) else {
            return Err(format!("BuildClaims: no subject {} in the spec", quote(&p.subject)));
        };
        let mut values = BTreeMap::new();
        if !p.id.is_empty() {
            let Some(id) = &sub.identifies else {
                return Err(format!("BuildClaims: subject {} has no identity key (`identifies`) but an id was supplied", quote(&p.subject)));
            };
            values.insert(id.clone(), p.id.clone());
        }
        for (name, val) in &p.scopes {
            let Some(l) = self.level_by_name(name) else {
                return Err(format!("BuildClaims: subject {} presents a scope for unknown level {}", quote(&p.subject), quote(name)));
            };
            if l.is_virtual {
                return Err(format!("BuildClaims: level {} is virtual (no scope claim) — it cannot carry a scope id", quote(name)));
            }
            values.insert(l.claim_key(), val.clone());
        }
        Ok(values)
    }

    /// Mints a claims JSON object from `values`, checked against this spec's claims contract.
    ///
    /// # Errors
    ///
    /// The contract cannot be built, or `values` holds a key outside it.
    fn mint_claims(&self, values: &BTreeMap<String, String>) -> Result<String, String> {
        let contract = self.claims_contract()?;
        demesne_runtime::mint_claims_values(&contract, values).map_err(|e| e.to_string())
    }

    /// Mints the claims JSON object that identifies principal `p`.
    ///
    /// # Errors
    ///
    /// Any error from [`SpecExt::build_claims`] or [`SpecExt::mint_claims`].
    fn mint_claims_for(&self, p: &Principal) -> Result<String, String> {
        let values = self.build_claims(p)?;
        self.mint_claims(&values)
    }

    /// Returns the SQL that asks whether one row of `object`, keyed by `$1`, is visible.
    ///
    /// # Errors
    ///
    /// No such object, or the object has a composite primary key.
    fn point_check_sql(&self, object: &str) -> Result<String, String> {
        match self.object_by_name(object) {
            Some(o) if !o.point_checkable() => Err(format!(
                "PointCheckSQL: object {} has a composite primary key ({}) — no single-column row identity to point-check",
                quote(object),
                demesne_gocompat::fmt_slice(&o.pk_cols)
            )),
            Some(o) => Ok(format!("SELECT EXISTS (SELECT 1 FROM {} WHERE {} = $1)", o.table, o.pk())),
            None => Err(format!("PointCheckSQL: no object {} in the spec", quote(object))),
        }
    }

    fn grant_reached_by_subject(&self, name: &str) -> bool {
        self.spec().subjects.iter().any(|s| s.reach() == "grant" && s.reach_grant() == name)
    }

    fn grant_selected_as_via(&self, name: &str) -> bool {
        self.spec().objects.iter().any(|o| o.reach_uses.iter().any(|u| u.via.as_deref() == Some(name)))
    }

    fn level_on_object_path(&self, obj: &Object, level: &str) -> bool {
        contains(&obj.scoped, level)
    }

    fn enumerated_grant<'a>(&'a self, obj: &Object, g: &'a Grant) -> Option<&'a Grant> {
        if g.claim_key.is_some() || !self.level_on_object_path(obj, &g.level) {
            return None;
        }
        if !self.grant_reached_by_subject(&g.name) && self.grant_selected_as_via(&g.name) {
            return None;
        }
        if let Some(u) = obj.grant_use(&g.name, "select")
            && let Some(via) = &u.via
        {
            return self.grant_by_name(via);
        }
        Some(g)
    }

    fn level_descends_from(&self, level: &str, ancestor: &str) -> bool {
        if level == ancestor {
            return false;
        }
        let Ok(paths) = topology::ancestor_paths(self.spec(), level) else { return false };
        paths.iter().any(|p| p.iter().any(|l| l.name == ancestor))
    }

    fn store_descriptors(&self, table: &str) -> Vec<&Object> {
        self.spec().objects.iter().filter(|o| object_grant_edge(o).is_some_and(|e| e.table == table)).collect()
    }

    fn grant_rel_binding(&self, o: &Object, vg: &ViaGrant, r: &Relation, i: usize) -> (String, String, String, String) {
        let kind = r.types[i].clone();
        let param = kind.clone();
        let claim = self.subject_by_name(&kind).map(|s| s.identifies().to_string()).unwrap_or_default();
        let base = grant_rel_definer_base(o, vg);
        let name = if i == 0 { base } else { format!("{base}_{kind}") };
        (name, kind, param, claim)
    }

    fn reach_grants(&self) -> Vec<ReachGrantRef<'_>> {
        let s = self.spec();
        let mut out: Vec<ReachGrantRef> = s.grants.iter().filter(|g| g.claim_key.is_none()).map(ReachGrantRef::Level).collect();
        for o in &s.objects {
            if let Some((_, vg)) = grant_relation(o) {
                out.push(ReachGrantRef::Row(vg));
            }
        }
        out
    }

    fn async_index_base(&self, obj_table: &str, rel_name: &str) -> String {
        format!("{}.{}_{}_async", self.spec().definer_schema(), obj_table, rel_name)
    }

    fn has_async(&self) -> bool {
        self.spec().objects.iter().any(|o| o.relations.iter().any(relation_is_async))
    }

    fn async_surface_tokens(&self) -> Vec<String> {
        let mut toks = Vec::new();
        for (o, r) in self.spec().relations() {
            if relation_is_async(r) {
                toks.push(self.async_index_base(&o.table, &r.name));
            }
        }
        toks
    }

    fn transient_set(&self, r: Option<&Relation>) -> bool {
        let Some(r) = r else { return false };
        let Some(first) = r.types.first() else { return false };
        self.subject_by_name(first).is_some_and(|st| st.transient_set)
    }

    fn relation_claim<'a>(&'a self, r: Option<&Relation>, fallback: &'a str) -> &'a str {
        if let Some(r) = r
            && let Some(first) = r.types.first()
            && let Some(sub) = self.subject_by_name(first)
            && !sub.identifies().is_empty()
        {
            return sub.identifies();
        }
        fallback
    }

    fn object_references_staff(&self, obj: &Object) -> bool {
        obj.relations
            .iter()
            .any(|r| matches!(r.repr, Repr::Role) && r.types.first().and_then(|t| self.subject_by_name(t)).is_some_and(|st| self.is_platform_role_subject(st)))
    }

    fn select_uses_app_scope(&self, obj: &Object) -> bool {
        obj.perms.iter().any(|pm| pm.maps() == "select" && pm.tree.leaves().iter().any(|t| t.builtin() == "app_scope"))
    }

    fn owner_principal_name(&self, obj: &Object) -> String {
        for r in &obj.relations {
            if r.name == "owner"
                && let Some(first) = r.types.first()
                && matches!(r.repr, Repr::Column(_))
            {
                return first.clone();
            }
        }
        if let Some(sub) = obj.scoped.last().and_then(|leaf| self.owner_subject(leaf)) {
            return sub.name.clone();
        }
        "principal".into()
    }

    fn uses_holds(&self) -> bool {
        self.spec().objects.iter().any(|o| o.perms.iter().any(|pm| pm.tree.leaves().iter().any(|t| t.builtin() == "holds")))
    }

    fn emission_references_pk(&self, o: &Object) -> bool {
        if o.perms.iter().any(|pm| pm.has_layer("kernel")) {
            return true;
        }
        if o.relations.iter().any(|r| matches!(r.repr, Repr::Grant(_) | Repr::Edge(_) | Repr::Composition(_))) {
            return true;
        }
        self.spec().objects.iter().any(|other| other.relations.iter().any(|r| matches!(&r.repr, Repr::Object(vo) if vo.object == o.name)))
    }

    fn runtime_vocab(&self, v: &Vocabulary) -> demesne_runtime::Vocabulary {
        to_runtime(v)
    }
}

impl SpecExt for Spec {
    fn spec(&self) -> &Spec {
        self
    }
}
