use demesne_gocompat::quote;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pos {
    pub line: usize,
}

fn or_empty(s: Option<&str>) -> &str {
    s.unwrap_or("")
}

#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub topology: Option<Topology>,
    pub vocabs: Vec<Vocabulary>,
    pub subjects: Vec<Subject>,
    pub objects: Vec<Object>,
    pub procedures: Vec<Procedures>,
    pub ungoverned: Vec<Ungoverned>,
    pub field_scopes: Vec<FieldScopes>,
    pub role_stores: Vec<RoleStore>,
    pub grants: Vec<Grant>,
    pub templates: Vec<Template>,
    pub externals: Vec<External>,
    pub claims: Option<ClaimsAccessor>,
    pub definer_schema: Option<String>,
    pub table_schema: Option<String>,
    pub identifiers: Option<String>,
}

impl Spec {
    /// Every relation in the spec with the object that declares it, in declaration order.
    pub fn relations(&self) -> impl Iterator<Item = (&Object, &Relation)> {
        self.objects.iter().flat_map(|o| o.relations.iter().map(move |r| (o, r)))
    }

    /// Every leaf term of every permission, with its object and permission, in declaration order.
    pub fn perm_terms(&self) -> impl Iterator<Item = (&Object, &Perm, &Term)> {
        self.objects.iter().flat_map(|o| o.perm_terms().map(move |(pm, t)| (o, pm, t)))
    }

    #[must_use]
    pub fn id_type(&self) -> &str {
        self.identifiers.as_deref().unwrap_or("text")
    }

    #[must_use]
    pub fn id_cast(&self) -> String {
        match self.id_type() {
            "text" => String::new(),
            t => format!("::{t}"),
        }
    }

    #[must_use]
    pub fn definer_schema(&self) -> &str {
        self.definer_schema.as_deref().unwrap_or("auth")
    }

    #[must_use]
    pub fn table_schema(&self) -> &str {
        self.table_schema.as_deref().unwrap_or("public")
    }

    #[must_use]
    pub fn levels(&self) -> &[Level] {
        self.topology.as_ref().map_or(&[], |t| t.levels.as_slice())
    }

    #[must_use]
    pub fn external_by_name(&self, name: &str) -> Option<&External> {
        self.externals.iter().find(|e| e.name == name)
    }
}

#[derive(Debug, Clone)]
pub struct ClaimsAccessor {
    pub setting: String,
    pub cast: String,
    pub role: Option<String>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Grant {
    pub name: String,
    pub level: String,
    pub table: Option<String>,
    pub grantee_col: Option<String>,
    pub level_col: Option<String>,
    pub active_col: Option<String>,
    pub expires_col: Option<String>,
    pub id_col: Option<String>,
    pub granted_by_col: Option<String>,
    pub revoked_by_col: Option<String>,
    pub created_at_col: Option<String>,
    pub verbs: Vec<String>,
    pub extra_cols: Vec<String>,
    pub named: Option<String>,
    pub scopes: Vec<GrantScope>,
    pub claim_key: Option<String>,
    pub claim_value: Option<String>,
    pub pos: Pos,
}

impl Grant {
    #[must_use]
    pub fn confers(&self, op: &str) -> bool {
        self.verbs.is_empty() || self.verbs.iter().any(|v| v == op)
    }

    #[must_use]
    pub fn grant_pk(&self) -> &str {
        self.id_col.as_deref().unwrap_or("id")
    }

    #[must_use]
    pub fn definer_base(&self) -> &str {
        self.named.as_deref().unwrap_or_else(|| self.table())
    }

    #[must_use]
    pub fn table(&self) -> &str {
        or_empty(self.table.as_deref())
    }

    #[must_use]
    pub fn grantee_col(&self) -> &str {
        or_empty(self.grantee_col.as_deref())
    }

    #[must_use]
    pub fn level_col(&self) -> &str {
        or_empty(self.level_col.as_deref())
    }

    #[must_use]
    pub fn claim_key(&self) -> &str {
        or_empty(self.claim_key.as_deref())
    }

    #[must_use]
    pub fn claim_value(&self) -> &str {
        or_empty(self.claim_value.as_deref())
    }

    #[must_use]
    pub fn has_scope(&self, level: &str) -> bool {
        self.scopes.iter().any(|s| s.level == level)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantScope {
    pub level: String,
    pub column: String,
    pub missing: String,
}

#[derive(Debug, Clone, Default)]
pub struct GrantUse {
    pub grant: String,
    pub via: Option<String>,
    pub bound: Option<String>,
    pub unscoped: bool,
    pub ops: Vec<String>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct RoleStore {
    pub name: String,
    pub assignments: Option<String>,
    pub kind_col: Option<String>,
    pub kind_val: Option<String>,
    pub subject_col: Option<String>,
    pub scope_cols: Vec<String>,
    pub plane: Option<String>,
    pub role_col: Option<String>,
    pub roles_table: Option<String>,
    pub roles_id: Option<String>,
    pub key_col: Option<String>,
    pub revoked_col: Option<String>,
    pub perms_col: Option<String>,
    pub id_col: Option<String>,
    pub granted_at_col: Option<String>,
    pub granted_by_col: Option<String>,
    pub revoked_by_col: Option<String>,
    pub extra_cols: Vec<String>,
    pub pos: Pos,
}

impl RoleStore {
    #[must_use]
    pub fn assignment_pk(&self) -> &str {
        self.id_col.as_deref().unwrap_or("id")
    }
}

#[derive(Debug, Clone, Default)]
pub struct Topology {
    pub levels: Vec<Level>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Level {
    pub name: String,
    pub parents: Vec<String>,
    pub is_virtual: bool,
    pub scope_col: Option<String>,
    pub claim_key: Option<String>,
    pub pos: Pos,
}

impl Level {
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }

    #[must_use]
    pub fn scope_column(&self) -> String {
        self.scope_col.clone().unwrap_or_else(|| format!("{}_id", self.name))
    }

    #[must_use]
    pub fn claim_key(&self) -> String {
        self.claim_key.clone().unwrap_or_else(|| format!("{}_id", self.name))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Vocabulary {
    pub name: String,
    pub permissions: Vec<String>,
    pub implications: Vec<Implication>,
    pub presets: Vec<Preset>,
    pub rank: Vec<String>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Implication {
    pub perm: String,
    pub set: Vec<String>,
    pub star: bool,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Preset {
    pub name: String,
    pub level: Option<String>,
    pub set: Vec<String>,
    pub star: bool,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Subject {
    pub name: String,
    pub anchor: Option<String>,
    pub reach: Option<String>,
    pub identifies: Option<String>,
    pub membership: Option<Membership>,
    pub roles: Option<String>,
    pub roles_none: bool,
    pub reach_grant: Option<String>,
    pub binds: Option<String>,
    pub transient: bool,
    pub transient_set: bool,
    pub pos: Pos,
}

impl Subject {
    #[must_use]
    pub fn anchor(&self) -> &str {
        or_empty(self.anchor.as_deref())
    }

    #[must_use]
    pub fn reach(&self) -> &str {
        or_empty(self.reach.as_deref())
    }

    #[must_use]
    pub fn identifies(&self) -> &str {
        or_empty(self.identifies.as_deref())
    }

    #[must_use]
    pub fn roles(&self) -> &str {
        or_empty(self.roles.as_deref())
    }

    #[must_use]
    pub fn reach_grant(&self) -> &str {
        or_empty(self.reach_grant.as_deref())
    }

    #[must_use]
    pub fn binds(&self) -> &str {
        or_empty(self.binds.as_deref())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Membership {
    pub table: String,
    pub id_col: String,
    pub flag_col: String,
    pub active_col: Option<String>,
    pub active_val: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Template {
    pub name: String,
    pub perms: Vec<Perm>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Gate {
    pub verb: String,
    pub relation: String,
    pub perm: String,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct FieldRule {
    pub name: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub column: Option<String>,
    pub pos: Pos,
}

#[derive(Debug, Clone, Default)]
pub struct Object {
    pub name: String,
    pub table: String,
    pub pk: Option<String>,
    pub pk_cols: Vec<String>,
    pub level: Option<String>,
    pub scoped: Vec<String>,
    pub scope_wildcards: Vec<String>,
    pub scope_wildcard_verbs: BTreeMap<String, Vec<String>>,
    pub reach_uses: Vec<GrantUse>,
    pub admits: Vec<Admit>,
    pub exports: Vec<PermissionExport>,
    pub relations: Vec<Relation>,
    pub perms: Vec<Perm>,
    pub requires: Vec<Require>,
    pub gates: Vec<Gate>,
    pub field_principals: Vec<String>,
    pub fields: Vec<FieldRule>,
    pub use_template: Option<String>,
    pub omit: Vec<String>,
    pub track_owner: bool,
    pub track_visibility: bool,
    pub pos: Pos,
}

impl Object {
    /// Every leaf term of this object's permissions, with its permission, in declaration order.
    pub fn perm_terms(&self) -> impl Iterator<Item = (&Perm, &Term)> {
        self.perms.iter().flat_map(|pm| pm.tree.leaves().into_iter().map(move |t| (pm, t)))
    }

    #[must_use]
    pub fn is_level_entity(&self) -> bool {
        self.level.is_some()
    }

    #[must_use]
    pub fn level(&self) -> &str {
        or_empty(self.level.as_deref())
    }

    #[must_use]
    pub fn scope_is_wildcard(&self, level: &str) -> bool {
        self.scope_wildcards.iter().any(|w| w == level)
    }

    #[must_use]
    pub fn scope_is_wildcard_for(&self, level: &str, op: &str) -> bool {
        if !self.scope_is_wildcard(level) {
            return false;
        }
        match self.scope_wildcard_verbs.get(level) {
            Some(verbs) if !verbs.is_empty() => verbs.iter().any(|v| v == op),
            _ => true,
        }
    }

    #[must_use]
    pub fn pk(&self) -> &str {
        self.pk.as_deref().unwrap_or("id")
    }

    #[must_use]
    pub fn point_checkable(&self) -> bool {
        self.pk_cols.is_empty()
    }

    #[must_use]
    pub fn require_for(&self, verb: &str) -> Option<&Require> {
        self.requires.iter().find(|r| r.verb == verb)
    }

    #[must_use]
    pub fn grant_use(&self, grant: &str, op: &str) -> Option<&GrantUse> {
        self.reach_uses.iter().find(|u| u.grant == grant && (u.ops.is_empty() || u.ops.iter().any(|o| o == op)))
    }

    #[must_use]
    pub fn owner_changelog_cols(&self) -> Option<(&str, &str)> {
        self.relations.iter().find_map(|r| match &r.repr {
            Repr::Column(vc) => vc.discrim_col.as_deref().map(|d| (vc.column.as_str(), d)),
            _ => None,
        })
    }

    #[must_use]
    pub fn mode_changelog_col(&self) -> Option<&str> {
        self.perms.iter().find_map(|pm| pm.tree.leaves().into_iter().find_map(|t| t.mode_col()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKind {
    Composition,
    Association,
}

impl RelationKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RelationKind::Composition => "composition",
            RelationKind::Association => "association",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub name: String,
    pub types: Vec<String>,
    pub repr: Repr,
    pub kind: Option<RelationKind>,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repr {
    Column(ViaColumn),
    Edge(ViaEdge),
    Role,
    Composition(ViaComposition),
    Closure(ViaClosure),
    Group(ViaGroup),
    Object(ViaObject),
    MemberIn(ViaMemberIn),
    Grant(ViaGrant),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaColumn {
    pub column: String,
    pub discrim_col: Option<String>,
    pub discrim_val: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaEdge {
    pub table: String,
    pub cols: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaComposition {
    pub table: String,
    pub child_col: String,
    pub parent_col: String,
    pub kind_col: Option<String>,
    pub kind_val: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaClosure {
    pub closure: String,
    pub ancestor_col: String,
    pub descendant_col: String,
    pub base: Option<String>,
    pub base_id: Option<String>,
    pub base_parent: Option<String>,
    pub col: String,
    pub claim: Option<String>,
    pub missing: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaGroup {
    pub closure: String,
    pub group_col: String,
    pub member_col: String,
    pub edge: String,
    pub edge_member: String,
    pub edge_group: String,
    pub col: String,
    pub materialized: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaObject {
    pub object: String,
    pub verb: String,
    pub col: String,
    pub op: Option<String>,
}

impl ViaObject {
    #[must_use]
    pub fn function_name(&self) -> String {
        match &self.op {
            Some(op) => format!("{}_can_{}_for_{}", self.object, self.verb, op),
            None => format!("{}_can_{}", self.object, self.verb),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViaGrant {
    pub table: String,
    pub record_col: String,
    pub kind_col: String,
    pub principal_col: String,
    pub access_col: String,
    pub discrim_col: Option<String>,
    pub discrim_val: Option<String>,
    pub group_kind_val: Option<String>,
    pub group_closure: Option<String>,
    pub group_group_col: Option<String>,
    pub group_member_col: Option<String>,
    pub group_edge: Option<String>,
    pub group_edge_member: Option<String>,
    pub group_edge_group: Option<String>,
    pub tracked: bool,
    pub is_async: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgSrc {
    Claim(String),
    Col(String),
}

impl ArgSrc {
    #[must_use]
    pub fn claim(&self) -> &str {
        match self {
            ArgSrc::Claim(c) => c,
            ArgSrc::Col(_) => "",
        }
    }

    #[must_use]
    pub fn col(&self) -> &str {
        match self {
            ArgSrc::Col(c) => c,
            ArgSrc::Claim(_) => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaMemberIn {
    pub level: String,
    pub principal: ArgSrc,
    pub scope: ArgSrc,
    pub reached_by: bool,
    pub reach_member: bool,
}

#[derive(Debug, Clone)]
pub struct Perm {
    pub verb: String,
    pub tree: PermNode,
    pub layers: Vec<String>,
    pub maps: Option<String>,
    pub guard: Option<Guard>,
    pub self_check: Option<String>,
    pub predicate_only: bool,
    pub blind: bool,
    pub pos: Pos,
}

impl Perm {
    #[must_use]
    pub fn expr(&self) -> Vec<&Term> {
        self.tree.leaves()
    }

    #[must_use]
    pub fn layer_tag(&self) -> String {
        format!("@{}", self.layers.join(","))
    }

    #[must_use]
    pub fn maps(&self) -> &str {
        or_empty(self.maps.as_deref())
    }

    #[must_use]
    pub fn has_layer(&self, layer: &str) -> bool {
        self.layers.iter().any(|l| l == layer)
    }
}

#[derive(Debug, Clone)]
pub enum PermNode {
    Leaf(Term),
    Or(Vec<PermNode>),
    And(Vec<PermNode>),
    Not(Box<PermNode>),
}

impl PermNode {
    #[must_use]
    pub fn op(&self) -> &'static str {
        match self {
            PermNode::Leaf(_) => "leaf",
            PermNode::Or(_) => "or",
            PermNode::And(_) => "and",
            PermNode::Not(_) => "not",
        }
    }

    #[must_use]
    pub fn leaves(&self) -> Vec<&Term> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a Term>) {
        match self {
            PermNode::Leaf(t) => out.push(t),
            PermNode::Or(kids) | PermNode::And(kids) => kids.iter().for_each(|k| k.collect_leaves(out)),
            PermNode::Not(k) => k.collect_leaves(out),
        }
    }

    #[must_use]
    pub fn kids(&self) -> Vec<&PermNode> {
        match self {
            PermNode::Leaf(_) => Vec::new(),
            PermNode::Or(kids) | PermNode::And(kids) => kids.iter().collect(),
            PermNode::Not(k) => vec![k.as_ref()],
        }
    }

    #[must_use]
    pub fn nil() -> PermNode {
        PermNode::Or(Vec::new())
    }

    #[must_use]
    pub fn is_nil(&self) -> bool {
        matches!(self, PermNode::Or(kids) if kids.is_empty())
    }

    #[must_use]
    pub fn term(&self) -> Option<&Term> {
        match self {
            PermNode::Leaf(t) => Some(t),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct External {
    pub name: String,
    pub arg_types: Vec<String>,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalArg {
    Col(String),
    Claim(String),
    Lit(String),
}

impl ExternalArg {
    #[must_use]
    pub fn col(&self) -> &str {
        match self {
            ExternalArg::Col(c) => c,
            _ => "",
        }
    }

    #[must_use]
    pub fn claim(&self) -> &str {
        match self {
            ExternalArg::Claim(c) => c,
            _ => "",
        }
    }

    #[must_use]
    pub fn lit(&self) -> &str {
        match self {
            ExternalArg::Lit(l) => l,
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Require {
    pub verb: String,
    pub tree: PermNode,
    pub pos: Pos,
}

impl Require {
    #[must_use]
    pub fn expr(&self) -> Vec<&Term> {
        self.tree.leaves()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOp {
    Eq,
    Ne,
}

impl GuardOp {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GuardOp::Eq => "=",
            GuardOp::Ne => "<>",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Guard {
    pub col: String,
    pub op: GuardOp,
    pub val: String,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct Term {
    pub kind: TermKind,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermKind {
    Ref { ident: String, walk_verb: Option<String> },
    Mode { col: String, val: String, scope: Option<String> },
    Grant(String),
    Builtin(Builtin),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Builtin {
    Session(Option<String>),
    AppScope(Vec<String>),
    Kind(String),
    Claim { key: String, val: String },
    SelfCol(String),
    Within { level: String, nullable: bool },
    External { func: String, args: Vec<ExternalArg> },
    Holds(String),
    Row { col: String, val: String },
    Other(String),
}

impl Builtin {
    /// Renders the builtin as it is written in a spec, with its arguments.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Builtin::Session(Some(rel)) => format!("@session({rel})"),
            Builtin::AppScope(rels) if !rels.is_empty() => format!("@app_scope(exclude {})", rels.join(", ")),
            Builtin::Kind(v) => format!("@kind({})", quote(v)),
            Builtin::Claim { key, val } => format!("@claim({}, {})", quote(key), quote(val)),
            Builtin::SelfCol(c) => format!("@self({c})"),
            Builtin::Within { level, nullable: true } => format!("@within({level} nullable)"),
            Builtin::Within { level, nullable: false } => format!("@within({level})"),
            Builtin::Holds(p) => format!("@holds({p})"),
            Builtin::External { func, .. } => format!("@external({func})"),
            Builtin::Row { col, val } => format!("@row({col}, {})", quote(val)),
            Builtin::Session(None) | Builtin::AppScope(_) | Builtin::Other(_) => format!("@{}", self.name()),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Builtin::Session(_) => "session",
            Builtin::AppScope(_) => "app_scope",
            Builtin::Kind(_) => "kind",
            Builtin::Claim { .. } => "claim",
            Builtin::SelfCol(_) => "self",
            Builtin::Within { .. } => "within",
            Builtin::External { .. } => "external",
            Builtin::Holds(_) => "holds",
            Builtin::Row { .. } => "row",
            Builtin::Other(name) => name,
        }
    }
}

impl Term {
    fn builtin_ref(&self) -> Option<&Builtin> {
        match &self.kind {
            TermKind::Builtin(b) => Some(b),
            _ => None,
        }
    }

    #[must_use]
    pub fn ident(&self) -> &str {
        match &self.kind {
            TermKind::Ref { ident, .. } => ident,
            _ => "",
        }
    }

    #[must_use]
    pub fn walk_verb(&self) -> &str {
        match &self.kind {
            TermKind::Ref { walk_verb: Some(v), .. } => v,
            _ => "",
        }
    }

    pub fn builtin(&self) -> &str {
        self.builtin_ref().map_or("", Builtin::name)
    }

    #[must_use]
    pub fn session_rel(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Session(Some(r))) => r,
            _ => "",
        }
    }

    #[must_use]
    pub fn exclude_rels(&self) -> &[String] {
        match self.builtin_ref() {
            Some(Builtin::AppScope(rels)) => rels,
            _ => &[],
        }
    }

    #[must_use]
    pub fn mode_col(&self) -> Option<&str> {
        match &self.kind {
            TermKind::Mode { col, .. } => Some(col),
            _ => None,
        }
    }

    #[must_use]
    pub fn mode_val(&self) -> &str {
        match &self.kind {
            TermKind::Mode { val, .. } => val,
            _ => "",
        }
    }

    #[must_use]
    pub fn mode_scope(&self) -> &str {
        match &self.kind {
            TermKind::Mode { scope: Some(s), .. } => s,
            _ => "",
        }
    }

    #[must_use]
    pub fn grant_ref(&self) -> &str {
        match &self.kind {
            TermKind::Grant(g) => g,
            _ => "",
        }
    }

    #[must_use]
    pub fn kind_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Kind(v)) => v,
            _ => "",
        }
    }

    #[must_use]
    pub fn self_col(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::SelfCol(c)) => c,
            _ => "",
        }
    }

    #[must_use]
    pub fn claim_key(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Claim { key, .. }) => key,
            _ => "",
        }
    }

    #[must_use]
    pub fn claim_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Claim { val, .. }) => val,
            _ => "",
        }
    }

    #[must_use]
    pub fn row_col(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Row { col, .. }) => col,
            _ => "",
        }
    }

    #[must_use]
    pub fn row_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Row { val, .. }) => val,
            _ => "",
        }
    }

    #[must_use]
    pub fn within_level(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Within { level, .. }) => level,
            _ => "",
        }
    }

    #[must_use]
    pub fn within_nullable(&self) -> bool {
        matches!(self.builtin_ref(), Some(Builtin::Within { nullable: true, .. }))
    }

    #[must_use]
    pub fn holds_perm(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Holds(p)) => p,
            _ => "",
        }
    }

    #[must_use]
    pub fn external_fn(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::External { func, .. }) => func,
            _ => "",
        }
    }

    #[must_use]
    pub fn external_args(&self) -> &[ExternalArg] {
        match self.builtin_ref() {
            Some(Builtin::External { args, .. }) => args,
            _ => &[],
        }
    }

    /// Renders the term as it is written in a spec, with its arguments.
    #[must_use]
    pub fn display(&self) -> String {
        match &self.kind {
            TermKind::Grant(g) => format!("via grant {g}"),
            TermKind::Builtin(b) => b.display(),
            TermKind::Ref { ident, walk_verb: Some(v) } => format!("{ident}->{v}"),
            TermKind::Ref { ident, walk_verb: None } => ident.clone(),
            TermKind::Mode { col, val, scope: None } => format!("mode {col} = {}", quote(val)),
            TermKind::Mode { col, val, scope: Some(s) } => format!("mode {col} = {} for {s}", quote(val)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Admit {
    pub ops: Vec<String>,
    pub tree: PermNode,
    pub pos: Pos,
}

impl Admit {
    #[must_use]
    pub fn perm(&self, op: &str) -> Perm {
        Perm {
            verb: "admit".to_string(),
            tree: self.tree.clone(),
            layers: vec!["rls".to_string()],
            maps: Some(op.to_string()),
            guard: None,
            self_check: None,
            predicate_only: false,
            blind: false,
            pos: self.pos,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PermissionExport {
    pub verb: String,
    pub name: String,
    pub params: Vec<ExportParameter>,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct ExportParameter {
    pub column: String,
    pub ty: String,
    pub name: Option<String>,
}

impl ExportParameter {
    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("p_{}", self.column))
    }
}

#[derive(Debug, Clone)]
pub struct Procedures {
    pub emit_site: String,
    pub entries: Vec<ProcEntry>,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub proc_: String,
    pub perm: String,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct Ungoverned {
    pub emit_site: String,
    pub entries: Vec<UngovEntry>,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct UngovEntry {
    pub proc_: String,
    pub reason: String,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct FieldScopes {
    pub site: String,
    pub entries: Vec<FieldScopeEntry>,
    pub pos: Pos,
}

#[derive(Debug, Clone)]
pub struct FieldScopeEntry {
    pub field: String,
    pub scope: String,
    pub pos: Pos,
}
