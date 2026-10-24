use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pos {
    pub line: usize,
}

fn or_empty(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
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
    pub fn id_type(&self) -> &str {
        self.identifiers.as_deref().unwrap_or("text")
    }

    pub fn id_cast(&self) -> String {
        match self.id_type() {
            "text" => String::new(),
            t => format!("::{t}"),
        }
    }

    pub fn definer_schema(&self) -> &str {
        self.definer_schema.as_deref().unwrap_or("auth")
    }

    pub fn table_schema(&self) -> &str {
        self.table_schema.as_deref().unwrap_or("public")
    }

    pub fn levels(&self) -> &[Level] {
        self.topology.as_ref().map(|t| t.levels.as_slice()).unwrap_or(&[])
    }

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
    pub fn confers(&self, op: &str) -> bool {
        self.verbs.is_empty() || self.verbs.iter().any(|v| v == op)
    }

    pub fn grant_pk(&self) -> &str {
        self.id_col.as_deref().unwrap_or("id")
    }

    pub fn definer_base(&self) -> &str {
        self.named.as_deref().unwrap_or_else(|| self.table())
    }

    pub fn table(&self) -> &str {
        or_empty(&self.table)
    }

    pub fn grantee_col(&self) -> &str {
        or_empty(&self.grantee_col)
    }

    pub fn level_col(&self) -> &str {
        or_empty(&self.level_col)
    }

    pub fn claim_key(&self) -> &str {
        or_empty(&self.claim_key)
    }

    pub fn claim_value(&self) -> &str {
        or_empty(&self.claim_value)
    }

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
    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }

    pub fn scope_column(&self) -> String {
        self.scope_col.clone().unwrap_or_else(|| format!("{}_id", self.name))
    }

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
    pub fn anchor(&self) -> &str {
        or_empty(&self.anchor)
    }

    pub fn reach(&self) -> &str {
        or_empty(&self.reach)
    }

    pub fn identifies(&self) -> &str {
        or_empty(&self.identifies)
    }

    pub fn roles(&self) -> &str {
        or_empty(&self.roles)
    }

    pub fn reach_grant(&self) -> &str {
        or_empty(&self.reach_grant)
    }

    pub fn binds(&self) -> &str {
        or_empty(&self.binds)
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
    pub fn is_level_entity(&self) -> bool {
        self.level.is_some()
    }

    pub fn level(&self) -> &str {
        or_empty(&self.level)
    }

    pub fn scope_is_wildcard(&self, level: &str) -> bool {
        self.scope_wildcards.iter().any(|w| w == level)
    }

    pub fn scope_is_wildcard_for(&self, level: &str, op: &str) -> bool {
        if !self.scope_is_wildcard(level) {
            return false;
        }
        match self.scope_wildcard_verbs.get(level) {
            Some(verbs) if !verbs.is_empty() => verbs.iter().any(|v| v == op),
            _ => true,
        }
    }

    pub fn pk(&self) -> &str {
        self.pk.as_deref().unwrap_or("id")
    }

    pub fn point_checkable(&self) -> bool {
        self.pk_cols.is_empty()
    }

    pub fn require_for(&self, verb: &str) -> Option<&Require> {
        self.requires.iter().find(|r| r.verb == verb)
    }

    pub fn grant_use(&self, grant: &str, op: &str) -> Option<&GrantUse> {
        self.reach_uses
            .iter()
            .find(|u| u.grant == grant && (u.ops.is_empty() || u.ops.iter().any(|o| o == op)))
    }

    pub fn owner_changelog_cols(&self) -> Option<(&str, &str)> {
        self.relations.iter().find_map(|r| match &r.repr {
            Repr::Column(vc) => vc.discrim_col.as_deref().map(|d| (vc.column.as_str(), d)),
            _ => None,
        })
    }

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
    pub fn claim(&self) -> &str {
        match self {
            ArgSrc::Claim(c) => c,
            ArgSrc::Col(_) => "",
        }
    }

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
    pub pos: Pos,
}

impl Perm {
    pub fn expr(&self) -> Vec<&Term> {
        self.tree.leaves()
    }

    pub fn layer_tag(&self) -> String {
        format!("@{}", self.layers.join(","))
    }

    pub fn maps(&self) -> &str {
        or_empty(&self.maps)
    }

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
    pub fn op(&self) -> &'static str {
        match self {
            PermNode::Leaf(_) => "leaf",
            PermNode::Or(_) => "or",
            PermNode::And(_) => "and",
            PermNode::Not(_) => "not",
        }
    }

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

    pub fn kids(&self) -> Vec<&PermNode> {
        match self {
            PermNode::Leaf(_) => Vec::new(),
            PermNode::Or(kids) | PermNode::And(kids) => kids.iter().collect(),
            PermNode::Not(k) => vec![k.as_ref()],
        }
    }

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
    pub fn col(&self) -> &str {
        match self {
            ExternalArg::Col(c) => c,
            _ => "",
        }
    }

    pub fn claim(&self) -> &str {
        match self {
            ExternalArg::Claim(c) => c,
            _ => "",
        }
    }

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

    pub fn ident(&self) -> &str {
        match &self.kind {
            TermKind::Ref { ident, .. } => ident,
            _ => "",
        }
    }

    pub fn walk_verb(&self) -> &str {
        match &self.kind {
            TermKind::Ref { walk_verb: Some(v), .. } => v,
            _ => "",
        }
    }

    pub fn builtin(&self) -> &str {
        self.builtin_ref().map(Builtin::name).unwrap_or("")
    }

    pub fn session_rel(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Session(Some(r))) => r,
            _ => "",
        }
    }

    pub fn exclude_rels(&self) -> &[String] {
        match self.builtin_ref() {
            Some(Builtin::AppScope(rels)) => rels,
            _ => &[],
        }
    }

    pub fn mode_col(&self) -> Option<&str> {
        match &self.kind {
            TermKind::Mode { col, .. } => Some(col),
            _ => None,
        }
    }

    pub fn mode_val(&self) -> &str {
        match &self.kind {
            TermKind::Mode { val, .. } => val,
            _ => "",
        }
    }

    pub fn mode_scope(&self) -> &str {
        match &self.kind {
            TermKind::Mode { scope: Some(s), .. } => s,
            _ => "",
        }
    }

    pub fn grant_ref(&self) -> &str {
        match &self.kind {
            TermKind::Grant(g) => g,
            _ => "",
        }
    }

    pub fn kind_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Kind(v)) => v,
            _ => "",
        }
    }

    pub fn self_col(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::SelfCol(c)) => c,
            _ => "",
        }
    }

    pub fn claim_key(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Claim { key, .. }) => key,
            _ => "",
        }
    }

    pub fn claim_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Claim { val, .. }) => val,
            _ => "",
        }
    }

    pub fn row_col(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Row { col, .. }) => col,
            _ => "",
        }
    }

    pub fn row_val(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Row { val, .. }) => val,
            _ => "",
        }
    }

    pub fn within_level(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Within { level, .. }) => level,
            _ => "",
        }
    }

    pub fn within_nullable(&self) -> bool {
        matches!(self.builtin_ref(), Some(Builtin::Within { nullable: true, .. }))
    }

    pub fn holds_perm(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::Holds(p)) => p,
            _ => "",
        }
    }

    pub fn external_fn(&self) -> &str {
        match self.builtin_ref() {
            Some(Builtin::External { func, .. }) => func,
            _ => "",
        }
    }

    pub fn external_args(&self) -> &[ExternalArg] {
        match self.builtin_ref() {
            Some(Builtin::External { args, .. }) => args,
            _ => &[],
        }
    }

    pub fn display(&self) -> String {
        match &self.kind {
            TermKind::Grant(g) => format!("via grant {g}"),
            TermKind::Builtin(b) => match b {
                Builtin::SelfCol(c) => format!("@self({c})"),
                Builtin::Within { level, nullable: true } => format!("@within({level} nullable)"),
                Builtin::Within { level, nullable: false } => format!("@within({level})"),
                Builtin::Holds(p) => format!("@holds({p})"),
                Builtin::External { func, .. } => format!("@external({func})"),
                Builtin::Row { col, val } => format!("@row({col}, \"{val}\")"),
                other => format!("@{}", other.name()),
            },
            TermKind::Ref { ident, walk_verb: Some(v) } => format!("{ident}->{v}"),
            TermKind::Ref { ident, walk_verb: None } => ident.clone(),
            TermKind::Mode { .. } => String::new(),
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
    pub fn perm(&self, op: &str) -> Perm {
        Perm {
            verb: "admit".to_string(),
            tree: self.tree.clone(),
            layers: vec!["rls".to_string()],
            maps: Some(op.to_string()),
            guard: None,
            self_check: None,
            predicate_only: false,
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
