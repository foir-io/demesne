use crate::analysis::{SpecExt, contains};
use crate::error::{Error, refuse_any};
use demesne_gocompat::quote;
use demesne_syntax::{ExternalArg, Finding, Grant, Object, Perm, Relation, Repr, RoleStore, Spec, Subject, Term};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKey {
    pub table: String,
    pub column: String,
    pub ref_table: String,
    pub ref_column: String,
}

#[derive(Debug, Clone, Default)]
pub struct Schema {
    tables: HashMap<String, HashMap<String, Column>>,
    fks: Vec<ForeignKey>,
}

impl Schema {
    #[must_use]
    pub fn new() -> Self {
        Schema::default()
    }

    pub fn add_column(&mut self, table: &str, name: &str, data_type: &str, nullable: bool) {
        self.tables
            .entry(table.to_string())
            .or_default()
            .insert(name.to_string(), Column { name: name.to_string(), data_type: data_type.to_string(), nullable });
    }

    pub fn add_foreign_key(&mut self, table: &str, column: &str, ref_table: &str, ref_column: &str) {
        self.fks.push(ForeignKey { table: table.into(), column: column.into(), ref_table: ref_table.into(), ref_column: ref_column.into() });
    }

    #[must_use]
    pub fn has_table(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    #[must_use]
    pub fn tables(&self) -> Vec<String> {
        let mut out: Vec<String> = self.tables.keys().cloned().collect();
        out.sort();
        out
    }

    #[must_use]
    pub fn table_columns(&self, table: &str) -> Vec<&Column> {
        let mut cols: Vec<&Column> = self.tables.get(table).map(|m| m.values().collect()).unwrap_or_default();
        cols.sort_by(|a, b| a.name.cmp(&b.name));
        cols
    }

    #[must_use]
    pub fn foreign_keys(&self) -> &[ForeignKey] {
        &self.fks
    }

    #[must_use]
    pub fn column(&self, table: &str, col: &str) -> Option<&Column> {
        self.tables.get(table)?.get(col)
    }

    #[must_use]
    pub fn has_column(&self, table: &str, col: &str) -> bool {
        self.column(table, col).is_some()
    }
}

pub(crate) struct Binder<'a> {
    pub columns: Option<BTreeMap<String, BTreeSet<String>>>,
    pub sc: Option<&'a Schema>,
    pub errs: Vec<String>,
}

impl Binder<'_> {
    fn req_table(&mut self, table: &str, ctx: &str) -> bool {
        if self.columns.is_some() {
            return true;
        }
        if !self.sc.expect("a binder without a column map binds against a schema").has_table(table) {
            self.errs.push(format!("{ctx}: table {} not found in the database", quote(table)));
            return false;
        }
        true
    }

    pub(crate) fn req_col(&mut self, table: &str, col: &str, ctx: &str) {
        if let Some(cols) = &mut self.columns {
            cols.entry(table.to_string()).or_default().insert(col.to_string());
            return;
        }
        let sc = self.sc.expect("a binder without a column map binds against a schema");
        if !sc.has_table(table) {
            self.errs.push(format!("{ctx}: table {} (for column {}) not found in the database", quote(table), quote(col)));
            return;
        }
        if !sc.has_column(table, col) {
            self.errs.push(format!("{ctx}: table {} has no column {}", quote(table), quote(col)));
        }
    }
}

fn or(o: Option<&str>) -> &str {
    o.unwrap_or("")
}

pub(crate) fn check_object_refs(s: &Spec, b: &mut Binder, o: &Object) {
    let oc = format!("object {}", o.name);
    if !b.req_table(&o.table, &oc) {
        return;
    }
    if s.emission_references_pk(o) {
        b.req_col(&o.table, o.pk(), &format!("{oc} pk"));
    }
    for lvl in &o.scoped {
        if s.level_is_virtual(lvl) {
            continue;
        }
        b.req_col(&o.table, &s.scope_col(o, lvl), &format!("{oc} scope"));
    }
    for u in &o.reach_uses {
        if let Some(bound) = &u.bound {
            b.req_col(&o.table, &s.scope_col(o, bound), &format!("{oc} reach bound"));
        }
    }
    for r in &o.relations {
        check_relation_refs(b, o, r);
    }
    for pm in &o.perms {
        if let Some(sc) = &pm.self_check {
            b.req_col(&o.table, sc, &format!("{oc} selfcheck"));
        }
        for t in pm.tree.leaves() {
            if let Some(m) = t.mode_col() {
                b.req_col(&o.table, m, &format!("{oc} mode term"));
            }
            if !t.self_col().is_empty() {
                b.req_col(&o.table, t.self_col(), &format!("{oc} @self term"));
            }
            if !t.row_col().is_empty() {
                b.req_col(&o.table, t.row_col(), &format!("{oc} @row term"));
            }
            if t.builtin() == "within" && !t.within_level().is_empty() {
                b.req_col(&o.table, &s.scope_col(o, t.within_level()), &format!("{oc} @within term"));
            }
        }
    }
}

fn check_relation_refs(b: &mut Binder, o: &Object, r: &Relation) {
    let rc = format!("object {} relation {}", o.name, quote(&r.name));
    match &r.repr {
        Repr::Column(vc) => {
            b.req_col(&o.table, &vc.column, &rc);
            if let Some(d) = &vc.discrim_col {
                b.req_col(&o.table, d, &format!("{rc} kind"));
            }
        }
        Repr::Edge(e) => {
            if b.req_table(&e.table, &rc) {
                for c in &e.cols {
                    b.req_col(&e.table, c, &rc);
                }
            }
        }
        Repr::Composition(vc) => {
            if b.req_table(&vc.table, &rc) {
                b.req_col(&vc.table, &vc.child_col, &rc);
                b.req_col(&vc.table, &vc.parent_col, &rc);
                if let Some(k) = &vc.kind_col {
                    b.req_col(&vc.table, k, &format!("{rc} kind"));
                }
            }
        }
        Repr::Closure(c) => {
            b.req_col(&o.table, &c.col, &rc);
            if b.req_table(&c.closure, &rc) {
                b.req_col(&c.closure, &c.ancestor_col, &rc);
                b.req_col(&c.closure, &c.descendant_col, &rc);
            }
            if let Some(base) = &c.base
                && b.req_table(base, &rc)
            {
                b.req_col(base, or(c.base_id.as_deref()), &rc);
                b.req_col(base, or(c.base_parent.as_deref()), &rc);
            }
        }
        Repr::Group(g) => {
            b.req_col(&o.table, &g.col, &rc);
            if b.req_table(&g.closure, &rc) {
                b.req_col(&g.closure, &g.group_col, &rc);
                b.req_col(&g.closure, &g.member_col, &rc);
            }
            if b.req_table(&g.edge, &rc) {
                b.req_col(&g.edge, &g.edge_member, &rc);
                b.req_col(&g.edge, &g.edge_group, &rc);
            }
        }
        Repr::Object(vo) => b.req_col(&o.table, &vo.col, &rc),
        Repr::Grant(g) => {
            if b.req_table(&g.table, &rc) {
                let mut cols = vec![&g.record_col, &g.kind_col, &g.principal_col, &g.access_col];
                if let Some(d) = &g.discrim_col {
                    cols.push(d);
                }
                for c in cols {
                    b.req_col(&g.table, c, &rc);
                }
            }
        }
        Repr::MemberIn(mi) => {
            if !mi.principal.col().is_empty() {
                b.req_col(&o.table, mi.principal.col(), &rc);
            }
            if !mi.scope.col().is_empty() {
                b.req_col(&o.table, mi.scope.col(), &rc);
            }
        }
        Repr::Role => {}
    }
}

fn is_array_data_type(dt: &str) -> bool {
    let up = dt.to_uppercase();
    up.contains("ARRAY") || up.ends_with("[]") || dt.starts_with('_')
}

fn check_role_store_refs(s: &Spec, b: &mut Binder, rs: &RoleStore) {
    let rc = format!("rolestore {}", rs.name);
    if b.req_table(or(rs.assignments.as_deref()), &rc) {
        let mut cols: Vec<&str> = vec![or(rs.subject_col.as_deref()), or(rs.role_col.as_deref())];
        if let Some(k) = &rs.kind_col {
            cols.push(k);
        }
        if let Some(r) = &rs.revoked_col {
            cols.push(r);
        }
        cols.extend(rs.scope_cols.iter().map(String::as_str));
        for c in cols {
            b.req_col(or(rs.assignments.as_deref()), c, &rc);
        }
    }
    let rrc = format!("{rc} roles");
    if b.req_table(or(rs.roles_table.as_deref()), &rrc) {
        b.req_col(or(rs.roles_table.as_deref()), or(rs.roles_id.as_deref()), &rrc);
        b.req_col(or(rs.roles_table.as_deref()), or(rs.key_col.as_deref()), &rrc);
        if let Some(pc) = &rs.perms_col {
            b.req_col(or(rs.roles_table.as_deref()), pc, &rrc);
            if s.uses_holds()
                && let Some(col) = b.sc.and_then(|sc| sc.column(or(rs.roles_table.as_deref()), pc))
                && !is_array_data_type(&col.data_type)
            {
                b.errs.push(format!(
                    "{rrc}: column {} has type {}, not an array — @holds compiles to `p_perm = ANY({})`, which needs a text[] (or other array) column",
                    quote(pc),
                    quote(&col.data_type),
                    pc
                ));
            }
        }
    }
}

fn check_grant_refs(b: &mut Binder, g: &Grant) {
    if g.claim_key.is_some() {
        return;
    }
    let gc = format!("grant {}", g.name);
    if b.req_table(g.table(), &gc) {
        b.req_col(g.table(), g.grantee_col(), &gc);
        b.req_col(g.table(), g.level_col(), &gc);
        for scope in &g.scopes {
            b.req_col(g.table(), &scope.column, &gc);
        }
        if let Some(a) = &g.active_col {
            b.req_col(g.table(), a, &gc);
        }
        if let Some(e) = &g.expires_col {
            b.req_col(g.table(), e, &gc);
        }
    }
}

fn check_subject_refs(b: &mut Binder, sub: &Subject) {
    let Some(m) = &sub.membership else { return };
    let mc = format!("subject {} membership", sub.name);
    if b.req_table(&m.table, &mc) {
        b.req_col(&m.table, &m.id_col, &mc);
        b.req_col(&m.table, &m.flag_col, &mc);
        if let Some(a) = &m.active_col {
            b.req_col(&m.table, a, &mc);
        }
    }
}

/// Checks every table and column the spec names exists in `sc`.
///
/// # Errors
///
/// Every missing table or column, one finding each, in text order.
pub fn validate_against(s: &Spec, sc: &Schema) -> Result<(), Error> {
    let mut b = Binder { columns: None, sc: Some(sc), errs: Vec::new() };
    for o in &s.objects {
        check_object_refs(s, &mut b, o);
    }
    for rs in &s.role_stores {
        check_role_store_refs(s, &mut b, rs);
    }
    for g in &s.grants {
        check_grant_refs(&mut b, g);
    }
    for sub in &s.subjects {
        check_subject_refs(&mut b, sub);
    }
    b.errs.sort();
    refuse_any(b.errs.into_iter().map(Finding::unplaced).collect(), ())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableCoverage {
    pub governed: Vec<String>,
    pub referenced: Vec<String>,
    pub ungoverned: Vec<String>,
}

#[must_use]
pub fn table_coverage(s: &Spec, db_tables: &[String]) -> TableCoverage {
    let governed: BTreeSet<&str> = s.objects.iter().map(|o| o.table.as_str()).collect();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    let mut add = |t: &str| {
        if !t.is_empty() && !governed.contains(t) {
            referenced.insert(t.to_string());
        }
    };
    for rs in &s.role_stores {
        add(or(rs.assignments.as_deref()));
        add(or(rs.roles_table.as_deref()));
    }
    for g in &s.grants {
        add(g.table());
    }
    for sub in &s.subjects {
        if let Some(m) = &sub.membership {
            add(&m.table);
        }
    }
    for o in &s.objects {
        for r in &o.relations {
            match &r.repr {
                Repr::Edge(e) => add(&e.table),
                Repr::Composition(c) => add(&c.table),
                Repr::Closure(c) => {
                    add(&c.closure);
                    add(or(c.base.as_deref()));
                }
                Repr::Group(g) => {
                    add(&g.closure);
                    add(&g.edge);
                }
                Repr::Grant(g) => add(&g.table),
                _ => {}
            }
        }
    }
    let mut cov = TableCoverage::default();
    for t in db_tables {
        if governed.contains(t.as_str()) {
            cov.governed.push(t.clone());
        } else if referenced.contains(t) {
            cov.referenced.push(t.clone());
        } else {
            cov.ungoverned.push(t.clone());
        }
    }
    cov.governed.sort();
    cov.referenced.sort();
    cov.ungoverned.sort();
    cov
}

pub(crate) fn exported_row(s: &Spec, obj: &Object, pm: &Perm) -> Object {
    let mut row = obj.clone();
    row.perms = vec![pm.clone()];
    row.requires = Vec::new();
    row.reach_uses = obj.reach_uses.iter().filter(|u| u.ops.is_empty() || contains(&u.ops, pm.maps())).cloned().collect();
    let mut terms: Vec<Term> = pm.tree.leaves().into_iter().cloned().collect();
    if let Some(rq) = obj.require_for(&pm.verb) {
        row.requires = vec![rq.clone()];
        terms.extend(rq.tree.leaves().into_iter().cloned());
    }
    for a in &obj.admits {
        if contains(&a.ops, pm.maps()) {
            row.perms.push(a.perm(pm.maps()));
            terms.extend(a.tree.leaves().into_iter().cloned());
        }
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for t in &terms {
        used.insert(t.ident().split(':').next().unwrap_or("").to_string());
        used.insert(t.session_rel().to_string());
        used.extend(t.exclude_rels().iter().cloned());
    }
    row.relations = Vec::new();
    for rel in &obj.relations {
        if rel.types.iter().any(|k| s.level_by_name(k).is_some()) {
            used.insert(rel.name.clone());
        }
        if used.contains(&rel.name) {
            row.relations.push(rel.clone());
        }
    }
    row
}

fn requirement_columns(s: &Spec, row: &Object, t: &Term) -> Vec<String> {
    let mut cols: Vec<String> = [t.mode_col().unwrap_or(""), t.self_col(), t.row_col()].into_iter().filter(|c| !c.is_empty()).map(str::to_string).collect();
    if !t.within_level().is_empty() {
        cols.push(s.scope_col(row, t.within_level()));
    }
    cols.extend(t.external_args().iter().map(ExternalArg::col).filter(|c| !c.is_empty()).map(str::to_string));
    cols
}

pub(crate) fn exported_columns(s: &Spec, row: &Object) -> BTreeSet<String> {
    let mut b = Binder { columns: Some(BTreeMap::new()), sc: None, errs: Vec::new() };
    check_object_refs(s, &mut b, row);
    for pm in &row.perms {
        if let Some(g) = &pm.guard {
            b.req_col(&row.table, &g.col, "export guard");
        }
    }
    for t in row.requires.iter().flat_map(|rq| rq.tree.leaves()) {
        for column in requirement_columns(s, row, t) {
            b.req_col(&row.table, &column, "export requirement");
        }
    }
    b.columns.expect("the coverage binder is built with a column map").remove(&row.table).unwrap_or_default()
}
