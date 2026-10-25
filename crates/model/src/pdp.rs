use crate::analysis::SpecExt;
use crate::error::Error;
use demesne_gocompat::quote;
use demesne_runtime::Pdp;
use demesne_syntax::{Finding, Spec};
use std::collections::BTreeMap;

struct Site {
    policy: BTreeMap<String, String>,
    ungoverned: BTreeMap<String, String>,
}

/// Builds the policy decision point for each vocabulary its `procedures` blocks target.
///
/// # Errors
///
/// Every problem found: an unknown vocabulary or permission, or a procedure mapped twice or both governed and ungoverned.
pub fn emit_pdp(s: &Spec) -> Result<BTreeMap<String, Pdp>, Error> {
    let mut out: BTreeMap<String, Site> = BTreeMap::new();
    let mut errs: Vec<Finding> = Vec::new();
    for pr in &s.procedures {
        let Some(v) = s.vocab_by_name(&pr.emit_site) else {
            errs.push(Finding::at(pr.pos.line, format!("procedures block targets unknown vocabulary {} (V10)", quote(&pr.emit_site))));
            continue;
        };
        let p = out.entry(pr.emit_site.clone()).or_insert_with(|| Site { policy: BTreeMap::new(), ungoverned: BTreeMap::new() });
        for e in &pr.entries {
            if !v.permissions.iter().any(|x| x == &e.perm) {
                errs.push(Finding::at(e.pos.line, format!("{} -> {}: permission not in vocabulary {}", e.proc_, e.perm, quote(&pr.emit_site))));
            }
            if let Some(prev) = p.policy.get(&e.proc_)
                && prev != &e.perm
            {
                errs.push(Finding::at(e.pos.line, format!("procedure {} mapped to both {} and {}", e.proc_, prev, e.perm)));
            }
            p.policy.insert(e.proc_.clone(), e.perm.clone());
        }
    }
    for u in &s.ungoverned {
        if s.vocab_by_name(&u.emit_site).is_none() {
            errs.push(Finding::at(u.pos.line, format!("ungoverned block targets unknown vocabulary {} (V10)", quote(&u.emit_site))));
            continue;
        }
        let p = out.entry(u.emit_site.clone()).or_insert_with(|| Site { policy: BTreeMap::new(), ungoverned: BTreeMap::new() });
        for e in &u.entries {
            if p.policy.contains_key(&e.proc_) {
                errs.push(Finding::at(e.pos.line, format!("procedure {} is both governed and ungoverned", e.proc_)));
            }
            p.ungoverned.insert(e.proc_.clone(), e.reason.clone());
        }
    }
    if !errs.is_empty() {
        return Err(Error::headed("PDP emit", errs));
    }
    let pairs = |m: BTreeMap<String, String>| -> std::borrow::Cow<'static, [(demesne_runtime::Str, demesne_runtime::Str)]> {
        m.into_iter().map(|(k, v)| (demesne_runtime::owned(k), demesne_runtime::owned(v))).collect::<Vec<_>>().into()
    };
    Ok(out
        .into_iter()
        .map(|(site, p)| {
            let pdp = Pdp { emit_site: demesne_runtime::owned(site.clone()), policy: pairs(p.policy), ungoverned: pairs(p.ungoverned) };
            (site, pdp)
        })
        .collect())
}

/// Builds each site's map from field to the scope that may set it.
///
/// # Errors
///
/// Every problem found: a field mapped to two different scopes.
pub fn emit_field_scopes(s: &Spec) -> Result<BTreeMap<String, BTreeMap<String, String>>, Error> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut errs = Vec::new();
    for fs in &s.field_scopes {
        let m = out.entry(fs.site.clone()).or_default();
        for e in &fs.entries {
            if let Some(prev) = m.get(&e.field)
                && prev != &e.scope
            {
                errs.push(Finding::at(e.pos.line, format!("field {} mapped to both {} and {}", quote(&e.field), prev, e.scope)));
            }
            m.insert(e.field.clone(), e.scope.clone());
        }
    }
    if !errs.is_empty() {
        return Err(Error::headed("field-scopes emit", errs));
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldAccessRule {
    pub field: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub column: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldAccess {
    pub object: String,
    pub principals: Vec<String>,
    pub rules: Vec<FieldAccessRule>,
}

#[must_use]
pub fn emit_field_access(s: &Spec) -> BTreeMap<String, FieldAccess> {
    let mut out = BTreeMap::new();
    for o in &s.objects {
        if o.field_principals.is_empty() {
            continue;
        }
        let mut principals = o.field_principals.clone();
        principals.sort();
        let rules = o
            .fields
            .iter()
            .map(|f| FieldAccessRule { field: f.name.clone(), read: f.read.clone(), write: f.write.clone(), column: f.column.clone().unwrap_or_default() })
            .collect();
        out.insert(o.name.clone(), FieldAccess { object: o.name.clone(), principals, rules });
    }
    out
}
