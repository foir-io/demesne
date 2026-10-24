use crate::analysis::SpecExt;
use demesne_gocompat::quote;
use demesne_runtime::Pdp;
use demesne_syntax::Spec;
use std::collections::BTreeMap;

pub fn emit_pdp(s: &Spec) -> Result<BTreeMap<String, Pdp>, String> {
    let mut out: BTreeMap<String, Pdp> = BTreeMap::new();
    let mut errs: Vec<String> = Vec::new();
    for pr in &s.procedures {
        let Some(v) = s.vocab_by_name(&pr.emit_site) else {
            errs.push(format!(
                "line {}: procedures block targets unknown vocabulary {} (V10)",
                pr.pos.line,
                quote(&pr.emit_site)
            ));
            continue;
        };
        let p = out.entry(pr.emit_site.clone()).or_insert_with(|| Pdp { emit_site: pr.emit_site.clone(), ..Default::default() });
        for e in &pr.entries {
            if !v.permissions.iter().any(|x| x == &e.perm) {
                errs.push(format!(
                    "line {}: {} -> {}: permission not in vocabulary {}",
                    e.pos.line,
                    e.proc_,
                    e.perm,
                    quote(&pr.emit_site)
                ));
            }
            if let Some(prev) = p.policy.get(&e.proc_)
                && prev != &e.perm
            {
                errs.push(format!("line {}: procedure {} mapped to both {} and {}", e.pos.line, e.proc_, prev, e.perm));
            }
            p.policy.insert(e.proc_.clone(), e.perm.clone());
        }
    }
    for u in &s.ungoverned {
        if s.vocab_by_name(&u.emit_site).is_none() {
            errs.push(format!(
                "line {}: ungoverned block targets unknown vocabulary {} (V10)",
                u.pos.line,
                quote(&u.emit_site)
            ));
            continue;
        }
        let p = out.entry(u.emit_site.clone()).or_insert_with(|| Pdp { emit_site: u.emit_site.clone(), ..Default::default() });
        for e in &u.entries {
            if p.policy.contains_key(&e.proc_) {
                errs.push(format!("line {}: procedure {} is both governed and ungoverned", e.pos.line, e.proc_));
            }
            p.ungoverned.insert(e.proc_.clone(), e.reason.clone());
        }
    }
    if !errs.is_empty() {
        return Err(format!("PDP emit:\n  {}", errs.join("\n  ")));
    }
    Ok(out)
}

pub fn emit_field_scopes(s: &Spec) -> Result<BTreeMap<String, BTreeMap<String, String>>, String> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut errs = Vec::new();
    for fs in &s.field_scopes {
        let m = out.entry(fs.site.clone()).or_default();
        for e in &fs.entries {
            if let Some(prev) = m.get(&e.field)
                && prev != &e.scope
            {
                errs.push(format!("line {}: field {} mapped to both {} and {}", e.pos.line, quote(&e.field), prev, e.scope));
            }
            m.insert(e.field.clone(), e.scope.clone());
        }
    }
    if !errs.is_empty() {
        return Err(format!("field-scopes emit:\n  {}", errs.join("\n  ")));
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
            .map(|f| FieldAccessRule {
                field: f.name.clone(),
                read: f.read.clone(),
                write: f.write.clone(),
                column: f.column.clone().unwrap_or_default(),
            })
            .collect();
        out.insert(o.name.clone(), FieldAccess { object: o.name.clone(), principals, rules });
    }
    out
}
