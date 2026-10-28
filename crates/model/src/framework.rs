use crate::error::Error;
use crate::{SpecExt, topology};
use demesne_gocompat::{go_export, quote};
use demesne_runtime::AppObjectSurface;
use demesne_syntax::{Perm, Spec, Vocabulary};
use std::collections::{HashMap, HashSet};

type R<T> = Result<T, Error>;

/// One permission's field in a caps struct: the field's exported name and the permission it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VocabField {
    pub exp: String,
    pub perm: String,
}

/// One domain of a caps struct: the domain's exported name and a field per permission in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VocabDomain {
    pub exp: String,
    pub fields: Vec<VocabField>,
}

/// Groups a vocabulary's permissions into caps domains by their first segment, and returns the parameterized
/// permissions, which have no static field, beside them.
///
/// # Errors
///
/// Two permissions export to the same domain and field name.
pub fn vocab_caps_tree(perms: &[String]) -> R<(Vec<VocabDomain>, Vec<String>)> {
    let mut domains: Vec<VocabDomain> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut skipped = Vec::new();
    for p in perms {
        if p.contains('*') {
            skipped.push(p.clone());
            continue;
        }
        let Some((seg0, rest)) = p.split_once(':').filter(|(_, r)| !r.is_empty()) else {
            skipped.push(p.clone());
            continue;
        };
        let (dexp, fexp) = (go_export(seg0), go_export(rest));
        let key = format!("{dexp}.{fexp}");
        if !seen.insert(key) {
            return Err(Error::unplaced(format!("vocab caps: {} collides on {}.{}", quote(p), dexp, fexp)));
        }
        let di = *idx.entry(dexp.clone()).or_insert_with(|| {
            domains.push(VocabDomain { exp: dexp.clone(), fields: Vec::new() });
            domains.len() - 1
        });
        domains[di].fields.push(VocabField { exp: fexp, perm: p.clone() });
    }
    Ok((domains, skipped))
}

/// Returns each capability verb whose permission no rolestore vocabulary covers, as `object.verb (needs "perm")`.
#[must_use]
pub fn orphan_pdp_verbs(s: &Spec) -> Vec<String> {
    let mut covered: HashSet<&str> = HashSet::new();
    for rs in &s.role_stores {
        if let Ok(v) = s.rolestore_vocab(rs) {
            covered.extend(v.permissions.iter().map(String::as_str));
        }
    }
    let mut orphan = Vec::new();
    for o in s.objects.iter().filter(|o| o.point_checkable()) {
        for (pm, t) in o.perm_terms().filter(|(pm, _)| pm.has_layer("pdp")) {
            if !t.ident().is_empty() && !covered.contains(t.ident()) {
                orphan.push(format!("{}.{} (needs {})", o.name, pm.verb, quote(t.ident())));
            }
        }
    }
    orphan
}

/// Returns the SQL that checks one row for a verb, or `None` when the verb has no row-level check.
#[must_use]
pub fn row_check_sql(o: &AppObjectSurface, pm: &Perm) -> Option<String> {
    let sql = match pm.maps() {
        "select" => return Some(o.check_sql()),
        "update" => o.edit_check_sql.to_string(),
        _ if pm.has_layer("check") => o.check_verb_sql(&pm.verb).to_string(),
        _ => return None,
    };
    (!sql.is_empty()).then_some(sql)
}

fn framework_reserved_names(s: &Spec) -> HashSet<String> {
    let mut reserved = HashSet::new();
    let mut add = |n: &str| {
        reserved.insert(go_export(n).to_lowercase());
    };
    for n in [
        "Decision",
        "Allow",
        "Deny",
        "NotGoverned",
        "Claims",
        "Mint",
        "Querier",
        "ConnectionRole",
        "claimsContract",
        "claimsGUC",
        "SetRoleSQL",
        "ClaimsSetSQL",
        "SessionSetupSQL",
        "Check",
        "CheckHandler",
    ] {
        add(n);
    }
    for rs in &s.role_stores {
        let suffix = if s.role_stores.len() > 1 { go_export(&rs.name) } else { String::new() };
        for base in ["HoldsResolver", "AssignmentsSQL", "ResolveHeld", "Holds", "ResolveHeldRoles", "HoldsRoles", "RoleTiers", "RoleSet", "Caps", "CapSet"] {
            add(&format!("{base}{suffix}"));
        }
        if let Ok(v) = s.rolestore_vocab(rs)
            && let Ok((domains, _)) = vocab_caps_tree(&v.permissions)
        {
            for d in domains {
                add(&format!("{}Caps{}", d.exp, suffix));
            }
        }
    }
    reserved
}

/// Refuses an object whose generated accessor would take the name of a generated framework helper.
///
/// # Errors
///
/// An object's exported name matches a helper's, ignoring case.
pub fn check_accessor_collisions(s: &Spec, objects: &[AppObjectSurface]) -> R<()> {
    let reserved = framework_reserved_names(s);
    for o in objects {
        if reserved.contains(&go_export(&o.object).to_lowercase()) {
            return Err(Error::unplaced(format!(
                "framework emit: object {} generates the accessor {}, which collides with a generated framework helper of the same name; rename the object (the role-tier accessor is RoleTiers/roleTiers, verb caps is Caps/caps, the reusable check is Check/check)",
                quote(&o.object),
                quote(&go_export(&o.object))
            )));
        }
    }
    Ok(())
}

/// Returns the role tiers a vocabulary's roles report, as each field's exported name and its role key.
///
/// # Errors
///
/// Two presets export to the same field name.
pub fn role_tier_fields(s: &Spec, vocab: &Vocabulary) -> R<Vec<(String, String)>> {
    let virt: HashSet<String> = topology::chain(s).map(|c| c.into_iter().filter(|l| l.is_virtual).map(|l| l.name.clone()).collect()).unwrap_or_default();
    let mut fields = Vec::new();
    let mut seen_key = HashSet::new();
    let mut seen_exp = HashSet::new();
    let mut add = |key: &str| -> R<()> {
        if key.is_empty() || !seen_key.insert(key.to_string()) {
            return Ok(());
        }
        let exp = go_export(key);
        if !seen_exp.insert(exp.clone()) {
            return Err(Error::unplaced(format!("role tier: preset {} collides on field {}", quote(key), exp)));
        }
        fields.push((exp, key.to_string()));
        Ok(())
    };
    for v in &s.vocabs {
        for p in &v.presets {
            if let Some(level) = &p.level
                && virt.contains(level)
            {
                add(&p.name)?;
            }
        }
    }
    for p in &vocab.presets {
        match &p.level {
            Some(level) if !virt.contains(level) => add(&p.name)?,
            _ => {}
        }
    }
    Ok(fields)
}
