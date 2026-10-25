#![doc = "Emits the demesne enforcement floor from a validated spec: RLS policies, the SECURITY DEFINER kernel, closure and group triggers, materialized flats, the changelog and the async tier."]

mod app_surface;
mod asynch;
mod changelog;
mod closure;
mod definers;
mod genfn;
mod rls;
mod supabase;
mod write_reach;

pub use asynch::AsyncIndex;
pub use changelog::{CHANGELOG_CHANNEL, ChangelogTrigger, ObjectChangelogTrigger};
pub use closure::{ClosureTrigger, GroupTrigger, MaterializedFlat};
pub use genfn::{DefinerArm, GenFn, definers_sql};
pub use rls::{Policy, RlsResult, scan_definers};

use demesne_gocompat::quote;
use demesne_model::analysis::relation_is_async;
use demesne_model::{SpecExt, Structure, validate_structure};
use demesne_syntax::Spec;
use std::collections::HashSet;
use std::fmt::Write as _;

#[derive(Debug, Clone, Copy)]
pub struct Sql<'a> {
    pub s: &'a Spec,
    pub definer_body: bool,
}

impl<'a> Sql<'a> {
    #[must_use]
    pub fn new(s: &'a Spec) -> Self {
        Sql { s, definer_body: false }
    }
}

/// Validates a parsed spec: structure, definer closure, the async floor and write reach.
///
/// A write permission must not admit a caller its object's select permission cannot reach, unless it is marked `blind`.
///
/// # Errors
///
/// Every problem found, joined by newlines, or the first structural error that stops validation.
pub fn validate(s: &Spec) -> Result<(), String> {
    let mut errs = match validate_structure(s) {
        Structure::Fatal(e) => return Err(e),
        Structure::Errors(errs) => errs,
    };
    errs.extend(validate_definer_closure(s));
    errs.extend(validate_async_floor_asymmetry(s));
    errs.extend(validate_shared_table_names(s));
    if errs.is_empty() {
        errs.extend(Sql::new(s).write_reach().errors);
    }
    if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
}

/// Returns the warnings a valid spec still earns: a `blind` write term that the select permission cannot reach.
#[must_use]
pub fn validate_warnings(s: &Spec) -> Vec<String> {
    Sql::new(s).write_reach().warnings
}

fn validate_definer_closure(s: &Spec) -> Vec<String> {
    let sql = Sql::new(s);
    let res = match sql.emit_rls() {
        Ok(r) => r,
        Err(e) => return vec![format!("definer closure (V11): RLS does not emit: {e}")],
    };
    if !res.unsupported.is_empty() {
        return res.unsupported.iter().map(|u| format!("uncompilable @rls permission (V11): {u}")).collect();
    }
    let generated_fns = match sql.emit_definers() {
        Ok(g) => g,
        Err(e) => return vec![format!("definer closure (V11): kernel does not emit: {e}")],
    };
    let mut generated: HashSet<String> = generated_fns.iter().map(|g| format!("{}.{}", g.schema(), g.name)).collect();
    for e in &s.externals {
        generated.insert(format!("{}.{}", s.definer_schema(), e.name));
    }
    let mut dangling: Vec<String> = Vec::new();
    let called = res.policies.iter().flat_map(|p| [&p.using, &p.check]).flat_map(|body| scan_definers(body, s.definer_schema()));
    for f in called {
        if !generated.contains(&f) && !dangling.contains(&f) {
            dangling.push(f);
        }
    }
    dangling.sort();
    dangling
        .into_iter()
        .map(|f| {
            format!(
                "definer closure (V11): emitted RLS calls {f}() but the kernel does not generate it — declare it so the compiler owns the whole definer surface"
            )
        })
        .collect()
}

fn quoted_list(xs: &[String]) -> String {
    xs.iter().map(|x| quote(x)).collect::<Vec<_>>().join(", ")
}

fn validate_shared_table_names(s: &Spec) -> Vec<String> {
    let sql = Sql::new(s);
    let mut owners: std::collections::BTreeMap<(String, String), Vec<String>> = std::collections::BTreeMap::new();
    if let Ok(res) = sql.emit_rls() {
        for p in res.policies {
            let objects = owners.entry((p.table, p.name)).or_default();
            if !objects.contains(&p.object) {
                objects.push(p.object);
            }
        }
    }
    let mut errs: Vec<String> = owners
        .into_iter()
        .filter(|(_, objects)| objects.len() > 1)
        .map(|((table, name), objects)| {
            format!(
                "objects {} on table {} each compile a policy named {}; Postgres keeps only the last one created, so the others' predicates would never be enforced: give the table one object with that policy, and make the rest `predicate` permissions",
                quoted_list(&objects),
                quote(&table),
                quote(&name)
            )
        })
        .collect();
    let mut tracked: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for t in sql.emit_object_changelog_triggers() {
        tracked.entry(t.table).or_default().push(t.rel);
    }
    errs.extend(tracked.into_iter().filter(|(_, objects)| objects.len() > 1).map(|(table, objects)| {
        format!(
            "objects {} each track changes on table {}; their changelog triggers share one name, so only the last created would fire: track the table from one object",
            quoted_list(&objects),
            quote(&table)
        )
    }));
    let mut indexes: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for (o, r) in s.relations() {
        if relation_is_async(r) {
            indexes.entry(s.async_index_base(&o.table, &r.name)).or_default().push(o.name.clone());
        }
    }
    errs.extend(indexes.into_iter().filter(|(_, objects)| objects.len() > 1).map(|(index, objects)| {
        format!(
            "objects {} each keep an async index named {}; the last one created replaces the others' maintenance functions, so the others' indexes would be filled from its grant table: rename one of the relations",
            quoted_list(&objects),
            quote(&index)
        )
    }));
    errs
}

fn validate_async_floor_asymmetry(s: &Spec) -> Vec<String> {
    let tokens = s.async_surface_tokens();
    if tokens.is_empty() {
        return Vec::new();
    }
    let sql = Sql::new(s);
    let res = match sql.emit_rls() {
        Ok(r) => r,
        Err(e) => return vec![format!("async asymmetry (V12): RLS does not emit: {e}")],
    };
    let defs = match sql.emit_definers() {
        Ok(d) => d,
        Err(e) => return vec![format!("async asymmetry (V12): kernel does not emit: {e}")],
    };
    let mut bodies: Vec<String> = Vec::new();
    for p in &res.policies {
        bodies.push(p.using.clone());
        bodies.push(p.check.clone());
    }
    for d in &defs {
        bodies.push(d.text());
    }
    bodies.push(sql.flats_sql());
    bodies.push(sql.triggers_sql());
    bodies.push(sql.changelog_sql());
    let mut found: Vec<&str> = Vec::new();
    for body in &bodies {
        if body.is_empty() {
            continue;
        }
        for tok in &tokens {
            if !found.contains(&tok.as_str()) && body.contains(tok.as_str()) {
                found.push(tok);
            }
        }
    }
    found
        .into_iter()
        .map(|tok| {
            format!(
                "async asymmetry (V12): a floor artifact references async surface {} — the floor must read only sync, committed truth; an async index may serve an affordance Check but never gate enforcement",
                demesne_gocompat::quote(tok)
            )
        })
        .collect()
}

#[must_use]
pub fn render_field_grants(fa: &demesne_model::pdp::FieldAccess, table: &str) -> String {
    let mut grants: Vec<(&str, &str, &str)> = Vec::new();
    for r in &fa.rules {
        if r.column.is_empty() {
            continue;
        }
        for role in &r.read {
            grants.push(("SELECT", &r.column, role));
        }
        for role in &r.write {
            grants.push(("UPDATE", &r.column, role));
        }
    }
    if grants.is_empty() {
        return String::new();
    }
    grants.sort_by(|a, b| (a.1, a.0, a.2).cmp(&(b.1, b.0, b.2)));
    let mut b = format!("-- Code generated by Demesne field-access (object {}). DO NOT EDIT.\n", demesne_gocompat::quote(&fa.object));
    for (verb, col, role) in grants {
        writeln!(b, "GRANT {verb} ({col}) ON {table} TO {role};").expect("fmt::Write for String never fails");
    }
    b
}
