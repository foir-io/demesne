#![doc = "Emits demesne's Rust surface: the runtime tables a spec compiles to, as `static` items built from `Cow::Borrowed` data, for only the surfaces a crate names. Nothing is parsed at runtime. `Builder` runs it from `build.rs`."]
#![forbid(unsafe_code)]

mod build;
mod error;
mod lit;

pub use build::Builder;
pub use error::Error;

use demesne_emit_sql::Sql;
use demesne_model::{SpecExt, SurfaceExt};
use demesne_runtime as rt;
use demesne_syntax::Spec;
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Surface {
    Vocabulary(String),
    HoldsResolver(String),
    RoleAssignment(String),
    ExpandedPresets(String),
    Grant(String),
    ResourceAccess(String),
    ConditionalResourceAccess(String),
    PointCheck(String),
    AppSurface(String),
    Check(String, String),
    Pdp(String),
    Session,
    ClaimsContract,
    ClaimsContractEntries,
}

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut",
    "pub", "ref", "return", "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become",
    "box", "do", "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
];

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_') && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') && s != "_"
}

fn module_ident(kind: &str, name: &str) -> Result<String, String> {
    if !is_ident(name) || matches!(name, "self" | "Self" | "super" | "crate") {
        return Err(format!("{kind} {name:?} is not a Rust identifier, so it cannot name a module"));
    }
    Ok(if KEYWORDS.contains(&name) { format!("r#{name}") } else { name.to_string() })
}

fn const_ident(kind: &str, name: &str) -> Result<String, String> {
    let upper = name.to_ascii_uppercase();
    if !is_ident(&upper) || upper == "SELF" {
        return Err(format!("{kind} {name:?} is not a Rust identifier, so it cannot name a static"));
    }
    Ok(upper)
}

#[derive(Default)]
struct Module {
    items: BTreeMap<String, (String, String)>,
    children: BTreeMap<String, Module>,
}

impl Module {
    fn child(&mut self, path: &[String]) -> &mut Module {
        let mut m = self;
        for p in path {
            m = m.children.entry(p.clone()).or_default();
        }
        m
    }

    fn add(&mut self, path: &[String], ident: String, source_name: &str, text: String) -> Result<(), String> {
        let m = self.child(path);
        match m.items.get(&ident) {
            Some((prev, prev_text)) if prev != source_name || prev_text != &text => {
                Err(format!("{} and {} both become {}::{ident}; rename one in the spec", prev, source_name, path.join("::")))
            }
            _ => {
                m.items.insert(ident, (source_name.to_string(), text));
                Ok(())
            }
        }
    }

    fn render(&self, out: &mut String, depth: usize) {
        let pad = "    ".repeat(depth);
        for line in self.items.values().flat_map(|(_, text)| text.lines()) {
            if line.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&pad);
                out.push_str(line);
                out.push('\n');
            }
        }
        for (name, child) in &self.children {
            write!(out, "{pad}#[allow(non_snake_case, reason = \"modules are named after the spec's own names\")]\n{pad}pub mod {name} {{\n")
                .expect("fmt::Write for String never fails");
            child.render(out, depth + 1);
            writeln!(out, "{pad}}}").expect("fmt::Write for String never fails");
        }
    }
}

fn store_name(s: &Spec, store: &str) -> Result<String, String> {
    if store.is_empty() {
        return s.role_stores.first().map(|r| r.name.clone()).ok_or_else(|| "the spec declares no rolestore".to_string());
    }
    if s.role_stores.iter().any(|r| r.name == store) {
        return Ok(store.to_string());
    }
    Err(format!("no rolestore {store:?} in the spec"))
}

fn app_object(s: &Spec, object: &str) -> Result<rt::AppObjectSurface, String> {
    let surf = Sql::new(s).emit_app_surface().map_err(|e| e.to_string())?;
    surf.object(object).cloned().ok_or_else(|| match s.objects.iter().find(|o| o.name == object) {
        None => format!("no object {object:?} in the spec"),
        Some(_) => format!("object {object:?} has no app surface: it has no single-column primary key to point-check"),
    })
}

fn check_sql(s: &Spec, object: &str, verb: &str) -> Result<String, String> {
    let app = app_object(s, object)?;
    if let Some(c) = app.checks.iter().find(|c| c.verb == verb) {
        return Ok(c.check_sql.to_string());
    }
    let o = s.objects.iter().find(|o| o.name == object).expect("app_object found it");
    match o.perms.iter().find(|p| p.verb == verb) {
        None => Err(format!("object {object:?} has no permission {verb:?}")),
        Some(p) if p.has_layer("pdp") => Err(rt::capability_gate_err(object, verb).to_string()),
        Some(_) => Err(format!("{object}.{verb} has no @check layer, so it has no point-check")),
    }
}

/// Returns the path, relative to the generated module, of the item that holds surface `w`.
///
/// # Errors
///
/// A name that is not a valid Rust identifier, or a rolestore the spec does not declare.
pub fn item_path(s: &Spec, w: &Surface) -> Result<String, Error> {
    surface_path(s, w).map_err(Error::surface)
}

fn surface_path(s: &Spec, w: &Surface) -> Result<String, String> {
    Ok(match w {
        Surface::Vocabulary(name) => format!("vocabularies::{}", const_ident("vocabulary", name)?),
        Surface::HoldsResolver(store) => format!("rolestores::{}::HOLDS_RESOLVER", module_ident("rolestore", &store_name(s, store)?)?),
        Surface::RoleAssignment(store) => format!("rolestores::{}::ROLE_ASSIGNMENT", module_ident("rolestore", &store_name(s, store)?)?),
        Surface::ExpandedPresets(store) => format!("rolestores::{}::EXPANDED_PRESETS", module_ident("rolestore", &store_name(s, store)?)?),
        Surface::Grant(name) => format!("grants::{}", const_ident("grant", name)?),
        Surface::ResourceAccess(object) => format!("objects::{}::RESOURCE_ACCESS", module_ident("object", object)?),
        Surface::ConditionalResourceAccess(object) => format!("objects::{}::CONDITIONAL_RESOURCE_ACCESS", module_ident("object", object)?),
        Surface::PointCheck(object) => format!("objects::{}::POINT_CHECK_SQL", module_ident("object", object)?),
        Surface::AppSurface(object) => format!("objects::{}::APP_SURFACE", module_ident("object", object)?),
        Surface::Check(object, verb) => format!("objects::{}::checks::{}", module_ident("object", object)?, const_ident("verb", verb)?),
        Surface::Pdp(site) => format!("pdp::{}", const_ident("PDP emit site", site)?),
        Surface::Session => "claims::SESSION".into(),
        Surface::ClaimsContract => "claims::CONTRACT".into(),
        Surface::ClaimsContractEntries => "claims::CONTRACT_ENTRIES".into(),
    })
}

/// Renders the `wanted` surfaces as static Rust tables in one module tree.
///
/// # Errors
///
/// Every surface that cannot be built, each named, joined by newlines.
pub fn emit_rust(s: &Spec, wanted: &[Surface]) -> Result<String, Error> {
    let mut root = Module::default();
    let mut errs = Vec::new();
    for w in wanted {
        if let Err(e) = add_surface(s, &mut root, w) {
            errs.push(format!("{w:?}: {e}"));
        }
    }
    if !errs.is_empty() {
        return Err(Error::surface(errs.join("\n")));
    }
    let mut out = String::from("// Code generated by Demesne. DO NOT EDIT.\n\n");
    root.render(&mut out, 0);
    Ok(out)
}

fn add_surface(s: &Spec, root: &mut Module, w: &Surface) -> Result<(), String> {
    let path = |parts: &[&str]| parts.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
    match w {
        Surface::Vocabulary(name) => {
            let v = s.vocabs.iter().find(|v| &v.name == name).ok_or_else(|| format!("no vocabulary {name:?} in the spec"))?;
            let ident = const_ident("vocabulary", name)?;
            let text = format!("pub static {ident}: ::demesne_runtime::Vocabulary = {};\n", lit::vocabulary(&demesne_model::vocab::to_runtime(v)));
            root.add(&path(&["vocabularies"]), ident, name, text)
        }
        Surface::HoldsResolver(store) => add_rolestore_item(s, root, store, "HOLDS_RESOLVER", |name| {
            Ok(format!(
                "pub static HOLDS_RESOLVER: ::demesne_runtime::HoldsResolver = {};\n",
                lit::holds_resolver(&s.holds_resolver(name).map_err(|e| e.to_string())?)
            ))
        }),
        Surface::RoleAssignment(store) => add_rolestore_item(s, root, store, "ROLE_ASSIGNMENT", |name| {
            Ok(format!(
                "pub static ROLE_ASSIGNMENT: ::demesne_runtime::RoleAssignmentSurface = {};\n",
                lit::role_assignment(&s.role_assignment_surface(name).map_err(|e| e.to_string())?)
            ))
        }),
        Surface::ExpandedPresets(store) => add_rolestore_item(s, root, store, "EXPANDED_PRESETS", |name| {
            Ok(format!("pub static EXPANDED_PRESETS: &[(&str, &[&str])] = {};\n", lit::presets(&s.expanded_presets(name).map_err(|e| e.to_string())?)))
        }),
        Surface::Grant(name) => {
            let g = s.grant_surface(name).map_err(|e| e.to_string())?;
            let ident = const_ident("grant", name)?;
            let text = format!("pub static {ident}: ::demesne_runtime::GrantSurface = {};\n", lit::grant(&g));
            root.add(&path(&["grants"]), ident, name, text)
        }
        Surface::ResourceAccess(object) => {
            let r = s.resource_access_surface(object).map_err(|e| e.to_string())?;
            let text = format!("pub static RESOURCE_ACCESS: ::demesne_runtime::ResourceAccessSurface = {};\n", lit::resource_access(&r));
            add_object_item(root, object, "RESOURCE_ACCESS", text)
        }
        Surface::ConditionalResourceAccess(object) => {
            let r = s.conditional_resource_access_surface(object).map_err(|e| e.to_string())?;
            let text = format!("pub static CONDITIONAL_RESOURCE_ACCESS: ::demesne_runtime::ResourceAccessSurface = {};\n", lit::resource_access(&r));
            add_object_item(root, object, "CONDITIONAL_RESOURCE_ACCESS", text)
        }
        Surface::PointCheck(object) => {
            let sql = s.point_check_sql(object).map_err(|e| e.to_string())?;
            add_object_item(root, object, "POINT_CHECK_SQL", format!("pub const POINT_CHECK_SQL: &str = {sql:?};\n"))
        }
        Surface::AppSurface(object) => {
            let app = app_object(s, object)?;
            let text = format!("pub static APP_SURFACE: ::demesne_runtime::AppObjectSurface = {};\n", lit::app_object(&app));
            add_object_item(root, object, "APP_SURFACE", text)
        }
        Surface::Check(object, verb) => {
            let sql = check_sql(s, object, verb)?;
            let ident = const_ident("verb", verb)?;
            let text = format!("pub const {ident}: &str = {sql:?};\n");
            let source = format!("{object}.{verb}");
            root.add(&[String::from("objects"), module_ident("object", object)?, String::from("checks")], ident, &source, text)
        }
        Surface::Pdp(site) => {
            let pdps = demesne_model::pdp::emit_pdp(s).map_err(|e| e.to_string())?;
            let p = pdps.get(site).ok_or_else(|| format!("no PDP emit site {site:?} in the spec"))?;
            let ident = const_ident("PDP emit site", site)?;
            let text = format!("pub static {ident}: ::demesne_runtime::Pdp = {};\n", lit::pdp(p));
            root.add(&path(&["pdp"]), ident, site, text)
        }
        Surface::Session => {
            let text = format!("pub static SESSION: ::demesne_runtime::Session = {};\n", lit::session(&s.session()));
            root.add(&path(&["claims"]), "SESSION".into(), "session", text)
        }
        Surface::ClaimsContract => {
            let text = format!("pub static CONTRACT: &[&str] = {};\n", lit::str_slice(&s.claims_contract().map_err(|e| e.to_string())?));
            root.add(&path(&["claims"]), "CONTRACT".into(), "claims contract", text)
        }
        Surface::ClaimsContractEntries => {
            let text = format!(
                "pub static CONTRACT_ENTRIES: &[::demesne_runtime::ClaimEntry] = {};\n",
                lit::claim_entries(&s.claims_contract_entries().map_err(|e| e.to_string())?)
            );
            root.add(&path(&["claims"]), "CONTRACT_ENTRIES".into(), "claims contract entries", text)
        }
    }
}

fn add_rolestore_item(s: &Spec, root: &mut Module, store: &str, item: &str, text: impl FnOnce(&str) -> Result<String, String>) -> Result<(), String> {
    let name = store_name(s, store)?;
    let text = text(&name)?;
    root.add(&[String::from("rolestores"), module_ident("rolestore", &name)?], item.into(), &name, text)
}

fn add_object_item(root: &mut Module, object: &str, item: &str, text: String) -> Result<(), String> {
    root.add(&[String::from("objects"), module_ident("object", object)?], item.into(), object, text)
}
