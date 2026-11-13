use crate::SpecExt;
use crate::analysis::{
    ORDERED_TABLE_OPS, Rels, contains, go_type_name, grant_relation, grant_selector, is_perm_key_lit, mapped_perm, object_grant_edge, object_uses_store_manage,
    op_to_cmd,
};
use crate::closure;
use crate::conditional::is_row_leaf;
use crate::error::Error;
use crate::schema::{exported_columns, exported_row};
use crate::topology;
use crate::vocab::to_runtime;
use demesne_gocompat::{fmt_slice, quote};
use demesne_syntax::{
    Finding, Grant, GrantUse, Level, Marker, Object, Perm, PermNode, PermissionExport, ProbeAnswer, Relation, Repr, Require, Spec, Subject, Term, ViaClosure,
    ViaComposition, ViaGrant, ViaObject, Vocabulary,
};
use std::collections::{BTreeMap, HashMap, HashSet};

const KNOWN_LAYERS: [&str; 4] = ["rls", "pdp", "kernel", "check"];
const KNOWN_BUILTINS: [&str; 20] = [
    "clock",
    "app_scope",
    "scoped",
    "session",
    "open",
    "store_manage",
    "public",
    "kind",
    "self",
    "within",
    "holds",
    "holds_every",
    "claim",
    "row",
    "some",
    "element",
    "declared",
    "slot",
    "slot_held",
    "holds_at",
];
const EXPORT_PARAMETER_TYPES: [&str; 12] =
    ["text", "uuid", "smallint", "integer", "bigint", "boolean", "json", "jsonb", "numeric", "timestamptz", "timestamp", "date"];

fn table_op(s: &str) -> bool {
    matches!(s, "select" | "insert" | "update" | "delete")
}

#[derive(Debug)]
pub enum Structure {
    Fatal(Error),
    Errors(Vec<Finding>),
}

#[must_use]
pub fn validate_structure(s: &Spec) -> Structure {
    let chain = match topology::chain(s) {
        Ok(c) => c,
        Err(e) => return Structure::Fatal(e),
    };
    let level_names: HashSet<&str> = chain.iter().map(|l| l.name.as_str()).collect();
    let mut errs: Vec<Finding> = Vec::new();

    let (vocab_names, vocab_errs) = check_vocabs(s);
    errs.extend(vocab_errs);
    errs.extend(check_grants(s, &level_names));
    errs.extend(check_claims_block(s));
    for sub in &s.subjects {
        errs.extend(validate_subject(s, sub, &level_names, &vocab_names));
    }
    errs.extend(check_plane_bindings(s));
    errs.extend(check_role_store_planes(s, &chain));
    if let Err(e) = s.claims_contract() {
        errs.extend(e.into_findings());
    }
    for o in &s.objects {
        errs.extend(validate_object(s, o, &chain));
    }
    errs.extend(check_duplicate_maps(s));
    errs.extend(validate_cross_object_acyclic(s));
    errs.extend(validate_predicate_only_referenced(s));
    errs.extend(validate_grant_reach(s));
    errs.extend(validate_permission_exports(s));
    errs.extend(validate_probes(s));
    errs.extend(validate_nearests(s));
    errs.extend(validate_projections(s));
    errs.extend(validate_markers(s));
    errs.extend(validate_chains(s));
    errs.extend(validate_role_forms(s));
    errs.extend(validate_grant_stores(s));
    errs.extend(validate_store_manage(s));
    errs.extend(check_emit_sites(s, &vocab_names));
    errs.extend(check_externals(s));
    errs.extend(check_closures(s));
    Structure::Errors(errs)
}

fn check_vocabs(s: &Spec) -> (HashSet<String>, Vec<Finding>) {
    let mut errs = Vec::new();
    let mut names = HashSet::new();
    for v in &s.vocabs {
        if names.contains(&v.name) {
            errs.push(Finding::at(v.pos.line, format!("duplicate vocabulary {}", quote(&v.name))));
        }
        names.insert(v.name.clone());
        errs.extend(validate_vocabulary(v));
    }
    (names, errs)
}

fn validate_vocabulary(v: &Vocabulary) -> Vec<Finding> {
    let mut errs = Vec::new();
    let perms: HashSet<&str> = v.permissions.iter().map(String::as_str).collect();
    let preset_names: HashSet<&str> = v.presets.iter().map(|p| p.name.as_str()).collect();
    for pr in &v.presets {
        if pr.star {
            continue;
        }
        for item in &pr.set {
            if perms.contains(item.as_str()) || preset_names.contains(item.as_str()) {
                continue;
            }
            errs.push(Finding::at(
                pr.pos.line,
                format!("preset {} references unknown permission/preset {} in vocabulary {}", quote(&pr.name), quote(item), quote(&v.name)),
            ));
        }
    }
    let rv = to_runtime(v);
    for im in &v.implications {
        if let Err(e) = rv.implied_permissions(&im.perm) {
            errs.push(Finding::at(im.pos.line, format!("{e}")));
        }
    }
    for r in &v.rank {
        if !preset_names.contains(r.as_str()) {
            errs.push(Finding::at(v.pos.line, format!("rank ladder names {} which is not a preset of vocabulary {}", quote(r), quote(&v.name))));
        }
    }
    errs
}

fn check_grants(s: &Spec, levels: &HashSet<&str>) -> Vec<Finding> {
    let mut errs = Vec::new();
    for g in &s.grants {
        if !levels.contains(g.level.as_str()) {
            errs.push(Finding::at(g.pos.line, format!("grant {} confers reach at unknown level {}", quote(&g.name), quote(&g.level))));
        }
        if g.claim_key.is_none() && (g.table.is_none() || g.grantee_col.is_none() || g.level_col.is_none()) {
            errs.push(Finding::at(g.pos.line, format!("grant {} must name an edge table, grantee column and level column", quote(&g.name))));
        }
        let mut seen = HashSet::new();
        for v in &g.verbs {
            if op_to_cmd(v).is_empty() {
                errs.push(Finding::at(
                    g.pos.line,
                    format!("grant {} confers unknown verb {} (expected select, insert, update or delete)", quote(&g.name), quote(v)),
                ));
            }
            if seen.contains(v) {
                errs.push(Finding::at(g.pos.line, format!("grant {} names verb {} twice", quote(&g.name), quote(v))));
            }
            seen.insert(v.clone());
        }
    }
    errs
}

fn check_claims_block(s: &Spec) -> Vec<Finding> {
    let Some(c) = &s.claims else { return Vec::new() };
    let mut errs = Vec::new();
    if c.setting.is_empty() {
        errs.push(Finding::at(c.pos.line, "claims block needs a setting name"));
    }
    if c.cast != "json" && c.cast != "jsonb" {
        errs.push(Finding::at(c.pos.line, format!("claims cast {} must be json or jsonb", quote(&c.cast))));
    }
    errs
}

fn validate_subject(s: &Spec, sub: &Subject, levels: &HashSet<&str>, vocabs: &HashSet<String>) -> Vec<Finding> {
    let mut errs = Vec::new();
    let line = sub.pos.line;
    let name = quote(&sub.name);
    if !matches!(sub.reach(), "self" | "descendants" | "grant") {
        errs.push(Finding::at(line, format!("subject {name} has reach {} — only self|descendants|grant are emittable (V2)", quote(sub.reach()))));
    }
    if !levels.contains(sub.anchor()) {
        errs.push(Finding::at(line, format!("subject {name} anchors at unknown level {} (V2)", quote(sub.anchor()))));
    }
    if sub.reach() == "grant" {
        errs.extend(check_subject_reach_grant(s, sub));
    }
    if !sub.roles().is_empty() && !vocabs.contains(sub.roles()) {
        errs.push(Finding::at(line, format!("subject {name} roles reference unknown vocabulary {}", quote(sub.roles()))));
    }
    if !matches!(sub.binds(), "" | "owner" | "admin") {
        errs.push(Finding::at(line, format!("subject {name} has unknown binding {} (binds owner|admin)", quote(sub.binds()))));
    }
    if levels.contains(sub.anchor()) {
        match s.pinned_columns(sub) {
            Err(e) => errs.extend(e.into_findings()),
            Ok((cols, is_virtual)) => {
                if cols.is_empty() && !is_virtual {
                    errs.push(Finding::at(line, format!("subject {name} pins no scope column yet does not anchor at a virtual level — unconditional reach is only allowed for a virtual-anchored operator (V7)")));
                }
            }
        }
    }
    if let Some(m) = &sub.membership
        && (m.table.is_empty() || m.id_col.is_empty() || m.flag_col.is_empty())
    {
        errs.push(Finding::at(line, format!("subject {name} membership must name a table, id column and flag column (V9)")));
    }
    if sub.transient {
        errs.extend(check_transient_subject(sub));
    }
    errs
}

fn check_subject_reach_grant(s: &Spec, sub: &Subject) -> Option<Finding> {
    let (line, name) = (sub.pos.line, quote(&sub.name));
    if sub.reach_grant().is_empty() {
        return Some(Finding::at(line, format!("subject {name} has `reach via grant` but names no grant")));
    }
    match s.grant_by_name(sub.reach_grant()) {
        None => Some(Finding::at(line, format!("subject {name} reaches via unknown grant {}", quote(sub.reach_grant())))),
        Some(g) if g.claim_key.is_some() => Some(Finding::at(line, format!("claim grant {} does not take a reaching subject", quote(&g.name)))),
        Some(_) => None,
    }
}

fn check_transient_subject(sub: &Subject) -> Vec<Finding> {
    let (line, name) = (sub.pos.line, quote(&sub.name));
    let mut errs = Vec::new();
    if sub.identifies().is_empty() {
        errs.push(Finding::at(line, format!("transient subject {name} must name the claim it is identified by (`identifies <claim>`)")));
    }
    if sub.reach() != "self" {
        errs.push(Finding::at(
            line,
            format!("transient subject {name} must `reach self`: it stands for one request, not a principal with descendants or grants"),
        ));
    }
    if !sub.roles_none || !sub.roles().is_empty() {
        errs.push(Finding::at(
            line,
            format!("transient subject {name} must be `roles none`: a role is held by a standing principal, and a transient subject is a claim on one request"),
        ));
    }
    if !sub.binds().is_empty() {
        errs.push(Finding::at(
            line,
            format!("transient subject {name} cannot bind a plane (`binds {}`): a plane's owner is a standing principal", sub.binds()),
        ));
    }
    if sub.membership.is_some() {
        errs.push(Finding::at(line, format!("transient subject {name} cannot be identified via a membership")));
    }
    errs
}

fn check_plane_bindings(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut owner_at: HashMap<&str, &str> = HashMap::new();
    let mut admin_sub = "";
    for sub in &s.subjects {
        match sub.binds() {
            "owner" => {
                if let Some(prev) = owner_at.get(sub.anchor()).filter(|p| !p.is_empty()) {
                    errs.push(Finding::unplaced(format!(
                        "subjects {} and {} both `binds owner` at level {} — the owner plane must be unambiguous",
                        quote(prev),
                        quote(&sub.name),
                        quote(sub.anchor())
                    )));
                }
                owner_at.insert(sub.anchor(), &sub.name);
            }
            "admin" => {
                if !admin_sub.is_empty() {
                    errs.push(Finding::unplaced(format!(
                        "subjects {} and {} both `binds admin` — the admin plane must be unambiguous",
                        quote(admin_sub),
                        quote(&sub.name)
                    )));
                }
                admin_sub = &sub.name;
            }
            _ => {}
        }
    }
    errs
}

fn check_role_store_planes(s: &Spec, chain: &[&Level]) -> Vec<Finding> {
    let mut errs = Vec::new();
    let non_virtual = chain.iter().filter(|l| !l.is_virtual).count();
    let known: HashSet<&str> = chain.iter().map(|l| l.name.as_str()).collect();
    let mut by_fn: HashMap<String, &str> = HashMap::new();
    for rs in &s.role_stores {
        let f = s.holds_perm_fn(rs);
        match by_fn.get(&f).filter(|n| !n.is_empty()) {
            Some(prev) => errs.push(Finding::unplaced(format!(
                "rolestores {} and {} both compile their @holds check to {}() — rename one so each rolestore has its own definer",
                quote(prev),
                quote(&rs.name),
                f
            ))),
            None => {
                by_fn.insert(f, &rs.name);
            }
        }
        let Some(plane) = &rs.plane else { continue };
        if !known.contains(plane.as_str()) {
            errs.push(Finding::at(rs.pos.line, format!("rolestore {} declares `plane {}`, which is not a topology level", quote(&rs.name), plane)));
            continue;
        }
        if rs.scope_cols.len() < non_virtual {
            errs.push(Finding::at(rs.pos.line, format!("rolestore {} declares `plane {}` but names only {} of the {} non-virtual levels in `scope` — every level below the plane must be named so the floor can pin it NULL, or an assignment scoped there would satisfy the plane's check", quote(&rs.name), plane, rs.scope_cols.len(), non_virtual)));
        }
    }
    errs
}

fn check_emit_sites(s: &Spec, vocabs: &HashSet<String>) -> Vec<Finding> {
    let mut errs = Vec::new();
    for pr in &s.procedures {
        if !vocabs.contains(&pr.emit_site) {
            errs.push(Finding::at(pr.pos.line, format!("procedures block targets unknown vocabulary {} (V10)", quote(&pr.emit_site))));
        }
    }
    for u in &s.ungoverned {
        if !vocabs.contains(&u.emit_site) {
            errs.push(Finding::at(u.pos.line, format!("ungoverned block targets unknown vocabulary {} (V10)", quote(&u.emit_site))));
        }
    }
    errs
}

fn validate_predicate_only_referenced(s: &Spec) -> Vec<Finding> {
    let mut referenced = HashSet::new();
    for obj in &s.objects {
        for r in &obj.relations {
            if let Repr::Object(vo) = &r.repr {
                referenced.insert(format!("{}.{}", vo.object, vo.verb));
            }
        }
    }
    let mut errs = Vec::new();
    for obj in &s.objects {
        for pm in &obj.perms {
            if pm.predicate_only && !referenced.contains(&format!("{}.{}", obj.name, pm.verb)) {
                errs.push(Finding::at(pm.pos.line, format!("permission {}.{} is `predicate` (predicate-only) but no `via object {}->{}` borrows it — a lent authority that is never borrowed is dead, unverified SQL", obj.name, pm.verb, obj.name, pm.verb)));
            }
        }
    }
    errs
}

fn validate_object(s: &Spec, o: &Object, chain: &[&Level]) -> Vec<Finding> {
    let mut errs = Vec::new();
    errs.extend(check_scope_path(s, o, chain));
    errs.extend(check_level_entity(o, chain));
    let (rels, rel_errs) = check_object_relations(s, o);
    errs.extend(rel_errs);
    errs.extend(check_grant_rel_count(o));
    errs.extend(check_track_changelog(o));
    errs.extend(check_gates(s, o, &rels));
    for pm in &o.perms {
        errs.extend(validate_perm(s, o, pm, &rels));
    }
    errs.extend(check_requires(s, o, &rels));
    errs.extend(validate_admits(s, o, &rels));
    errs.extend(check_field_access(o));
    errs
}

fn check_scope_path(s: &Spec, o: &Object, chain: &[&Level]) -> Vec<Finding> {
    let leaf_level = o.scoped.last().map_or("", String::as_str);
    let leaf_is_virtual = s.level_by_name(leaf_level).is_some_and(|l| l.is_virtual);
    if o.scoped.is_empty() {
        return vec![Finding::at(o.pos.line, format!("object {} declares no scoped path (V6)", quote(&o.name)))];
    }
    if leaf_is_virtual {
        if o.scoped.len() != 1 {
            return vec![Finding::at(
                o.pos.line,
                format!(
                    "object {} is scoped at virtual level {} (a global object) but declares a multi-level path {} — a global object carries no containment columns (V6)",
                    quote(&o.name),
                    quote(leaf_level),
                    fmt_slice(&o.scoped)
                ),
            )];
        }
        return check_scope_wildcards(s, o);
    }
    let Ok(paths) = topology::ancestor_paths(s, leaf_level) else {
        return vec![Finding::at(o.pos.line, format!("object {} scoped leaf {} is not a topology level (V6)", quote(&o.name), quote(leaf_level)))];
    };
    let in_ancestry: HashSet<&str> = paths.iter().flatten().map(|l| l.name.as_str()).collect();
    let want: Vec<&str> = chain.iter().filter(|l| in_ancestry.contains(l.name.as_str()) && !l.is_virtual).map(|l| l.name.as_str()).collect();
    let ok = want.len() == o.scoped.len() && want.iter().zip(&o.scoped).all(|(w, s)| w == s);
    if !ok {
        return vec![Finding::at(
            o.pos.line,
            format!(
                "object {} scoped {} is not the non-virtual ancestry of {} in topological order (expected {}) (V6)",
                quote(&o.name),
                fmt_slice(&o.scoped),
                quote(leaf_level),
                fmt_slice(&want)
            ),
        )];
    }
    check_scope_wildcards(s, o)
}

fn check_scope_wildcards(s: &Spec, o: &Object) -> Vec<Finding> {
    let mut errs = Vec::new();
    for lvl in &o.scope_wildcards {
        if s.level_is_virtual(lvl) {
            errs.push(Finding::at(o.pos.line, format!("object {} declares `{} wildcard`, but {} is a virtual level — containment emits no conjunct for a virtual level, so the marker could never narrow or widen anything (V6)", quote(&o.name), lvl, quote(lvl))));
        } else if o.is_level_entity() && lvl == o.level() {
            errs.push(Finding::at(o.pos.line, format!("object {} declares `{} wildcard`, but {} is its own level, whose scope column is the primary key {} — a primary key is never NULL, so the marker could never match a row (V6)", quote(&o.name), lvl, quote(lvl), quote(o.pk()))));
        }
        let mut seen = HashSet::new();
        for v in o.scope_wildcard_verbs.get(lvl).map_or(&[][..], Vec::as_slice) {
            if op_to_cmd(v).is_empty() {
                errs.push(Finding::at(
                    o.pos.line,
                    format!(
                        "object {} wildcard at {} confers unknown verb {} (expected select, insert, update or delete)",
                        quote(&o.name),
                        quote(lvl),
                        quote(v)
                    ),
                ));
            }
            if seen.contains(v) {
                errs.push(Finding::at(o.pos.line, format!("object {} wildcard at {} names verb {} twice", quote(&o.name), quote(lvl), quote(v))));
            }
            seen.insert(v.clone());
        }
    }
    for lvl in &o.scope_exact {
        if s.level_is_virtual(lvl) {
            errs.push(Finding::at(
                o.pos.line,
                format!(
                    "object {} declares `{} exact`, but {} is a virtual level — containment emits no conjunct for a virtual level (V6)",
                    quote(&o.name),
                    lvl,
                    quote(lvl)
                ),
            ));
        } else if o.is_level_entity() && lvl == o.level() {
            errs.push(Finding::at(
                o.pos.line,
                format!(
                    "object {} declares `{} exact`, but {} is its own level, whose scope column is the primary key {} — a primary key is never NULL, so plain containment already is exact (V6)",
                    quote(&o.name),
                    lvl,
                    quote(lvl),
                    quote(o.pk())
                ),
            ));
        }
    }
    for lvl in o.scope_wildcard_verbs.keys() {
        if !o.scope_is_wildcard(lvl) {
            errs.push(Finding::at(o.pos.line, format!("object {} bounds a wildcard at level {} that it does not declare", quote(&o.name), quote(lvl))));
        }
    }
    errs
}

fn check_level_entity(o: &Object, chain: &[&Level]) -> Vec<Finding> {
    let Some(level) = &o.level else { return Vec::new() };
    let mut errs = Vec::new();
    if !chain.iter().any(|l| &l.name == level) {
        errs.push(Finding::at(o.pos.line, format!("object {} declares level {} which is not a topology level", quote(&o.name), quote(level))));
    }
    if o.scoped.last() != Some(level) {
        errs.push(Finding::at(o.pos.line, format!("object {} level {} must be its deepest scoped level", quote(&o.name), quote(level))));
    }
    errs
}

fn check_object_relations<'a>(s: &Spec, o: &'a Object) -> (Rels<'a>, Vec<Finding>) {
    let mut errs = Vec::new();
    let mut rels: Rels = HashMap::new();
    for r in &o.relations {
        if rels.contains_key(r.name.as_str()) {
            errs.push(Finding::at(r.pos.line, format!("object {} has duplicate relation {}", quote(&o.name), quote(&r.name))));
        }
        rels.insert(r.name.as_str(), r);
        match &r.repr {
            Repr::MemberIn(mi) if s.level_by_name(&mi.level).is_none() => errs.push(Finding::at(
                r.pos.line,
                format!("object {} relation {} via memberin references unknown level {}", quote(&o.name), quote(&r.name), quote(&mi.level)),
            )),
            Repr::Closure(c) => errs.extend(check_closure_relation(s, o, r, c)),
            Repr::Object(vo) => errs.extend(validate_borrow_operation(s, r, vo)),
            Repr::Role => errs.extend(check_via_role(s, o, r)),
            _ => {}
        }
        if let Repr::Group(g) = &r.repr
            && g.materialized
            && r.types.len() > 1
        {
            errs.push(Finding::at(r.pos.line, format!("object {} relation {} is `via group ... materialized` with multiple kinds {} — a materialized via-group must be single-kind (the flat tags only one principal_kind and the floor matches the id alone)", quote(&o.name), quote(&r.name), fmt_slice(&r.types))));
        }
        if let Repr::Grant(g) = &r.repr
            && g.is_async
            && !g.tracked
        {
            errs.push(Finding::at(r.pos.line, format!("object {} relation {} is `via grant ... async` without `tracked` — the async affordance index is maintained off the changelog, which requires `tracked`", quote(&o.name), quote(&r.name))));
        }
        if let Repr::Grant(g) = &r.repr {
            errs.extend(check_grant_admits(o, r, g));
        }
        errs.extend(check_transient_relation(s, o, r));
    }
    (rels, errs)
}

fn check_grant_admits(o: &Object, r: &Relation, g: &ViaGrant) -> Vec<Finding> {
    let at = |msg: String| Finding::at(r.pos.line, format!("object {} relation {} {msg}", quote(&o.name), quote(&r.name)));
    let mut errs = Vec::new();
    for (i, rule) in g.admits.iter().enumerate() {
        if g.admits[..i].iter().any(|earlier| earlier.access == rule.access) {
            errs.push(at(format!("says what {} admits twice — list every class it admits on one `{} admits` clause", quote(&rule.access), rule.access)));
        }
        for (j, also) in rule.also.iter().enumerate() {
            if *also == rule.access {
                errs.push(at(format!("says {} admits itself — a grant term always admits its own class", quote(&rule.access))));
            } else if rule.also[..j].contains(also) {
                errs.push(at(format!("says {} admits {} twice", quote(&rule.access), quote(also))));
            } else if g.admits.iter().any(|other| other.access == *also) {
                errs.push(at(format!(
                    "says {} admits {}, which admits classes of its own — admitting is not transitive, so list on {}'s clause every class it admits",
                    quote(&rule.access),
                    quote(also),
                    rule.access
                )));
            }
        }
    }
    errs
}

fn check_closure_relation(s: &Spec, o: &Object, r: &Relation, c: &ViaClosure) -> Vec<Finding> {
    let at = |msg: String| Finding::at(r.pos.line, format!("object {} relation {}: {msg}", quote(&o.name), quote(&r.name)));
    let mut errs = Vec::new();
    let edge = closure::edge(s, &c.closure);
    if c.ancestor_col == c.descendant_col {
        errs.push(at(format!("closure {} names {} as both of its columns — an edge runs between two", c.closure, quote(&c.ancestor_col))));
    } else if let Some(edge) = &edge {
        if edge.relation_direction(c).is_none() {
            errs.push(at(format!(
                "closure {}({}, {}) matches no edge of the closure, which is ({}, {}) — name its columns ancestor first to reach beneath the caller, descendant first to reach above",
                c.closure, c.ancestor_col, c.descendant_col, edge.ancestor_col, edge.descendant_col
            )));
        }
        if let (Some(mine), Some(theirs)) = (c.base.as_deref(), edge.base)
            && (mine, c.base_id.as_deref().unwrap_or(""), c.base_parent.as_deref().unwrap_or("")) != (theirs.table, theirs.id_col, theirs.parent_col)
        {
            errs.push(at(format!(
                "closure {} is maintained from {}({}, {}), not {}({}, {}) — a closure has one base",
                c.closure,
                theirs.table,
                theirs.id_col,
                theirs.parent_col,
                mine,
                c.base_id.as_deref().unwrap_or(""),
                c.base_parent.as_deref().unwrap_or("")
            )));
        }
    }
    let Some(claim) = &c.claim else {
        let declared_base = edge.is_some_and(|e| e.declared.is_some() && e.base.is_some());
        if c.base.is_none() && !declared_base {
            errs.push(Finding::unplaced(format!(
                "object {} relation {}: a closure keyed on the owner needs `base <table>(id, parent)`",
                quote(&o.name),
                quote(&r.name)
            )));
        }
        return errs;
    };
    let missing = c.missing.as_deref().unwrap_or("");
    if missing != "allow" && missing != "deny" {
        errs.push(Finding::unplaced(format!(
            "object {} relation {}: closure claim {}: missing must be allow or deny, got {}",
            quote(&o.name),
            quote(&r.name),
            quote(claim),
            quote(missing)
        )));
    }
    errs
}

fn check_closures(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for (i, c) in s.closures.iter().enumerate() {
        let at = |msg: String| Finding::at(c.pos.line, format!("closure {} {msg}", quote(&c.table)));
        if s.closures[..i].iter().any(|earlier| earlier.table == c.table) {
            errs.push(at("is declared more than once".into()));
        } else if let Some(earlier) = s.closures[..i].iter().find(|earlier| earlier.definer_base() == c.definer_base()) {
            errs.push(at(format!(
                "and closure {} both name their functions {}_… — give one its own name with `named`",
                quote(&earlier.table),
                c.definer_base()
            )));
        }
        if c.ancestor_col == c.descendant_col {
            errs.push(at(format!("names {} as both its ancestor and its descendant column", quote(&c.ancestor_col))));
        }
        let Some(base) = &c.base else {
            if c.scope_col.is_some() {
                errs.push(at(
                    "declares `scope` with no `base` — the scope column is what maintenance copies and locks on, and nothing maintains this closure".into()
                ));
            }
            continue;
        };
        if base.id_col == base.parent_col {
            errs.push(at(format!("base {} names {} as both its id and its parent column", quote(&base.table), quote(&base.id_col))));
        }
        if base.table == c.table {
            errs.push(at("names itself as its base".into()));
        }
    }
    errs
}

fn check_transient_relation(s: &Spec, o: &Object, r: &Relation) -> Vec<Finding> {
    let transient = r.types.iter().filter(|t| s.subject_by_name(t).is_some_and(|st| st.transient)).count();
    if transient == 0 {
        return Vec::new();
    }
    let mut errs = Vec::new();
    if transient != r.types.len() {
        errs.push(Finding::at(r.pos.line, format!("object {} relation {} mixes a transient subject with standing ones {}: the listing names standing principals and reports a transient one as a claim, so they cannot share a relation", quote(&o.name), quote(&r.name), fmt_slice(&r.types))));
    }
    if !matches!(r.repr, Repr::Column(_)) {
        errs.push(Finding::at(
            r.pos.line,
            format!(
                "object {} relation {} names a transient subject {}: a transient subject is a claim compared to a column of the row (`via <column>`)",
                quote(&o.name),
                quote(&r.name),
                go_type_name(&r.repr)
            ),
        ));
    }
    if r.types.len() > 1 {
        for t in &r.types {
            if s.subject_by_name(t).is_some_and(|st| st.transient_set) {
                errs.push(Finding::at(r.pos.line, format!("object {} relation {} names the transient set {} beside other subjects {}: a set's claim lists values and another subject's claim holds one, so they cannot share a relation", quote(&o.name), quote(&r.name), quote(t), fmt_slice(&r.types))));
                break;
            }
        }
    }
    errs
}

fn check_via_role(s: &Spec, o: &Object, r: &Relation) -> Vec<Finding> {
    if s.default_role_store().is_none() {
        return Vec::new();
    }
    let mut lvl = "";
    if let Some(first) = r.types.first()
        && let Some(st) = s.subject_by_name(first)
        && s.is_platform_role_subject(st)
    {
        lvl = st.anchor();
    }
    if lvl.is_empty()
        && let Some(last) = o.scoped.last()
    {
        lvl = last;
    }
    if lvl.is_empty() {
        return Vec::new();
    }
    if s.preset_level_map().get(lvl).is_none_or(std::vec::Vec::is_empty) {
        return vec![Finding::at(
            r.pos.line,
            format!(
                "object {} relation {} is `via role` at level {}, but no vocabulary declares a preset at that level — the check would compile to an empty key set that can never match",
                quote(&o.name),
                quote(&r.name),
                quote(lvl)
            ),
        )];
    }
    Vec::new()
}

fn check_grant_rel_count(o: &Object) -> Vec<Finding> {
    let n = o.relations.iter().filter(|r| matches!(r.repr, Repr::Grant(_))).count();
    if n > 1 {
        return vec![Finding::unplaced(format!("object {} declares {} `via grant` relations — at most one is allowed", quote(&o.name), n))];
    }
    Vec::new()
}

fn check_track_changelog(o: &Object) -> Vec<Finding> {
    if o.track_owner && o.owner_changelog_cols().is_none() {
        return vec![Finding::at(
            o.pos.line,
            format!("object {} declares `track owner` but has no owner column (a `via <id> where <kind> = ...` relation)", quote(&o.name)),
        )];
    }
    if o.track_visibility && o.mode_changelog_col().is_none() {
        return vec![Finding::at(o.pos.line, format!("object {} declares `track visibility` but has no `mode <col>` term", quote(&o.name)))];
    }
    Vec::new()
}

fn check_gates(s: &Spec, o: &Object, rels: &Rels) -> Vec<Finding> {
    let has_verb = |obj: &Object, verb: &str| obj.perms.iter().any(|p| p.verb == verb);
    let mut errs = Vec::new();
    for g in &o.gates {
        if !has_verb(o, &g.verb) {
            errs.push(Finding::at(
                g.pos.line,
                format!(
                    "object {} gate `{} via {} -> {}` gates verb {}, which the object does not declare as a permission",
                    quote(&o.name),
                    g.verb,
                    g.relation,
                    g.perm,
                    quote(&g.verb)
                ),
            ));
        }
        let Some(r) = rels.get(g.relation.as_str()) else {
            errs.push(Finding::at(g.pos.line, format!("object {} gate references unknown relation {}", quote(&o.name), quote(&g.relation))));
            continue;
        };
        if r.types.is_empty() {
            errs.push(Finding::at(g.pos.line, format!("object {} gate relation {} resolves to no object type", quote(&o.name), quote(&g.relation))));
            continue;
        }
        for tname in &r.types {
            let Some(target) = s.object_by_name(tname) else {
                errs.push(Finding::at(
                    g.pos.line,
                    format!("object {} gate relation {} targets {}, which is not a governed object", quote(&o.name), quote(&g.relation), quote(tname)),
                ));
                continue;
            };
            if !has_verb(target, &g.perm) {
                errs.push(Finding::at(
                    g.pos.line,
                    format!(
                        "object {} gate `{} via {} -> {}`: target object {} has no permission {}",
                        quote(&o.name),
                        g.verb,
                        g.relation,
                        g.perm,
                        quote(tname),
                        quote(&g.perm)
                    ),
                ));
            }
        }
    }
    errs
}

fn perm_positive(n: &PermNode) -> bool {
    match n {
        PermNode::Leaf(_) => true,
        PermNode::Not(_) => false,
        PermNode::And(kids) => kids.iter().any(perm_positive),
        PermNode::Or(kids) => kids.iter().all(perm_positive) && !kids.is_empty(),
    }
}

fn keyed_relation(rels: &Rels, t: &Term) -> bool {
    rels.get(t.ident()).is_some_and(|r| match &r.repr {
        Repr::Edge(e) => e.key.is_some(),
        Repr::Conditions(c) => c.key.is_some(),
        _ => false,
    })
}

fn slot_bound_relation(rels: &Rels, t: &Term) -> bool {
    rels.get(t.ident()).is_some_and(|r| match &r.repr {
        Repr::Edge(e) => e.slot.is_some(),
        Repr::Composition(c) => c.slot.is_some(),
        _ => false,
    })
}

fn check_brackets(what: &str, body: &PermNode, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    if let Some(t) = conditions_admitting(body, rels) {
        errs.push(format!("uses `{what}` in which {} would admit a caller by itself — {CONDITIONS_NARROW}", t.display()));
    }
    if body.is_nil() || !perm_positive(body) {
        errs.push(format!("uses `{what}` whose brackets hold no positive term — a `not` inside them must be combined with `and` with a positive term"));
    }
    if let Some(row) = row_term_admitting(body) {
        errs.push(format!(
            "uses `{what}` in which {} would admit a caller by itself — a test of the row, the element or the declared row only narrows another term",
            row.display()
        ));
    }
    for inner in body.leaves() {
        if !inner.grant_ref().is_empty() || matches!(inner.builtin(), "scoped" | "public" | "open" | "self") {
            errs.push(format!("uses {} inside `{what}` — a term that is placed outside the object's containment cannot be bound there", inner.display()));
        }
    }
    errs
}

fn check_declared_scope(some: &str, t: &Term, rels: &Rels) -> Vec<String> {
    let Some(scope) = t.declared_scope() else { return Vec::new() };
    let what = format!("{} {}", if scope.quantifier == demesne_syntax::Quantifier::Every { "every" } else { "none" }, scope.var);
    let mut errs = check_brackets(&what, &scope.body, rels);
    for inner in scope.body.leaves() {
        if matches!(inner.builtin(), "some" | "declared") {
            errs.push(format!("nests {} inside `{what}` in `some {some}` — one element and one declared row are bound at a time", inner.display()));
        } else if inner.builtin() == "holds_at" {
            errs.push(format!("uses {} outside a composition's `path` — it judges an element at a row the path declares", inner.display()));
        } else if slot_bound_relation(rels, inner) && !keyed_relation(rels, inner) && rels.get(inner.ident()).is_some_and(|r| matches!(r.repr, Repr::Edge(_))) {
            errs.push(format!("uses relation {}, which binds a slot without a key", quote(inner.ident())));
        }
    }
    errs
}

fn check_some_scopes(tree: &PermNode, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    for t in tree.leaves() {
        if t.builtin() == "element" {
            errs.push(format!("uses {} outside a `some` — it tests the element a `some` has bound", t.display()));
        } else if t.builtin() == "holds_at" {
            errs.push(format!("uses {} outside a composition's `path` — it judges an element at a row the path declares", t.display()));
        } else if matches!(t.builtin(), "declared" | "slot" | "slot_held") {
            errs.push(format!("uses {} outside a `some` — `every`, `none` and `@slot` read the rows declared for the element a `some` has bound", t.display()));
        } else if keyed_relation(rels, t) {
            errs.push(format!("uses keyed relation {} outside a `some` — its `key` column is matched against the element a `some` binds", quote(t.ident())));
        }
        let Some(scope) = t.some_scope() else { continue };
        errs.extend(check_brackets(&format!("some {}", scope.var), &scope.body, rels));
        for inner in scope.body.leaves() {
            if inner.builtin() == "some" {
                errs.push(format!("nests a `some` inside `some {}` — one element is bound at a time", scope.var));
            } else if inner.builtin() == "holds_at" {
                errs.push(format!("uses {} outside a composition's `path` — it judges an element at a row the path declares", inner.display()));
            } else if matches!(inner.builtin(), "slot" | "slot_held") {
                errs.push(format!("uses {} outside an `every` or `none` — it tests the declared row one of them has bound", inner.display()));
            } else if slot_bound_relation(rels, inner) {
                errs.push(format!(
                    "uses slot-bound relation {} outside an `every` or `none` — its `slot` column is matched against the declared row one of them binds",
                    quote(inner.ident())
                ));
            }
            errs.extend(check_declared_scope(&scope.var, inner, rels));
        }
    }
    errs
}

fn check_holds_every(s: &Spec, o: &Object, t: &Term) -> Vec<String> {
    let Some((_, _, level)) = t.holds_every() else { return Vec::new() };
    let Some(lvl) = s.level_by_name(level).filter(|l| !l.is_virtual) else {
        return vec![format!("uses {}, but {} is not a level that carries a scope column", t.display(), quote(level))];
    };
    let Some(entity) = s.objects.iter().find(|e| e.level() == lvl.name) else {
        return vec![format!("uses {}, but no object declares `level {level}`, so nothing says which values exist there", t.display())];
    };
    entity
        .scoped
        .iter()
        .filter(|l| *l != level && !s.level_is_virtual(l) && !contains(&o.scoped, l))
        .map(|l| {
            format!(
                "uses {}, but object {} is not scoped at {}, so a value's place there cannot be checked against the row's",
                t.display(),
                quote(&o.name),
                quote(l)
            )
        })
        .collect()
}

fn require_positive(n: &PermNode) -> bool {
    match n {
        PermNode::Leaf(_) => true,
        PermNode::Not(k) => is_row_leaf(k),
        PermNode::And(kids) => kids.iter().any(require_positive),
        PermNode::Or(kids) => kids.iter().all(require_positive) && !kids.is_empty(),
    }
}

fn narrows_only(n: &PermNode) -> bool {
    is_row_leaf(n) || matches!(n, PermNode::Leaf(t) if t.builtin() == "slot_held")
}

fn row_term_admitting(n: &PermNode) -> Option<&Term> {
    match n {
        PermNode::Leaf(t) => narrows_only(n).then_some(t),
        PermNode::Not(k) => {
            if narrows_only(k) {
                return k.term();
            }
            row_term_admitting(k)
        }
        PermNode::And(kids) => row_term_admitting_conjunction(kids),
        PermNode::Or(kids) => kids.iter().find_map(row_term_admitting),
    }
}

fn row_term_admitting_conjunction(kids: &[PermNode]) -> Option<&Term> {
    let mut row_term: Option<&Term> = None;
    let mut grants = false;
    for k in kids {
        let row_leaf = match k {
            PermNode::Not(inner) if narrows_only(inner) => Some(inner.as_ref()),
            _ if narrows_only(k) => Some(k),
            _ => None,
        };
        if let Some(leaf) = row_leaf {
            row_term = leaf.term();
            continue;
        }
        if let Some(t) = row_term_admitting(k) {
            return Some(t);
        }
        grants |= perm_positive(k);
    }
    if row_term.is_some() && !grants { row_term } else { None }
}

fn conditions_leaf<'a>(n: &'a PermNode, rels: &Rels) -> Option<&'a Term> {
    let leaf = match n {
        PermNode::Not(inner) => inner.as_ref(),
        other => other,
    };
    leaf.term().filter(|t| rels.get(t.ident()).is_some_and(|r| matches!(r.repr, Repr::Conditions(_))))
}

fn conditions_admitting<'a>(n: &'a PermNode, rels: &Rels) -> Option<&'a Term> {
    if let Some(t) = conditions_leaf(n, rels) {
        return Some(t);
    }
    match n {
        PermNode::Leaf(_) => None,
        PermNode::Not(k) => conditions_admitting(k, rels),
        PermNode::Or(kids) => kids.iter().find_map(|k| conditions_admitting(k, rels)),
        PermNode::And(kids) => {
            let mut narrowing = None;
            let mut grants = false;
            for k in kids {
                if let Some(t) = conditions_leaf(k, rels) {
                    narrowing = Some(t);
                } else if let Some(t) = conditions_admitting(k, rels) {
                    return Some(t);
                } else {
                    grants |= perm_positive(k) && !is_row_leaf(k);
                }
            }
            narrowing.filter(|_| !grants)
        }
    }
}

const CONDITIONS_NARROW: &str =
    "stored conditions hold for a row that stores none, so they only narrow another term: write the relation inside an `and`, beside a term that grants";

fn check_perm_polarity(o: &Object, pm: &Perm) -> Option<Finding> {
    if !pm.tree.is_nil() && !perm_positive(&pm.tree) {
        return Some(Finding::at(
            pm.pos.line,
            format!(
                "permission {}.{} is not positively gated — a `not` (exclusion) must be combined with `and` with a positive grant, never used alone or as a union (`+`/`or`) branch",
                o.name, pm.verb
            ),
        ));
    }
    if let Some(t) = conditions_admitting(&pm.tree, &crate::analysis::rels_of(o)) {
        return Some(Finding::at(
            pm.pos.line,
            format!("permission {}.{} uses {} where it would admit a caller by itself — {CONDITIONS_NARROW}", o.name, pm.verb, t.display()),
        ));
    }
    if let Some(t) = row_term_admitting(&pm.tree) {
        return Some(Finding::at(
            pm.pos.line,
            format!(
                "permission {}.{} uses {} where it would admit a caller by itself — a row term tests the row and names nobody, so it only narrows another term: write it inside an `and`, beside a term that grants",
                o.name,
                pm.verb,
                t.display()
            ),
        ));
    }
    None
}

fn admits_alone(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if !t.grant_ref().is_empty() || matches!(t.builtin(), "self" | "public"))
}

fn is_scoped(n: &PermNode) -> bool {
    matches!(n, PermNode::Leaf(t) if t.builtin() == "scoped")
}

fn alternatives(tree: &PermNode) -> &[PermNode] {
    match tree {
        PermNode::Or(kids) => kids,
        n => std::slice::from_ref(n),
    }
}

fn lone_admitters<'a>(n: &'a PermNode, out: &mut Vec<&'a PermNode>) {
    match n {
        _ if admits_alone(n) => out.push(n),
        PermNode::Leaf(_) => {}
        PermNode::Not(k) => lone_admitters(k, out),
        PermNode::And(kids) | PermNode::Or(kids) => kids.iter().for_each(|k| lone_admitters(k, out)),
    }
}

fn without_lone_admitters(n: &PermNode) -> Option<PermNode> {
    match n {
        _ if admits_alone(n) => None,
        PermNode::Leaf(_) => Some(n.clone()),
        PermNode::Not(k) => without_lone_admitters(k).map(|k| PermNode::Not(Box::new(k))),
        PermNode::And(kids) | PermNode::Or(kids) => {
            let mut rest: Vec<PermNode> = kids.iter().filter_map(without_lone_admitters).collect();
            match rest.len() {
                0 => None,
                1 => rest.pop(),
                _ if matches!(n, PermNode::And(_)) => Some(PermNode::And(rest)),
                _ => Some(PermNode::Or(rest)),
            }
        }
    }
}

fn check_nested_lone_admitters(o: &Object, pm: &Perm) -> Option<Finding> {
    let alts = alternatives(&pm.tree);
    let mut nested = Vec::new();
    let mut inside = None;
    for alt in alts.iter().filter(|a| !admits_alone(a)) {
        let before = nested.len();
        lone_admitters(alt, &mut nested);
        if inside.is_none() && nested.len() > before {
            inside = Some(alt);
        }
    }
    let inside = inside?;
    let mut compiled: Vec<String> = Vec::new();
    for n in alts.iter().filter_map(|a| if admits_alone(a) { Some(a.clone()) } else { without_lone_admitters(a) }).chain(nested.iter().map(|n| (*n).clone())) {
        let text = n.display();
        if !compiled.contains(&text) {
            compiled.push(text);
        }
    }
    let terms: Vec<String> = nested.iter().map(|n| format!("`{}`", n.display())).collect();
    Some(Finding::at(
        pm.pos.line,
        format!(
            "permission {}.{} writes {} inside `{}`, but a @self, @public or `via grant` term admits its callers on its own wherever it is written, so the permission compiles as `{}`, wider than it reads: write each such term as its own alternative",
            o.name,
            pm.verb,
            terms.join(", "),
            inside.display(),
            compiled.join(" + ")
        ),
    ))
}

fn scoped_union(n: &PermNode) -> Option<&[PermNode]> {
    match n {
        PermNode::Leaf(_) => None,
        PermNode::Or(kids) if kids.iter().any(is_scoped) && kids.iter().any(|k| !is_scoped(k) && !admits_alone(k)) => Some(kids),
        PermNode::Or(kids) | PermNode::And(kids) => kids.iter().find_map(scoped_union),
        PermNode::Not(k) => scoped_union(k),
    }
}

fn check_absorbed_scoped(o: &Object, pm: &Perm) -> Option<Finding> {
    let union = scoped_union(&pm.tree)?;
    let rest: Vec<String> = union.iter().filter(|k| !is_scoped(k)).map(PermNode::display).collect();
    let ordinary: Vec<String> = union.iter().filter(|k| !is_scoped(k) && !admits_alone(k)).map(|k| format!("`{}`", k.display())).collect();
    Some(Finding::at(
        pm.pos.line,
        format!(
            "permission {}.{} writes `{}`, which compiles as `{}`: every term is already held to the row's scope, so `@scoped` beside {} adds no one; write `@scoped` alone to admit every caller in scope, or drop it",
            o.name,
            pm.verb,
            PermNode::Or(union.to_vec()).display(),
            rest.join(" + "),
            ordinary.join(" and ")
        ),
    ))
}

fn validate_perm(s: &Spec, o: &Object, pm: &Perm, rels: &Rels) -> Vec<Finding> {
    let mut errs = Vec::new();
    errs.extend(check_perm_polarity(o, pm));
    errs.extend(check_nested_lone_admitters(o, pm));
    errs.extend(check_absorbed_scoped(o, pm));
    let mut has = HashSet::new();
    for l in &pm.layers {
        if !KNOWN_LAYERS.contains(&l.as_str()) {
            errs.push(Finding::at(pm.pos.line, format!("permission {}.{} has unknown layer {}", o.name, pm.verb, quote(l))));
        }
        has.insert(l.as_str());
    }
    if pm.layers.is_empty() {
        errs.push(Finding::at(pm.pos.line, format!("permission {}.{} has no layer tag", o.name, pm.verb)));
    }
    let (has_rls, has_kernel, has_check) = (has.contains("rls"), has.contains("kernel"), has.contains("check"));
    if pm.guard.is_some() && !has_rls {
        errs.push(Finding::at(pm.pos.line, format!("permission {}.{} has a guard but is not @rls", o.name, pm.verb)));
    }
    errs.extend(check_perm_maps(o, pm, has_rls, has_kernel, has_check));
    errs.extend(check_perm_terms(s, o, pm, rels));
    errs
}

fn check_perm_maps(o: &Object, pm: &Perm, has_rls: bool, has_kernel: bool, has_check: bool) -> Vec<Finding> {
    let mut errs = Vec::new();
    let maps = pm.maps();
    if is_perm_key_lit(maps) && (has_rls || has_kernel) {
        errs.push(Finding::at(
            pm.pos.line,
            format!(
                "permission {}.{} maps to capability {} but is tagged @rls/@kernel — a row layer cannot distinguish a verb; use @pdp (V4)",
                o.name,
                pm.verb,
                quote(maps)
            ),
        ));
    }
    if has_rls && !maps.is_empty() && !table_op(maps) {
        errs.push(Finding::at(
            pm.pos.line,
            format!("permission {}.{} is @rls but maps to {}, not a table op (select|insert|update|delete) (V4)", o.name, pm.verb, quote(maps)),
        ));
    }
    if pm.predicate_only {
        if !has_rls {
            errs.push(Finding::at(
                pm.pos.line,
                format!("permission {}.{} is `predicate` but not @rls — a predicate-only permission lends an @rls authority to other objects", o.name, pm.verb),
            ));
        }
        if !maps.is_empty() {
            errs.push(Finding::at(
                pm.pos.line,
                format!("permission {}.{} is both `predicate` and `maps {}` — a predicate-only permission emits no policy of its own", o.name, pm.verb, maps),
            ));
        }
    }
    if has_check && !maps.is_empty() {
        errs.push(Finding::at(
            pm.pos.line,
            format!("permission {}.{} is @check but also `maps {}` — a @check permission emits a callable point-check, not a policy", o.name, pm.verb, maps),
        ));
    }
    errs
}

fn check_perm_terms(s: &Spec, o: &Object, pm: &Perm, rels: &Rels) -> Vec<Finding> {
    let (has_rls, has_kernel, has_pdp, has_check) = (pm.has_layer("rls"), pm.has_layer("kernel"), pm.has_layer("pdp"), pm.has_layer("check"));
    let mut errs = Vec::new();
    let has_pred = has_rls || has_check;
    let at = |what: &str| Finding::at(pm.pos.line, format!("permission {}.{} {what}", o.name, pm.verb));
    errs.extend(check_some_scopes(&pm.tree, rels).iter().map(|e| at(e)));
    for t in pm.tree.leaves_deep() {
        if matches!(t.builtin(), "some" | "element" | "declared" | "slot" | "slot_held" | "holds_at") {
            continue;
        }
        if !t.grant_ref().is_empty() {
            match s.grant_by_name(t.grant_ref()) {
                None => errs.push(at(&format!("references unknown grant {} (via grant)", quote(t.grant_ref())))),
                Some(g) if g.claim_key.is_some() => {
                    errs.push(Finding::at(pm.pos.line, format!("claim grant {} is containment reach and cannot be an authority term", quote(&g.name))));
                }
                Some(_) => {}
            }
            if !has_pred {
                errs.push(at(&format!("uses `via grant {}` but is not @rls", t.grant_ref())));
            }
        } else if t.mode_col().is_some() {
            if !has_pred {
                errs.push(at("uses a mode term but is not @rls"));
            }
            if !t.mode_scope().is_empty() && s.subject_by_name(t.mode_scope()).is_none() {
                errs.push(at(&format!("mode term scope `for {}` names no subject", t.mode_scope())));
            }
        } else if t.builtin() == "row" {
            if t.row_col().is_empty() || (t.row_val().is_empty() && !t.row_null()) {
                errs.push(at("uses @row with an empty column or value — `@row(<column>, \"<value>\")`"));
            }
            if !has_pred {
                errs.push(at("uses @row but compiles no row predicate — a row term is a test of the row and the decision point cannot read it"));
            }
        } else if t.holds_every().is_some() {
            errs.extend(check_holds_every(s, o, t).iter().map(|e| at(e)));
            if !has_pred {
                errs.push(at("uses @holds … every but compiles no row predicate — it reads an array column of the row, which the decision point cannot"));
            }
        } else if !t.builtin().is_empty() {
            errs.extend(check_builtin_term(s, o, pm, t, rels, has_pred, has_pdp));
        } else if let Some((_, access)) = grant_selector(t.ident(), rels) {
            if access.is_empty() {
                errs.push(at(&format!("grant term {} has an empty access class (use grantee:read|write|delete)", quote(t.ident()))));
            }
            if !has_pred {
                errs.push(at(&format!("uses grant term {} but is not @rls (V3/V4)", quote(t.ident()))));
            }
        } else if is_perm_key_lit(t.ident()) {
            if !has_pdp || has_rls || has_kernel {
                errs.push(at(&format!("uses capability term {} outside a @pdp-only permission (V3/V4)", quote(t.ident()))));
            }
        } else if !rels.contains_key(t.ident()) {
            errs.push(at(&format!("references unknown relation {} (V3)", quote(t.ident()))));
        }
    }
    errs
}

#[expect(clippy::many_single_char_names, reason = "s, o, t, g and u name the spec, object, term, grant and grant use throughout this crate")]
fn check_builtin_term(s: &Spec, o: &Object, pm: &Perm, t: &Term, rels: &Rels, has_rls: bool, has_pdp: bool) -> Vec<Finding> {
    let mut errs = Vec::new();
    let at = |what: &str| Finding::at(pm.pos.line, format!("permission {}.{} {what}", o.name, pm.verb));
    let b = t.builtin();
    if b == "external" {
        errs.push(at(&format!(
            "uses @external({}) — an adopter-supplied predicate may appear only in a `require` clause, so it can subtract authority and never add it (V14)",
            t.external_fn()
        )));
    } else if !KNOWN_BUILTINS.contains(&b) {
        errs.push(at(&format!("uses unknown builtin @{b} (app_scope|scoped|session|open|store_manage|public|kind|self|within|holds)")));
    }
    for ex in t.exclude_rels() {
        match rels.get(ex.as_str()) {
            None => errs.push(at(&format!("@app_scope(exclude {}) names no relation", quote(ex)))),
            Some(r) if !matches!(r.repr, Repr::Column(_)) => {
                errs.push(at(&format!("@app_scope(exclude {}) must exclude an owner column relation", quote(ex))));
            }
            Some(_) => {}
        }
    }
    if b == "open" && pm.maps() != "insert" {
        errs.push(at(&format!(
            "uses @open but maps to {} — @open is only valid on an insert (a bootstrap write the row engine cannot gate)",
            quote(pm.maps())
        )));
    }
    if b == "public" && pm.maps() != "select" {
        errs.push(at(&format!("uses @public but maps to {} — @public is a world-read grant, valid only on select", quote(pm.maps()))));
    }
    match b {
        "kind" => {
            if t.kind_val().is_empty() {
                errs.push(at("uses @kind with an empty value — `@kind(\"<value>\")`"));
            }
            if !has_rls {
                errs.push(at("uses @kind but is not @rls"));
            }
        }
        "claim" if t.claim_absent() => {
            errs.push(at(&format!(
                "uses {} — a test that a claim is absent names nobody a permission could admit, so it may appear only in a `require` clause",
                t.display()
            )));
        }
        "claim" => {
            if t.claim_key().is_empty() || t.claim_val().is_empty() {
                errs.push(at("uses @claim with an empty key or value — `@claim(\"<key>\", \"<value>\")`"));
            }
            if !has_rls {
                errs.push(at("uses @claim but is not @rls — a claim is a row-layer test and the decision point cannot read it"));
            }
        }
        "self" => {
            if t.self_col().is_empty() {
                errs.push(at("uses @self with no column — `@self(<column>)`"));
            }
            if !has_rls {
                errs.push(at("uses @self but is not @rls"));
            }
        }
        "within" if t.within_exact() => {
            errs.push(at(&format!(
                "uses {} — an exact level test admits a request that names no {}, so it may appear only in a `require` clause; scope the object `{} exact` to contain it that way",
                t.display(),
                t.within_level(),
                t.within_level()
            )));
        }
        "within" => {
            if s.level_by_name(t.within_level()).is_none() {
                errs.push(at(&format!("uses @within({}) which is not a topology level", quote(t.within_level()))));
            }
            if !has_rls {
                errs.push(at("uses @within but is not @rls"));
            }
        }
        "holds" => errs.extend(check_holds_term(s, o, pm, t, has_rls, has_pdp)),
        _ => {}
    }
    errs
}

fn check_holds_term(s: &Spec, o: &Object, pm: &Perm, t: &Term, has_pred: bool, has_pdp: bool) -> Vec<Finding> {
    let mut errs = Vec::new();
    let at = |what: &str| Finding::at(pm.pos.line, format!("permission {}.{} {what}", o.name, pm.verb));
    let perm = t.holds_perm();
    if perm.is_empty() {
        errs.push(at("uses @holds with an empty verb — `@holds(<domain>:<verb>)`"));
    }
    if has_pdp {
        errs.push(at(&format!(
            "uses @holds inside a @pdp permission — a @pdp permission already checks held capabilities; write the permission key {} as a bare term",
            quote(perm)
        )));
    } else if !has_pred {
        errs.push(at("uses @holds but is not @rls or @check"));
    }
    let rs = match s.holds_role_store(perm) {
        Ok(rs) => rs,
        Err(e) => {
            errs.push(at(&format!("uses @holds({}): {e}", quote(perm))));
            return errs;
        }
    };
    if o.scoped.last().is_some_and(|l| s.level_is_virtual(l)) && s.rolestore_plane_depth(rs) > 0 {
        errs.push(at(&format!(
            "uses @holds on a global object against rolestore {}, whose assignments are scoped — the check keys on the row's scope columns, which a global object does not carry; give the rolestore a `plane` at or above the object's level",
            quote(&rs.name)
        )));
    }
    if rs.perms_col.is_none() {
        errs.push(at(&format!(
            "uses @holds but rolestore {} declares no `permissions` column — the floor matches `p_perm = ANY(<perms>)` and cannot expand preset keys at runtime",
            quote(&rs.name)
        )));
    }
    let v = match s.rolestore_vocab(rs) {
        Ok(v) => v,
        Err(e) => {
            errs.push(at(&format!("uses @holds: {e}")));
            return errs;
        }
    };
    if !perm.is_empty() && !v.permissions.iter().any(|p| p == perm) {
        errs.push(at(&format!("uses @holds({}), which is not a permission of vocabulary {}", quote(perm), quote(&v.name))));
    }
    errs
}

fn check_requires(s: &Spec, o: &Object, rels: &Rels) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut seen = HashSet::new();
    for rq in &o.requires {
        if seen.contains(&rq.verb) {
            errs.push(Finding::at(
                rq.pos.line,
                format!("object {} declares `require {}` more than once — a permission carries at most one restrictive clause", quote(&o.name), rq.verb),
            ));
            continue;
        }
        seen.insert(rq.verb.clone());
        let Some(pm) = o.perms.iter().find(|p| p.verb == rq.verb) else {
            errs.push(Finding::at(
                rq.pos.line,
                format!(
                    "object {} requires {} but declares no permission {} — a RESTRICTIVE policy with no permissive policy beside it denies every caller (V13)",
                    quote(&o.name),
                    quote(&rq.verb),
                    quote(&rq.verb)
                ),
            ));
            continue;
        };
        if !pm.has_layer("rls") && !pm.has_layer("check") {
            errs.push(Finding::at(rq.pos.line, format!("object {} requires {}, but permission {} compiles no row predicate (layers {}) — a `require` narrows a predicate and has nothing to narrow here (V13)", quote(&o.name), quote(&rq.verb), quote(&rq.verb), fmt_slice(&pm.layers))));
        }
        if pm.has_layer("rls") && pm.maps().is_empty() && !pm.predicate_only {
            errs.push(Finding::at(
                rq.pos.line,
                format!(
                    "object {} requires {}, but permission {} is @rls with no `maps` table-op — there is no policy to restrict (V13)",
                    quote(&o.name),
                    quote(&rq.verb),
                    quote(&rq.verb)
                ),
            ));
        }
        errs.extend(check_require_terms(s, o, rq, rels));
    }
    errs
}

fn check_require_terms(s: &Spec, o: &Object, rq: &Require, rels: &Rels) -> Vec<Finding> {
    let mut errs = Vec::new();
    let at = |what: String| Finding::at(rq.pos.line, format!("require {}.{} {what}", o.name, rq.verb));
    if !rq.tree.is_nil() && !require_positive(&rq.tree) {
        errs.push(at("is not positively gated — a `not` must be combined with `and` with a positive term".into()));
    }
    errs.extend(check_some_scopes(&rq.tree, rels).into_iter().map(&at));
    for t in rq.tree.leaves_deep() {
        let b = t.builtin();
        if matches!(b, "some" | "element" | "declared" | "slot" | "slot_held" | "holds_at") {
            continue;
        }
        errs.extend(check_holds_every(s, o, t).into_iter().map(&at));
        if b == "within" && s.level_by_name(t.within_level()).is_none() {
            errs.push(at(format!("uses @within({}) which is not a topology level", quote(t.within_level()))));
        }
        if b == "external" {
            let f = t.external_fn();
            match s.external_by_name(f) {
                None => errs.push(at(format!("calls @external({f}) with no `external predicate {f}(...)` declaration (V14)"))),
                Some(ext) if ext.arg_types.len() != t.external_args().len() => errs.push(at(format!(
                    "calls @external({f}) with {} argument(s); it is declared with {} (V14)",
                    t.external_args().len(),
                    ext.arg_types.len()
                ))),
                Some(_) => {}
            }
        } else if !t.grant_ref().is_empty() || matches!(b, "scoped" | "public" | "open") {
            errs.push(at(format!("uses widening term {} — a `require` compiles to a RESTRICTIVE policy, which can only narrow (V13)", t.display())));
        } else if !b.is_empty() && !KNOWN_BUILTINS.contains(&b) {
            errs.push(at(format!("has unknown builtin @{b}")));
        } else if b.is_empty() && t.mode_col().is_none() {
            match rels.get(t.ident()) {
                None => errs.push(at(format!("references unknown relation {}", quote(t.ident())))),
                Some(r) if matches!(r.repr, Repr::Composition(_)) => errs.push(at(format!(
                    "names composition relation {} — a composition definer cascades this object's own predicate, so requiring it is circular (V13)",
                    quote(t.ident())
                ))),
                Some(_) => {}
            }
        }
    }
    errs
}

fn validate_admits(s: &Spec, o: &Object, rels: &Rels) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mapped: HashSet<&str> = o.perms.iter().filter(|pm| pm.has_layer("rls") && !pm.predicate_only).map(demesne_syntax::Perm::maps).collect();
    for a in &o.admits {
        for op in &a.ops {
            if op_to_cmd(op).is_empty() {
                errs.push(Finding::at(a.pos.line, format!("object {} admits unknown operation {}", quote(&o.name), quote(op))));
            } else if !mapped.contains(op.as_str()) {
                errs.push(Finding::at(
                    a.pos.line,
                    format!("object {} admits {}, but no @rls permission maps {}, so there is no policy to join", quote(&o.name), op, op),
                ));
            }
        }
        let pm = a.perm("");
        errs.extend(check_perm_polarity(o, &pm));
        errs.extend(check_perm_terms(s, o, &pm, rels));
    }
    errs
}

fn check_field_access(o: &Object) -> Vec<Finding> {
    if o.field_principals.is_empty() {
        if let Some(f) = o.fields.first() {
            return vec![Finding::at(f.pos.line, format!("object {} declares field rules but no `fields {{ ... }}` principal set", quote(&o.name)))];
        }
        return Vec::new();
    }
    let mut errs = Vec::new();
    let mut declared = HashSet::new();
    for p in &o.field_principals {
        if declared.contains(p) {
            errs.push(Finding::at(o.pos.line, format!("object {} declares field principal {} more than once", quote(&o.name), quote(p))));
        }
        declared.insert(p.clone());
    }
    let mut seen = HashSet::new();
    for f in &o.fields {
        if seen.contains(&f.name) {
            errs.push(Finding::at(f.pos.line, format!("object {} declares field {} more than once", quote(&o.name), quote(&f.name))));
        }
        seen.insert(f.name.clone());
        for tok in f.read.iter().chain(&f.write) {
            if !declared.contains(tok) {
                errs.push(Finding::at(
                    f.pos.line,
                    format!(
                        "object {} field {} references {}, which is not a declared field principal (fields {{ ... }})",
                        quote(&o.name),
                        quote(&f.name),
                        quote(tok)
                    ),
                ));
            }
        }
    }
    errs
}

fn check_duplicate_maps(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for o in &s.objects {
        let mut first_verb: HashMap<&str, &str> = HashMap::new();
        for pm in &o.perms {
            if !pm.has_layer("rls") || pm.predicate_only || op_to_cmd(pm.maps()).is_empty() {
                continue;
            }
            if let Some(prev) = first_verb.get(pm.maps()) {
                errs.push(Finding::at(
                    pm.pos.line,
                    format!(
                        "object {} maps {} from both {} and {} — each emits a policy named {}_{} and the second silently replaces the first (V15)",
                        quote(&o.name),
                        quote(pm.maps()),
                        quote(prev),
                        quote(&pm.verb),
                        o.table,
                        pm.maps()
                    ),
                ));
                continue;
            }
            first_verb.insert(pm.maps(), &pm.verb);
        }
    }
    errs
}

fn check_externals(s: &Spec) -> Vec<Finding> {
    let mut used = HashSet::new();
    for t in s.objects.iter().flat_map(|o| &o.requires).flat_map(|rq| rq.tree.leaves()) {
        if t.builtin() == "external" {
            used.insert(t.external_fn().to_string());
        }
    }
    s.externals
        .iter()
        .filter(|e| !used.contains(&e.name))
        .map(|e| {
            Finding::at(
                e.pos.line,
                format!("external predicate {} is declared but never required — an unused escape hatch is an unaudited one (V14)", quote(&e.name)),
            )
        })
        .collect()
}

fn validate_grant_stores(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut by_table: BTreeMap<&str, Vec<(&Object, &ViaGrant)>> = BTreeMap::new();
    let mut table_order: Vec<&str> = Vec::new();
    for o in &s.objects {
        let Some((rel, g)) = grant_relation(o) else { continue };
        if g.discrim_col.is_some() != g.discrim_val.is_some() {
            errs.push(Finding::unplaced(format!(
                "object {} grant relation: a discriminator needs both a column and a value (`where <col> = \"<val>\"`)",
                quote(&o.name)
            )));
        }
        for k in &rel.types {
            if s.subject_by_name(k).is_none_or(|sub| sub.identifies().is_empty()) {
                errs.push(Finding::unplaced(format!(
                    "object {} grant relation kind {} is not a claim-bearing subject (no `subject {} {{ ... identifies <claim> }}`)",
                    quote(&o.name),
                    quote(k),
                    k
                )));
            }
        }
        if !by_table.contains_key(g.table.as_str()) {
            table_order.push(&g.table);
        }
        by_table.entry(&g.table).or_default().push((o, g));
    }
    for table in table_order {
        let refs = &by_table[table];
        if refs.len() < 2 {
            continue;
        }
        let col = refs[0].1.discrim_col.as_deref().unwrap_or("");
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for (obj, g) in refs {
            let Some(dc) = g.discrim_col.as_deref() else {
                errs.push(Finding::unplaced(format!(
                    "object {} shares grant store {} with another grant relation but is not discriminated — add `where <col> = \"<val>\"`",
                    quote(&obj.name),
                    quote(table)
                )));
                continue;
            };
            if dc != col {
                errs.push(Finding::unplaced(format!(
                    "grant relations sharing store {} must discriminate on the SAME column ({} vs {})",
                    quote(table),
                    quote(col),
                    quote(dc)
                )));
            }
            let dv = g.discrim_val.as_deref().unwrap_or("");
            if let Some(prev) = seen.get(dv) {
                errs.push(Finding::unplaced(format!(
                    "objects {} and {} share grant store {} with the SAME discriminator value {} — values must be distinct",
                    quote(prev),
                    quote(&obj.name),
                    quote(table),
                    quote(dv)
                )));
            }
            seen.insert(dv, &obj.name);
        }
    }
    errs
}

fn validate_store_manage(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for o in &s.objects {
        if !object_uses_store_manage(o) {
            continue;
        }
        let descs = s.store_descriptors(&o.table);
        if descs.is_empty() {
            errs.push(Finding::unplaced(format!(
                "object {} uses @store_manage but no object uses its table {} as a grant store",
                quote(&o.name),
                quote(&o.table)
            )));
            continue;
        }
        for d in descs {
            if object_grant_edge(d).is_some_and(|e| e.discrim_col.is_none()) {
                errs.push(Finding::unplaced(format!(
                    "object {} uses @store_manage but grant store {} on object {} is not discriminated (`where <col> = \"<val>\"`)",
                    quote(&o.name),
                    quote(&o.table),
                    quote(&d.name)
                )));
            }
        }
    }
    errs
}

fn dfs<'a>(n: &'a str, edges: &HashMap<&'a str, Vec<&'a str>>, color: &mut HashMap<&'a str, u8>) -> bool {
    color.insert(n, 1);
    for &m in edges.get(n).map_or(&[][..], Vec::as_slice) {
        match color.get(m).copied().unwrap_or(0) {
            1 => return true,
            0 if dfs(m, edges, color) => return true,
            _ => {}
        }
    }
    color.insert(n, 2);
    false
}

fn validate_cross_object_acyclic(s: &Spec) -> Vec<Finding> {
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for o in &s.objects {
        for r in &o.relations {
            let Repr::Object(vo) = &r.repr else { continue };
            if s.object_by_name(&vo.object).is_none() {
                return vec![Finding::unplaced(format!(
                    "object {} relation {} references unknown object {} (via object)",
                    quote(&o.name),
                    quote(&r.name),
                    quote(&vo.object)
                ))];
            }
            edges.entry(&o.name).or_default().push(&vo.object);
        }
    }
    let mut color: HashMap<&str, u8> = HashMap::new();
    for o in &s.objects {
        if color.get(o.name.as_str()).copied().unwrap_or(0) == 0 && dfs(&o.name, &edges, &mut color) {
            return vec![Finding::unplaced(format!(
                "cross-object `via object` references form a cycle through {} — this would generate mutually-recursive definers",
                quote(&o.name)
            ))];
        }
    }
    Vec::new()
}

fn validate_grant_reach(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut bases: HashMap<String, &Grant> = HashMap::new();
    let mut names = HashSet::new();
    for g in &s.grants {
        if names.contains(&g.name) {
            errs.push(Finding::at(g.pos.line, format!("grant {} is declared twice", quote(&g.name))));
        }
        names.insert(g.name.clone());
        if g.claim_key.is_some() {
            errs.extend(validate_claim_grant(s, g));
            continue;
        }
        errs.extend(validate_grant_scopes(s, g));
        let base = g.definer_base().to_string();
        match bases.get(&base) {
            Some(prior) if !same_grant_emission(prior, g) => errs.push(Finding::at(
                g.pos.line,
                format!(
                    "grants {} and {} both emit {}_reach from different edges; give one its own definer name with `named`",
                    quote(&prior.name),
                    quote(&g.name),
                    base
                ),
            )),
            Some(_) => {}
            None => {
                bases.insert(base, g);
            }
        }
    }
    for o in &s.objects {
        errs.extend(validate_grant_uses(s, o));
    }
    errs
}

fn same_grant_emission(a: &Grant, b: &Grant) -> bool {
    a.table == b.table
        && a.grantee_col == b.grantee_col
        && a.level_col == b.level_col
        && a.active_col == b.active_col
        && a.expires_col == b.expires_col
        && a.scopes == b.scopes
}

fn validate_claim_grant(s: &Spec, g: &Grant) -> Vec<Finding> {
    let mut errs = Vec::new();
    if s.level_is_virtual(&g.level) {
        errs.push(Finding::at(g.pos.line, format!("claim grant {} reaches virtual level {}, which has no column to lift", quote(&g.name), quote(&g.level))));
    }
    if g.verbs.is_empty() {
        errs.push(Finding::at(g.pos.line, format!("claim grant {} must name the operations it confers", quote(&g.name))));
    }
    if g.active_col.is_some()
        || g.expires_col.is_some()
        || g.id_col.is_some()
        || g.granted_by_col.is_some()
        || g.revoked_by_col.is_some()
        || g.created_at_col.is_some()
        || !g.extra_cols.is_empty()
        || g.named.is_some()
        || !g.scopes.is_empty()
    {
        errs.push(Finding::at(g.pos.line, format!("claim grant {} has no edge, so it takes no edge options", quote(&g.name))));
    }
    errs
}

fn validate_grant_scopes(s: &Spec, g: &Grant) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut previous = g.level.as_str();
    let mut seen_cols: HashSet<&str> = [g.grantee_col(), g.level_col()].into_iter().collect();
    for scope in &g.scopes {
        if !s.level_descends_from(&scope.level, previous) || s.level_is_virtual(&scope.level) {
            errs.push(Finding::at(
                g.pos.line,
                format!("grant {} scope {} must be a non-virtual level below {}", quote(&g.name), quote(&scope.level), quote(previous)),
            ));
        }
        if scope.missing != "allow" && scope.missing != "deny" {
            errs.push(Finding::at(
                g.pos.line,
                format!("grant {} scope {}: missing must be allow or deny, got {}", quote(&g.name), quote(&scope.level), quote(&scope.missing)),
            ));
        }
        if seen_cols.contains(scope.column.as_str()) {
            errs.push(Finding::at(g.pos.line, format!("grant {} scope {} reuses column {}", quote(&g.name), quote(&scope.level), quote(&scope.column))));
        }
        seen_cols.insert(&scope.column);
        previous = &scope.level;
    }
    errs
}

fn validate_grant_uses(s: &Spec, o: &Object) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut claimed = HashSet::new();
    for u in &o.reach_uses {
        let g = match s.grant_by_name(&u.grant) {
            Some(g) if g.claim_key.is_none() => g,
            _ => {
                errs.push(Finding::at(u.pos.line, format!("object {} selects the reach of {}, which is not an edge grant", quote(&o.name), quote(&u.grant))));
                continue;
            }
        };
        errs.extend(validate_grant_use_target(s, o, g, u));
        let ops: Vec<&str> = if u.ops.is_empty() { ORDERED_TABLE_OPS.to_vec() } else { u.ops.iter().map(String::as_str).collect() };
        for op in ops {
            if op_to_cmd(op).is_empty() {
                errs.push(Finding::at(u.pos.line, format!("object {} reach {} names unknown operation {}", quote(&o.name), g.name, quote(op))));
                continue;
            }
            if !u.ops.is_empty() && !g.confers(op) {
                errs.push(Finding::at(
                    u.pos.line,
                    format!("object {} reach {} selects {}, which grant {} does not confer", quote(&o.name), g.name, op, quote(&g.name)),
                ));
            }
            let key = format!("{}:{}", g.name, op);
            if claimed.contains(&key) {
                errs.push(Finding::at(u.pos.line, format!("object {} selects the reach of {} for {} twice", quote(&o.name), quote(&g.name), op)));
            }
            claimed.insert(key);
        }
    }
    errs
}

fn validate_grant_use_target(s: &Spec, o: &Object, g: &Grant, u: &GrantUse) -> Vec<Finding> {
    let mut errs = Vec::new();
    if !contains(&o.scoped, &g.level) {
        errs.push(Finding::at(
            u.pos.line,
            format!("object {} selects the reach of {} at {}, which is outside its scope", quote(&o.name), quote(&g.name), quote(&g.level)),
        ));
    }
    if !s.grant_reached_by_subject(&g.name) {
        errs.push(Finding::at(u.pos.line, format!("object {} selects the reach of {}, which no subject reaches through", quote(&o.name), quote(&g.name))));
    }
    if !u.via.is_empty() {
        errs.extend(validate_grant_use_via(s, o, g, u));
    } else if g.scopes.is_empty() {
        errs.push(Finding::at(u.pos.line, format!("object {} reach {}: unscoped and bound need a grant with scope levels", quote(&o.name), g.name)));
    } else if let Some(bound) = &u.bound
        && !g.has_scope(bound)
    {
        errs.push(Finding::at(u.pos.line, format!("object {} reach {} bound {}: the level must be one of the grant's scopes", quote(&o.name), g.name, bound)));
    }
    errs
}

fn validate_grant_use_via(s: &Spec, o: &Object, g: &Grant, u: &GrantUse) -> Vec<Finding> {
    let ops: Vec<&str> = if u.ops.is_empty() { ORDERED_TABLE_OPS.to_vec() } else { u.ops.iter().map(String::as_str).collect() };
    let alone = u.via.len() == 1;
    let mut errs = Vec::new();
    for (i, via_name) in u.via.iter().enumerate() {
        if u.via[..i].contains(via_name) {
            errs.push(Finding::at(u.pos.line, format!("object {} reach {} names {} twice after `via`", quote(&o.name), g.name, via_name)));
            continue;
        }
        let Some(via) = s.grant_by_name(via_name).filter(|v| v.claim_key.is_none() && !(alone && std::ptr::eq(*v, g)) && v.level == g.level) else {
            let what = if alone { "the replacement must be another edge grant" } else { "each grant it reads through must be an edge grant" };
            errs.push(Finding::at(u.pos.line, format!("object {} reach {} via {}: {what} at {}", quote(&o.name), g.name, via_name, quote(&g.level))));
            continue;
        };
        errs.extend(ops.iter().filter(|op| g.confers(op) && !via.confers(op)).map(|op| {
            Finding::at(u.pos.line, format!("object {} reach {} via {}: {} does not confer {}", quote(&o.name), g.name, via_name, quote(via_name), op))
        }));
    }
    errs
}

fn validate_borrow_operation(s: &Spec, r: &Relation, vo: &ViaObject) -> Vec<Finding> {
    let Some(op) = &vo.op else { return Vec::new() };
    if op_to_cmd(op).is_empty() {
        return vec![Finding::at(r.pos.line, format!("relation {} borrows for unknown operation {}", quote(&r.name), quote(op)))];
    }
    let Some(other) = s.object_by_name(&vo.object) else { return Vec::new() };
    for pm in &other.perms {
        if pm.verb == vo.verb && !pm.predicate_only {
            return vec![Finding::at(
                r.pos.line,
                format!(
                    "relation {} borrows {}->{} for {}, but that permission already maps {}; `for` selects the operation of a predicate-only permission",
                    quote(&r.name),
                    vo.object,
                    vo.verb,
                    op,
                    pm.maps()
                ),
            )];
        }
    }
    Vec::new()
}

fn validate_permission_exports(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut names = HashSet::new();
    for obj in &s.objects {
        for export in &obj.exports {
            if names.contains(&export.name) {
                errs.push(Finding::at(export.pos.line, format!("permission export {} is declared twice", quote(&export.name))));
            }
            names.insert(export.name.clone());
            errs.extend(validate_permission_export(s, obj, export));
        }
    }
    errs
}

fn validate_projections(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let taken = |o: &'_ Object| -> Vec<String> {
        o.exports.iter().map(|e| e.name.clone()).chain(o.probes.iter().map(|p| p.name.clone())).chain(o.nearests.iter().map(|n| n.name.clone())).collect()
    };
    let mut names: HashSet<String> = s.objects.iter().flat_map(taken).collect();
    for (obj, p) in s.objects.iter().flat_map(|o| o.projections.iter().map(move |p| (o, p))) {
        let at = |msg: String| Finding::at(p.pos.line, format!("projection {} {msg}", quote(&p.name)));
        if !names.insert(p.name.clone()) {
            errs.push(at("shares its name with another generated function of the spec".into()));
        }
        let mut returned = HashSet::new();
        for c in &p.columns {
            if !returned.insert(c.name.as_deref().unwrap_or(&c.column)) {
                errs.push(at(format!("returns {} twice", quote(c.name.as_deref().unwrap_or(&c.column)))));
            }
            if !EXPORT_PARAMETER_TYPES.contains(&c.ty.as_str()) {
                errs.push(at(format!("column {} has unsupported type {}", quote(&c.column), quote(&c.ty))));
            }
        }
        let pm = p.admit().perm("select");
        errs.extend(check_perm_polarity(obj, &pm));
        errs.extend(check_perm_terms(s, obj, &pm, &crate::analysis::rels_of(obj)));
    }
    errs
}

fn validate_role_forms(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for rs in &s.role_stores {
        let at = |msg: String| Finding::at(rs.pos.line, format!("rolestore {} {msg}", quote(&rs.name)));
        if rs.roles_table.is_none() && !(rs.forms.is_empty() && rs.unversioned.is_empty() && rs.active.is_empty()) {
            errs.push(at("declares `form`, `unversioned` or `active` but no `rolejoin` naming the roles they read".into()));
        }
        let Some(first) = rs.forms.first() else {
            if !rs.unversioned.is_empty() {
                errs.push(at("declares `unversioned` but no `form` for a role to have more than one of".into()));
            }
            if rs.absent_form.is_some() {
                errs.push(at("declares `absent claim reads` but no `form` to read".into()));
            }
            continue;
        };
        if rs.perms_col.is_none() {
            errs.push(at("declares a `form` but no `permissions` column for the base form".into()));
        }
        if rs.forms.iter().any(|f| f.claim != first.claim) {
            errs.push(at("reads its forms from two claims — every `form` line names one claim".into()));
        }
        let mut values: HashSet<&str> = HashSet::new();
        for form in &rs.forms {
            if !values.insert(&form.value) {
                errs.push(at(format!("names form {} twice", quote(&form.value))));
            }
        }
        match &rs.absent_form {
            None => errs.push(at(format!(
                "names no form for a session with no {} claim — write `absent claim reads \"<value>\"`, so no session is left to a default",
                quote(&first.claim)
            ))),
            Some(value) if !values.contains(value.as_str()) => errs.push(at(format!("reads {} for an absent claim, which no `form` line names", quote(value)))),
            Some(_) => {}
        }
    }
    errs
}

const CHAIN_OPS: [&str; 3] = ["select", "update", "delete"];

fn judges_elements(o: &Object, op: &str) -> bool {
    fn widens(n: &PermNode) -> bool {
        match n {
            PermNode::Leaf(t) => t.some_scope().is_some(),
            PermNode::Not(_) => false,
            PermNode::And(kids) | PermNode::Or(kids) => kids.iter().any(widens),
        }
    }
    o.perms.iter().any(|pm| pm.has_layer("rls") && pm.maps() == op && widens(&pm.tree))
}

fn validate_chains(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for o in &s.objects {
        let paths: Vec<(&Relation, &ViaComposition)> = o
            .relations
            .iter()
            .filter_map(|r| match &r.repr {
                Repr::Composition(vc) => vc.path.as_ref().map(|_| (r, vc)),
                _ => None,
            })
            .collect();
        if o.nested.is_some() && !CHAIN_OPS.iter().any(|op| judges_elements(o, op)) {
            errs.push(Finding::at(
                o.pos.line,
                format!("object {} declares `nested`, but no permission of it holds a `some` whose elements could be judged at another row", quote(&o.name)),
            ));
        }
        for (r, vc) in paths {
            let at = |msg: String| Finding::at(r.pos.line, format!("object {}: relation {} {msg}", quote(&o.name), quote(&r.name)));
            if o.nested.is_none() {
                errs.push(at("declares a `path`, but the object declares no `nested <n>` to say how many compositions deep a hop is judged".into()));
            }
            errs.extend(path_faults(o, vc).into_iter().map(at));
        }
    }
    errs
}

fn path_faults(o: &Object, vc: &ViaComposition) -> Vec<String> {
    let mut faults = Vec::new();
    let Some(path) = &vc.path else { return faults };
    let mut ops: HashSet<&str> = HashSet::new();
    for (op, col) in &path.cols {
        if op.is_empty() {
            continue;
        }
        if !CHAIN_OPS.contains(&op.as_str()) {
            faults.push(format!("names path column {} for {}, which is not select, update or delete", quote(col), quote(op)));
        } else if !ops.insert(op) {
            faults.push(format!("names two path columns for {}", quote(op)));
        }
    }
    for op in CHAIN_OPS {
        if path.col_for(op).is_none() && o.perms.iter().any(|pm| pm.has_layer("rls") && pm.maps() == op) {
            faults.push(format!("names no path column for {op}, which a permission of the object maps"));
        }
    }
    if path.along.is_nil() {
        faults.push("declares a `path` whose brackets are empty".into());
    }
    for t in path.along.leaves() {
        let Some(scope) = t.declared_scope() else {
            faults.push(format!("uses {} in its `path` — a path holds `every` and `none` terms over the rows declared for its key", t.display()));
            continue;
        };
        if scope.body.is_nil() {
            faults.push(format!("uses {} whose brackets are empty", t.display()));
        }
        faults.extend(scope.body.leaves().into_iter().filter_map(|hop| hop_fault(o, vc, hop)));
    }
    faults
}

fn hop_fault(o: &Object, vc: &ViaComposition, hop: &Term) -> Option<String> {
    if matches!(hop.builtin(), "slot" | "slot_held") {
        return None;
    }
    let Some((_, _, op)) = hop.holds_at() else {
        return Some(format!("uses {} in its `path` — a hop is tested with `@slot` and `@holds_at`", hop.display()));
    };
    match (&vc.slot, hop.holds_at_slot()) {
        (Some((col, _)), None) => {
            return Some(format!(
                "uses {} without `slot <column>` — the composition binds slot {}, so a hop says which slot it follows",
                hop.display(),
                quote(col)
            ));
        }
        (None, Some(_)) => return Some(format!("uses {}, but the composition binds no slot for a hop to name", hop.display())),
        _ => {}
    }
    match op {
        Some(op) if !CHAIN_OPS.contains(&op) => Some(format!("uses {}, but {} is not select, update or delete", hop.display(), quote(op))),
        Some(op) if !judges_elements(o, op) => Some(format!("uses {}, but no permission that maps {op} holds a `some` to judge the element by", hop.display())),
        Some(_) => None,
        None => CHAIN_OPS.iter().find(|op| o.perms.iter().any(|pm| pm.has_layer("rls") && pm.maps() == **op) && !judges_elements(o, op)).map(|op| {
            format!(
                "uses {}, but the permission that maps {op} holds no `some` to judge the element by — write `for <operation>` to judge every hop by one",
                hop.display()
            )
        }),
    }
}

fn validate_markers(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    for o in &s.objects {
        let mut cols: HashSet<&str> = HashSet::new();
        for m in &o.markers {
            let at = |msg: String| Finding::at(m.pos.line, format!("object {}: marker {} {msg}", quote(&o.name), quote(&m.col)));
            if !o.is_level_entity() {
                errs.push(at("is on an object that declares no `level`, so no other object's rows sit beneath its rows".into()));
            }
            if !cols.insert(&m.col) {
                errs.push(at("is declared twice".into()));
            }
            errs.extend(marker_faults(s, o, m).into_iter().map(at));
        }
    }
    errs
}

fn marker_faults(s: &Spec, o: &Object, m: &Marker) -> Vec<String> {
    let mut faults = Vec::new();
    let mut ops: HashSet<&str> = HashSet::new();
    for op in &m.ops {
        if !ORDERED_TABLE_OPS.contains(&op.as_str()) {
            faults.push(format!("confines {}, which is no table operation", quote(op)));
        } else if !ops.insert(op) {
            faults.push(format!("confines {} twice", quote(op)));
        }
    }
    let Some(name) = &m.closure else { return faults };
    match s.closure_by_table(name) {
        None => faults.push(format!("reads closure {}, which the spec does not declare", quote(name))),
        Some(c) if c.base.as_ref().is_none_or(|b| b.table != o.table) => {
            faults.push(format!("reads closure {}, whose base is not table {}", quote(name), quote(&o.table)));
        }
        Some(_) => {}
    }
    faults
}

fn validate_nearests(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut names: HashSet<&str> =
        s.objects.iter().flat_map(|o| o.exports.iter().map(|e| e.name.as_str()).chain(o.probes.iter().map(|p| p.name.as_str()))).collect();
    for n in s.objects.iter().flat_map(|o| &o.nearests) {
        let at = |msg: String| Finding::at(n.pos.line, format!("nearest {} {msg}", quote(&n.name)));
        if !names.insert(&n.name) {
            errs.push(at("shares its name with another generated function of the spec".into()));
        }
        if !EXPORT_PARAMETER_TYPES.contains(&n.ty.as_str()) {
            errs.push(at(format!("returns unsupported type {}", quote(&n.ty))));
        }
        let closure = s.closure_by_table(&n.closure);
        if closure.is_none() {
            errs.push(at(format!(
                "reads closure {}, which the spec does not declare — declare it with `closure {}(…) depth <column>`",
                quote(&n.closure),
                n.closure
            )));
        } else if closure.is_some_and(|c| c.depth_col.is_none()) {
            errs.push(at(format!("reads closure {}, which declares no `depth` column to say which row is nearest", quote(&n.closure))));
        }
        if n.value_col == n.node_col {
            errs.push(at(format!("names {} as both its value and its node column", quote(&n.value_col))));
        }
    }
    errs
}

fn validate_probes(s: &Spec) -> Vec<Finding> {
    let mut errs = Vec::new();
    let mut names: HashSet<&str> = s.objects.iter().flat_map(|o| o.exports.iter().map(|e| e.name.as_str())).collect();
    for (obj, probe) in s.objects.iter().flat_map(|o| o.probes.iter().map(move |p| (o, p))) {
        let at = |msg: String| Finding::at(probe.pos.line, format!("probe {} {msg}", quote(&probe.name)));
        if !names.insert(&probe.name) {
            errs.push(at("shares its name with another probe or an export".into()));
        }
        if obj.scoped.iter().all(|l| s.level_is_virtual(l) || (obj.is_level_entity() && l == obj.level())) {
            errs.push(at(format!(
                "is on object {}, which no claim contains — a probe answers inside the caller's containment and never for the whole table",
                quote(&obj.name)
            )));
        }
        if probe.answer == ProbeAnswer::Key && !obj.point_checkable() {
            errs.push(at(format!("answers with a key, but object {} has a composite key", quote(&obj.name))));
        }
        let mut columns = HashSet::new();
        let mut params = HashSet::new();
        for param in &probe.params {
            if !columns.insert(param.column.as_str()) || !params.insert(param.name()) {
                errs.push(at(format!("binds column {} or parameter {} twice", quote(&param.column), quote(&param.name()))));
            }
            if !EXPORT_PARAMETER_TYPES.contains(&param.ty.as_str()) {
                errs.push(at(format!("parameter {} has unsupported type {}", quote(&param.name()), quote(&param.ty))));
            }
        }
    }
    errs
}

fn validate_permission_export(s: &Spec, obj: &Object, export: &PermissionExport) -> Vec<Finding> {
    let Some(pm) = mapped_perm(obj, &export.verb) else {
        return vec![Finding::at(export.pos.line, format!("export {}.{} needs a permission that maps a table operation under @rls", obj.name, export.verb))];
    };
    let mut errs = Vec::new();
    let mut params = HashSet::new();
    let mut names = HashSet::new();
    for param in &export.params {
        let pname = param.name();
        if names.contains(&pname) || params.contains(&param.column) {
            errs.push(Finding::at(
                export.pos.line,
                format!("export {} binds column {} or parameter {} twice", quote(&export.name), quote(&param.column), quote(&pname)),
            ));
        }
        names.insert(pname.clone());
        params.insert(param.column.clone());
        if !EXPORT_PARAMETER_TYPES.contains(&param.ty.as_str()) {
            errs.push(Finding::at(
                export.pos.line,
                format!("export {} parameter {} has unsupported type {}", quote(&export.name), quote(&pname), quote(&param.ty)),
            ));
        }
    }
    for column in exported_columns(s, &exported_row(s, obj, pm)) {
        if !params.contains(&column) {
            errs.push(Finding::at(export.pos.line, format!("export {} reads row column {}, which no parameter binds", quote(&export.name), quote(&column))));
        }
    }
    errs
}
