use crate::analysis::*;
use crate::conditional::is_row_leaf;
use crate::schema::{exported_columns, exported_row};
use crate::topology;
use crate::vocab::to_runtime;
use demesne_gocompat::{fmt_slice, quote};
use demesne_syntax::*;
use std::collections::{BTreeMap, HashMap, HashSet};

const KNOWN_LAYERS: [&str; 4] = ["rls", "pdp", "kernel", "check"];
const KNOWN_BUILTINS: [&str; 12] =
    ["app_scope", "scoped", "session", "open", "store_manage", "public", "kind", "self", "within", "holds", "claim", "row"];
const EXPORT_PARAMETER_TYPES: [&str; 12] =
    ["text", "uuid", "smallint", "integer", "bigint", "boolean", "json", "jsonb", "numeric", "timestamptz", "timestamp", "date"];

fn table_op(s: &str) -> bool {
    matches!(s, "select" | "insert" | "update" | "delete")
}

pub enum Structure {
    Fatal(String),
    Errors(Vec<String>),
}

pub fn validate_structure(s: &Spec) -> Structure {
    let chain = match topology::chain(s) {
        Ok(c) => c,
        Err(e) => return Structure::Fatal(e),
    };
    let level_names: HashSet<&str> = chain.iter().map(|l| l.name.as_str()).collect();
    let mut errs: Vec<String> = Vec::new();

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
        errs.push(e);
    }
    for o in &s.objects {
        errs.extend(validate_object(s, o, &chain));
    }
    errs.extend(check_duplicate_maps(s));
    errs.extend(validate_cross_object_acyclic(s));
    errs.extend(validate_predicate_only_referenced(s));
    errs.extend(validate_grant_reach(s));
    errs.extend(validate_permission_exports(s));
    errs.extend(validate_grant_stores(s));
    errs.extend(validate_store_manage(s));
    errs.extend(check_emit_sites(s, &vocab_names));
    errs.extend(check_externals(s));
    Structure::Errors(errs)
}

fn check_vocabs(s: &Spec) -> (HashSet<String>, Vec<String>) {
    let mut errs = Vec::new();
    let mut names = HashSet::new();
    for v in &s.vocabs {
        if names.contains(&v.name) {
            errs.push(format!("line {}: duplicate vocabulary {}", v.pos.line, quote(&v.name)));
        }
        names.insert(v.name.clone());
        errs.extend(validate_vocabulary(v));
    }
    (names, errs)
}

fn validate_vocabulary(v: &Vocabulary) -> Vec<String> {
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
            errs.push(format!(
                "line {}: preset {} references unknown permission/preset {} in vocabulary {}",
                pr.pos.line,
                quote(&pr.name),
                quote(item),
                quote(&v.name)
            ));
        }
    }
    let rv = to_runtime(v);
    for im in &v.implications {
        if let Err(e) = rv.implied_permissions(&im.perm) {
            errs.push(format!("line {}: {e}", im.pos.line));
        }
    }
    for r in &v.rank {
        if !preset_names.contains(r.as_str()) {
            errs.push(format!(
                "line {}: rank ladder names {} which is not a preset of vocabulary {}",
                v.pos.line,
                quote(r),
                quote(&v.name)
            ));
        }
    }
    errs
}

fn check_grants(s: &Spec, levels: &HashSet<&str>) -> Vec<String> {
    let mut errs = Vec::new();
    for g in &s.grants {
        if !levels.contains(g.level.as_str()) {
            errs.push(format!(
                "line {}: grant {} confers reach at unknown level {}",
                g.pos.line,
                quote(&g.name),
                quote(&g.level)
            ));
        }
        if g.claim_key.is_none() && (g.table.is_none() || g.grantee_col.is_none() || g.level_col.is_none()) {
            errs.push(format!(
                "line {}: grant {} must name an edge table, grantee column and level column",
                g.pos.line,
                quote(&g.name)
            ));
        }
        let mut seen = HashSet::new();
        for v in &g.verbs {
            if op_to_cmd(v).is_empty() {
                errs.push(format!(
                    "line {}: grant {} confers unknown verb {} (expected select, insert, update or delete)",
                    g.pos.line,
                    quote(&g.name),
                    quote(v)
                ));
            }
            if seen.contains(v) {
                errs.push(format!("line {}: grant {} names verb {} twice", g.pos.line, quote(&g.name), quote(v)));
            }
            seen.insert(v.clone());
        }
    }
    errs
}

fn check_claims_block(s: &Spec) -> Vec<String> {
    let Some(c) = &s.claims else { return Vec::new() };
    let mut errs = Vec::new();
    if c.setting.is_empty() {
        errs.push(format!("line {}: claims block needs a setting name", c.pos.line));
    }
    if c.cast != "json" && c.cast != "jsonb" {
        errs.push(format!("line {}: claims cast {} must be json or jsonb", c.pos.line, quote(&c.cast)));
    }
    errs
}

fn validate_subject(s: &Spec, sub: &Subject, levels: &HashSet<&str>, vocabs: &HashSet<String>) -> Vec<String> {
    let mut errs = Vec::new();
    let line = sub.pos.line;
    let name = quote(&sub.name);
    if !matches!(sub.reach(), "self" | "descendants" | "grant") {
        errs.push(format!(
            "line {line}: subject {name} has reach {} — only self|descendants|grant are emittable (V2)",
            quote(sub.reach())
        ));
    }
    if !levels.contains(sub.anchor()) {
        errs.push(format!("line {line}: subject {name} anchors at unknown level {} (V2)", quote(sub.anchor())));
    }
    if sub.reach() == "grant" {
        if sub.reach_grant().is_empty() {
            errs.push(format!("line {line}: subject {name} has `reach via grant` but names no grant"));
        } else {
            match s.grant_by_name(sub.reach_grant()) {
                None => errs.push(format!(
                    "line {line}: subject {name} reaches via unknown grant {}",
                    quote(sub.reach_grant())
                )),
                Some(g) if g.claim_key.is_some() => {
                    errs.push(format!("line {line}: claim grant {} does not take a reaching subject", quote(&g.name)))
                }
                Some(_) => {}
            }
        }
    }
    if !sub.roles().is_empty() && !vocabs.contains(sub.roles()) {
        errs.push(format!("line {line}: subject {name} roles reference unknown vocabulary {}", quote(sub.roles())));
    }
    if !matches!(sub.binds(), "" | "owner" | "admin") {
        errs.push(format!(
            "line {line}: subject {name} has unknown binding {} (binds owner|admin)",
            quote(sub.binds())
        ));
    }
    if levels.contains(sub.anchor()) {
        match s.pinned_columns(sub) {
            Err(e) => errs.push(e),
            Ok((cols, is_virtual)) => {
                if cols.is_empty() && !is_virtual {
                    errs.push(format!(
                        "line {line}: subject {name} pins no scope column yet does not anchor at a virtual level — unconditional reach is only allowed for a virtual-anchored operator (V7)"
                    ));
                }
            }
        }
    }
    if let Some(m) = &sub.membership
        && (m.table.is_empty() || m.id_col.is_empty() || m.flag_col.is_empty())
    {
        errs.push(format!(
            "line {line}: subject {name} membership must name a table, id column and flag column (V9)"
        ));
    }
    if sub.transient {
        if sub.identifies().is_empty() {
            errs.push(format!(
                "line {line}: transient subject {name} must name the claim it is identified by (`identifies <claim>`)"
            ));
        }
        if sub.reach() != "self" {
            errs.push(format!(
                "line {line}: transient subject {name} must `reach self`: it stands for one request, not a principal with descendants or grants"
            ));
        }
        if !sub.roles_none || !sub.roles().is_empty() {
            errs.push(format!(
                "line {line}: transient subject {name} must be `roles none`: a role is held by a standing principal, and a transient subject is a claim on one request"
            ));
        }
        if !sub.binds().is_empty() {
            errs.push(format!(
                "line {line}: transient subject {name} cannot bind a plane (`binds {}`): a plane's owner is a standing principal",
                sub.binds()
            ));
        }
        if sub.membership.is_some() {
            errs.push(format!("line {line}: transient subject {name} cannot be identified via a membership"));
        }
    }
    errs
}

fn check_plane_bindings(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    let mut owner_at: HashMap<&str, &str> = HashMap::new();
    let mut admin_sub = "";
    for sub in &s.subjects {
        match sub.binds() {
            "owner" => {
                if let Some(prev) = owner_at.get(sub.anchor()).filter(|p| !p.is_empty()) {
                    errs.push(format!(
                        "subjects {} and {} both `binds owner` at level {} — the owner plane must be unambiguous",
                        quote(prev),
                        quote(&sub.name),
                        quote(sub.anchor())
                    ));
                }
                owner_at.insert(sub.anchor(), &sub.name);
            }
            "admin" => {
                if !admin_sub.is_empty() {
                    errs.push(format!(
                        "subjects {} and {} both `binds admin` — the admin plane must be unambiguous",
                        quote(admin_sub),
                        quote(&sub.name)
                    ));
                }
                admin_sub = &sub.name;
            }
            _ => {}
        }
    }
    errs
}

fn check_role_store_planes(s: &Spec, chain: &[&Level]) -> Vec<String> {
    let mut errs = Vec::new();
    let non_virtual = chain.iter().filter(|l| !l.is_virtual).count();
    let known: HashSet<&str> = chain.iter().map(|l| l.name.as_str()).collect();
    let mut by_fn: HashMap<String, &str> = HashMap::new();
    for rs in &s.role_stores {
        let f = s.holds_perm_fn(rs);
        match by_fn.get(&f).filter(|n| !n.is_empty()) {
            Some(prev) => errs.push(format!(
                "rolestores {} and {} both compile their @holds check to {}() — rename one so each rolestore has its own definer",
                quote(prev),
                quote(&rs.name),
                f
            )),
            None => {
                by_fn.insert(f, &rs.name);
            }
        }
        let Some(plane) = &rs.plane else { continue };
        if !known.contains(plane.as_str()) {
            errs.push(format!(
                "line {}: rolestore {} declares `plane {}`, which is not a topology level",
                rs.pos.line,
                quote(&rs.name),
                plane
            ));
            continue;
        }
        if s.rolestore_plane_depth(rs) < non_virtual && rs.scope_cols.len() < non_virtual {
            errs.push(format!(
                "line {}: rolestore {} declares `plane {}` but names only {} of the {} non-virtual levels in `scope` — every level below the plane must be named so the floor can pin it NULL, or an assignment scoped there would satisfy the plane's check",
                rs.pos.line,
                quote(&rs.name),
                plane,
                rs.scope_cols.len(),
                non_virtual
            ));
        }
    }
    errs
}

fn check_emit_sites(s: &Spec, vocabs: &HashSet<String>) -> Vec<String> {
    let mut errs = Vec::new();
    for pr in &s.procedures {
        if !vocabs.contains(&pr.emit_site) {
            errs.push(format!(
                "line {}: procedures block targets unknown vocabulary {} (V10)",
                pr.pos.line,
                quote(&pr.emit_site)
            ));
        }
    }
    for u in &s.ungoverned {
        if !vocabs.contains(&u.emit_site) {
            errs.push(format!(
                "line {}: ungoverned block targets unknown vocabulary {} (V10)",
                u.pos.line,
                quote(&u.emit_site)
            ));
        }
    }
    errs
}

fn validate_predicate_only_referenced(s: &Spec) -> Vec<String> {
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
                errs.push(format!(
                    "line {}: permission {}.{} is `predicate` (predicate-only) but no `via object {}->{}` borrows it — a lent authority that is never borrowed is dead, unverified SQL",
                    pm.pos.line, obj.name, pm.verb, obj.name, pm.verb
                ));
            }
        }
    }
    errs
}

fn validate_object(s: &Spec, o: &Object, chain: &[&Level]) -> Vec<String> {
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

fn check_scope_path(s: &Spec, o: &Object, chain: &[&Level]) -> Vec<String> {
    let leaf_level = o.scoped.last().map(String::as_str).unwrap_or("");
    let leaf_is_virtual = s.level_by_name(leaf_level).is_some_and(|l| l.is_virtual);
    if o.scoped.is_empty() {
        return vec![format!("line {}: object {} declares no scoped path (V6)", o.pos.line, quote(&o.name))];
    }
    if leaf_is_virtual {
        if o.scoped.len() != 1 {
            return vec![format!(
                "line {}: object {} is scoped at virtual level {} (a global object) but declares a multi-level path {} — a global object carries no containment columns (V6)",
                o.pos.line,
                quote(&o.name),
                quote(leaf_level),
                fmt_slice(&o.scoped)
            )];
        }
        return check_scope_wildcards(s, o);
    }
    let Ok(paths) = topology::ancestor_paths(s, leaf_level) else {
        return vec![format!(
            "line {}: object {} scoped leaf {} is not a topology level (V6)",
            o.pos.line,
            quote(&o.name),
            quote(leaf_level)
        )];
    };
    let in_ancestry: HashSet<&str> = paths.iter().flatten().map(|l| l.name.as_str()).collect();
    let want: Vec<&str> =
        chain.iter().filter(|l| in_ancestry.contains(l.name.as_str()) && !l.is_virtual).map(|l| l.name.as_str()).collect();
    let ok = want.len() == o.scoped.len() && want.iter().zip(&o.scoped).all(|(w, s)| w == s);
    if !ok {
        return vec![format!(
            "line {}: object {} scoped {} is not the non-virtual ancestry of {} in topological order (expected {}) (V6)",
            o.pos.line,
            quote(&o.name),
            fmt_slice(&o.scoped),
            quote(o.scoped.last().unwrap()),
            fmt_slice(&want)
        )];
    }
    check_scope_wildcards(s, o)
}

fn check_scope_wildcards(s: &Spec, o: &Object) -> Vec<String> {
    let mut errs = Vec::new();
    for lvl in &o.scope_wildcards {
        if s.level_is_virtual(lvl) {
            errs.push(format!(
                "line {}: object {} declares `{} wildcard`, but {} is a virtual level — containment emits no conjunct for a virtual level, so the marker could never narrow or widen anything (V6)",
                o.pos.line,
                quote(&o.name),
                lvl,
                quote(lvl)
            ));
        } else if o.is_level_entity() && lvl == o.level() {
            errs.push(format!(
                "line {}: object {} declares `{} wildcard`, but {} is its own level, whose scope column is the primary key {} — a primary key is never NULL, so the marker could never match a row (V6)",
                o.pos.line,
                quote(&o.name),
                lvl,
                quote(lvl),
                quote(o.pk())
            ));
        }
        let mut seen = HashSet::new();
        for v in o.scope_wildcard_verbs.get(lvl).map(Vec::as_slice).unwrap_or(&[]) {
            if op_to_cmd(v).is_empty() {
                errs.push(format!(
                    "line {}: object {} wildcard at {} confers unknown verb {} (expected select, insert, update or delete)",
                    o.pos.line,
                    quote(&o.name),
                    quote(lvl),
                    quote(v)
                ));
            }
            if seen.contains(v) {
                errs.push(format!(
                    "line {}: object {} wildcard at {} names verb {} twice",
                    o.pos.line,
                    quote(&o.name),
                    quote(lvl),
                    quote(v)
                ));
            }
            seen.insert(v.clone());
        }
    }
    for lvl in o.scope_wildcard_verbs.keys() {
        if !o.scope_is_wildcard(lvl) {
            errs.push(format!(
                "line {}: object {} bounds a wildcard at level {} that it does not declare",
                o.pos.line,
                quote(&o.name),
                quote(lvl)
            ));
        }
    }
    errs
}

fn check_level_entity(o: &Object, chain: &[&Level]) -> Vec<String> {
    let Some(level) = &o.level else { return Vec::new() };
    let mut errs = Vec::new();
    if !chain.iter().any(|l| &l.name == level) {
        errs.push(format!(
            "line {}: object {} declares level {} which is not a topology level",
            o.pos.line,
            quote(&o.name),
            quote(level)
        ));
    }
    if o.scoped.last() != Some(level) {
        errs.push(format!(
            "line {}: object {} level {} must be its deepest scoped level",
            o.pos.line,
            quote(&o.name),
            quote(level)
        ));
    }
    errs
}

fn check_object_relations<'a>(s: &Spec, o: &'a Object) -> (Rels<'a>, Vec<String>) {
    let mut errs = Vec::new();
    let mut rels: Rels = HashMap::new();
    for r in &o.relations {
        if rels.contains_key(r.name.as_str()) {
            errs.push(format!("line {}: object {} has duplicate relation {}", r.pos.line, quote(&o.name), quote(&r.name)));
        }
        rels.insert(r.name.as_str(), r);
        match &r.repr {
            Repr::MemberIn(mi) => {
                if s.level_by_name(&mi.level).is_none() {
                    errs.push(format!(
                        "line {}: object {} relation {} via memberin references unknown level {}",
                        r.pos.line,
                        quote(&o.name),
                        quote(&r.name),
                        quote(&mi.level)
                    ));
                }
            }
            Repr::Closure(c) => {
                if let Some(claim) = &c.claim {
                    let missing = c.missing.as_deref().unwrap_or("");
                    if missing != "allow" && missing != "deny" {
                        errs.push(format!(
                            "object {} relation {}: closure claim {}: missing must be allow or deny, got {}",
                            quote(&o.name),
                            quote(&r.name),
                            quote(claim),
                            quote(missing)
                        ));
                    }
                } else if c.base.is_none() {
                    errs.push(format!(
                        "object {} relation {}: a closure keyed on the owner needs `base <table>(id, parent)`",
                        quote(&o.name),
                        quote(&r.name)
                    ));
                }
            }
            Repr::Object(vo) => errs.extend(validate_borrow_operation(s, r, vo)),
            Repr::Role => errs.extend(check_via_role(s, o, r)),
            _ => {}
        }
        if let Repr::Group(g) = &r.repr
            && g.materialized
            && r.types.len() > 1
        {
            errs.push(format!(
                "line {}: object {} relation {} is `via group ... materialized` with multiple kinds {} — a materialized via-group must be single-kind (the flat tags only one principal_kind and the floor matches the id alone)",
                r.pos.line,
                quote(&o.name),
                quote(&r.name),
                fmt_slice(&r.types)
            ));
        }
        if let Repr::Grant(g) = &r.repr
            && g.is_async
            && !g.tracked
        {
            errs.push(format!(
                "line {}: object {} relation {} is `via grant ... async` without `tracked` — the async affordance index is maintained off the changelog, which requires `tracked`",
                r.pos.line,
                quote(&o.name),
                quote(&r.name)
            ));
        }
        errs.extend(check_transient_relation(s, o, r));
    }
    (rels, errs)
}

fn check_transient_relation(s: &Spec, o: &Object, r: &Relation) -> Vec<String> {
    let transient = r.types.iter().filter(|t| s.subject_by_name(t).is_some_and(|st| st.transient)).count();
    if transient == 0 {
        return Vec::new();
    }
    let mut errs = Vec::new();
    if transient != r.types.len() {
        errs.push(format!(
            "line {}: object {} relation {} mixes a transient subject with standing ones {}: the listing names standing principals and reports a transient one as a claim, so they cannot share a relation",
            r.pos.line,
            quote(&o.name),
            quote(&r.name),
            fmt_slice(&r.types)
        ));
    }
    if !matches!(r.repr, Repr::Column(_)) {
        errs.push(format!(
            "line {}: object {} relation {} names a transient subject {}: a transient subject is a claim compared to a column of the row (`via <column>`)",
            r.pos.line,
            quote(&o.name),
            quote(&r.name),
            go_type_name(&r.repr)
        ));
    }
    if r.types.len() > 1 {
        for t in &r.types {
            if s.subject_by_name(t).is_some_and(|st| st.transient_set) {
                errs.push(format!(
                    "line {}: object {} relation {} names the transient set {} beside other subjects {}: a set's claim lists values and another subject's claim holds one, so they cannot share a relation",
                    r.pos.line,
                    quote(&o.name),
                    quote(&r.name),
                    quote(t),
                    fmt_slice(&r.types)
                ));
                break;
            }
        }
    }
    errs
}

fn check_via_role(s: &Spec, o: &Object, r: &Relation) -> Vec<String> {
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
    if s.preset_level_map().get(lvl).is_none_or(|v| v.is_empty()) {
        return vec![format!(
            "line {}: object {} relation {} is `via role` at level {}, but no vocabulary declares a preset at that level — the check would compile to an empty key set that can never match",
            r.pos.line,
            quote(&o.name),
            quote(&r.name),
            quote(lvl)
        )];
    }
    Vec::new()
}

fn check_grant_rel_count(o: &Object) -> Vec<String> {
    let n = o.relations.iter().filter(|r| matches!(r.repr, Repr::Grant(_))).count();
    if n > 1 {
        return vec![format!("object {} declares {} `via grant` relations — at most one is allowed", quote(&o.name), n)];
    }
    Vec::new()
}

fn check_track_changelog(o: &Object) -> Vec<String> {
    if o.track_owner && o.owner_changelog_cols().is_none() {
        return vec![format!(
            "line {}: object {} declares `track owner` but has no owner column (a `via <id> where <kind> = ...` relation)",
            o.pos.line,
            quote(&o.name)
        )];
    }
    if o.track_visibility && o.mode_changelog_col().is_none() {
        return vec![format!(
            "line {}: object {} declares `track visibility` but has no `mode <col>` term",
            o.pos.line,
            quote(&o.name)
        )];
    }
    Vec::new()
}

fn check_gates(s: &Spec, o: &Object, rels: &Rels) -> Vec<String> {
    let has_verb = |obj: &Object, verb: &str| obj.perms.iter().any(|p| p.verb == verb);
    let mut errs = Vec::new();
    for g in &o.gates {
        if !has_verb(o, &g.verb) {
            errs.push(format!(
                "line {}: object {} gate `{} via {} -> {}` gates verb {}, which the object does not declare as a permission",
                g.pos.line,
                quote(&o.name),
                g.verb,
                g.relation,
                g.perm,
                quote(&g.verb)
            ));
        }
        let Some(r) = rels.get(g.relation.as_str()) else {
            errs.push(format!("line {}: object {} gate references unknown relation {}", g.pos.line, quote(&o.name), quote(&g.relation)));
            continue;
        };
        if r.types.is_empty() {
            errs.push(format!(
                "line {}: object {} gate relation {} resolves to no object type",
                g.pos.line,
                quote(&o.name),
                quote(&g.relation)
            ));
            continue;
        }
        for tname in &r.types {
            let Some(target) = s.object_by_name(tname) else {
                errs.push(format!(
                    "line {}: object {} gate relation {} targets {}, which is not a governed object",
                    g.pos.line,
                    quote(&o.name),
                    quote(&g.relation),
                    quote(tname)
                ));
                continue;
            };
            if !has_verb(target, &g.perm) {
                errs.push(format!(
                    "line {}: object {} gate `{} via {} -> {}`: target object {} has no permission {}",
                    g.pos.line,
                    quote(&o.name),
                    g.verb,
                    g.relation,
                    g.perm,
                    quote(tname),
                    quote(&g.perm)
                ));
            }
        }
    }
    errs
}

pub fn perm_positive(n: &PermNode) -> bool {
    match n {
        PermNode::Leaf(_) => true,
        PermNode::Not(_) => false,
        PermNode::And(kids) => kids.iter().any(perm_positive),
        PermNode::Or(kids) => kids.iter().all(perm_positive) && !kids.is_empty(),
    }
}

pub fn row_term_admitting(n: &PermNode) -> Option<&Term> {
    match n {
        PermNode::Leaf(t) => {
            if is_row_leaf(n) {
                Some(t)
            } else {
                None
            }
        }
        PermNode::Not(k) => {
            if is_row_leaf(k) {
                return k.term();
            }
            row_term_admitting(k)
        }
        PermNode::And(kids) => {
            let mut row_term: Option<&Term> = None;
            let mut grants = false;
            for k in kids {
                if is_row_leaf(k) {
                    row_term = k.term();
                } else if let PermNode::Not(inner) = k
                    && is_row_leaf(inner)
                {
                    row_term = inner.term();
                } else {
                    if let Some(t) = row_term_admitting(k) {
                        return Some(t);
                    }
                    if perm_positive(k) {
                        grants = true;
                    }
                }
            }
            if row_term.is_some() && !grants { row_term } else { None }
        }
        PermNode::Or(kids) => kids.iter().find_map(row_term_admitting),
    }
}

fn check_perm_polarity(o: &Object, pm: &Perm) -> Option<String> {
    if !pm.tree.is_nil() && !perm_positive(&pm.tree) {
        return Some(format!(
            "line {}: permission {}.{} is not positively gated — a `not` (exclusion) must be combined with `and` with a positive grant, never used alone or as a union (`+`/`or`) branch",
            pm.pos.line, o.name, pm.verb
        ));
    }
    if let Some(t) = row_term_admitting(&pm.tree) {
        return Some(format!(
            "line {}: permission {}.{} uses {} where it would admit a caller by itself — a row term tests the row and names nobody, so it only narrows another term: write it inside an `and`, beside a term that grants",
            pm.pos.line,
            o.name,
            pm.verb,
            t.display()
        ));
    }
    None
}

fn validate_perm(s: &Spec, o: &Object, pm: &Perm, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    errs.extend(check_perm_polarity(o, pm));
    let mut has = HashSet::new();
    for l in &pm.layers {
        if !KNOWN_LAYERS.contains(&l.as_str()) {
            errs.push(format!("line {}: permission {}.{} has unknown layer {}", pm.pos.line, o.name, pm.verb, quote(l)));
        }
        has.insert(l.as_str());
    }
    if pm.layers.is_empty() {
        errs.push(format!("line {}: permission {}.{} has no layer tag", pm.pos.line, o.name, pm.verb));
    }
    let (has_rls, has_kernel, has_pdp, has_check) =
        (has.contains("rls"), has.contains("kernel"), has.contains("pdp"), has.contains("check"));
    if pm.guard.is_some() && !has_rls {
        errs.push(format!("line {}: permission {}.{} has a guard but is not @rls", pm.pos.line, o.name, pm.verb));
    }
    errs.extend(check_perm_maps(o, pm, has_rls, has_kernel, has_check));
    errs.extend(check_perm_terms(s, o, pm, rels, has_rls, has_kernel, has_pdp, has_check));
    errs
}

fn check_perm_maps(o: &Object, pm: &Perm, has_rls: bool, has_kernel: bool, has_check: bool) -> Vec<String> {
    let mut errs = Vec::new();
    let maps = pm.maps();
    if is_perm_key_lit(maps) && (has_rls || has_kernel) {
        errs.push(format!(
            "line {}: permission {}.{} maps to capability {} but is tagged @rls/@kernel — a row layer cannot distinguish a verb; use @pdp (V4)",
            pm.pos.line,
            o.name,
            pm.verb,
            quote(maps)
        ));
    }
    if has_rls && !maps.is_empty() && !table_op(maps) {
        errs.push(format!(
            "line {}: permission {}.{} is @rls but maps to {}, not a table op (select|insert|update|delete) (V4)",
            pm.pos.line,
            o.name,
            pm.verb,
            quote(maps)
        ));
    }
    if pm.predicate_only {
        if !has_rls {
            errs.push(format!(
                "line {}: permission {}.{} is `predicate` but not @rls — a predicate-only permission lends an @rls authority to other objects",
                pm.pos.line, o.name, pm.verb
            ));
        }
        if !maps.is_empty() {
            errs.push(format!(
                "line {}: permission {}.{} is both `predicate` and `maps {}` — a predicate-only permission emits no policy of its own",
                pm.pos.line, o.name, pm.verb, maps
            ));
        }
    }
    if has_check && !maps.is_empty() {
        errs.push(format!(
            "line {}: permission {}.{} is @check but also `maps {}` — a @check permission emits a callable point-check, not a policy",
            pm.pos.line, o.name, pm.verb, maps
        ));
    }
    errs
}

fn check_perm_terms(
    s: &Spec,
    o: &Object,
    pm: &Perm,
    rels: &Rels,
    has_rls: bool,
    has_kernel: bool,
    has_pdp: bool,
    has_check: bool,
) -> Vec<String> {
    let mut errs = Vec::new();
    let has_pred = has_rls || has_check;
    let at = |what: &str| format!("line {}: permission {}.{} {what}", pm.pos.line, o.name, pm.verb);
    for t in pm.tree.leaves() {
        if !t.grant_ref().is_empty() {
            match s.grant_by_name(t.grant_ref()) {
                None => errs.push(at(&format!("references unknown grant {} (via grant)", quote(t.grant_ref())))),
                Some(g) if g.claim_key.is_some() => errs.push(format!(
                    "line {}: claim grant {} is containment reach and cannot be an authority term",
                    pm.pos.line,
                    quote(&g.name)
                )),
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
            if t.row_col().is_empty() || t.row_val().is_empty() {
                errs.push(at("uses @row with an empty column or value — `@row(<column>, \"<value>\")`"));
            }
            if !has_pred {
                errs.push(at(
                    "uses @row but compiles no row predicate — a row term is a test of the row and the decision point cannot read it",
                ));
            }
        } else if !t.builtin().is_empty() {
            errs.extend(check_builtin_term(s, o, pm, t, rels, has_pred, has_pdp));
        } else if is_grant_selector_term(t.ident(), rels) {
            let (_, access) = grant_selector(t.ident(), rels).unwrap();
            if access.is_empty() {
                errs.push(at(&format!(
                    "grant term {} has an empty access class (use grantee:read|write|delete)",
                    quote(t.ident())
                )));
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

fn check_builtin_term(s: &Spec, o: &Object, pm: &Perm, t: &Term, rels: &Rels, has_rls: bool, has_pdp: bool) -> Vec<String> {
    let mut errs = Vec::new();
    let at = |what: &str| format!("line {}: permission {}.{} {what}", pm.pos.line, o.name, pm.verb);
    let b = t.builtin();
    if b == "external" {
        errs.push(at(&format!(
            "uses @external({}) — an adopter-supplied predicate may appear only in a `require` clause, so it can subtract authority and never add it (V14)",
            t.external_fn()
        )));
    } else if !KNOWN_BUILTINS.contains(&b) {
        errs.push(at(&format!(
            "uses unknown builtin @{b} (app_scope|scoped|session|open|store_manage|public|kind|self|within|holds)"
        )));
    }
    for ex in t.exclude_rels() {
        match rels.get(ex.as_str()) {
            None => errs.push(at(&format!("@app_scope(exclude {}) names no relation", quote(ex)))),
            Some(r) if !matches!(r.repr, Repr::Column(_)) => {
                errs.push(at(&format!("@app_scope(exclude {}) must exclude an owner column relation", quote(ex))))
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
        errs.push(at(&format!(
            "uses @public but maps to {} — @public is a world-read grant, valid only on select",
            quote(pm.maps())
        )));
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
        "claim" => {
            if t.claim_key().is_empty() || t.claim_val().is_empty() {
                errs.push(at("uses @claim with an empty key or value — `@claim(\"<key>\", \"<value>\")`"));
            }
            if !has_rls {
                errs.push(at(
                    "uses @claim but is not @rls — a claim is a row-layer test and the decision point cannot read it",
                ));
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

fn check_holds_term(s: &Spec, o: &Object, pm: &Perm, t: &Term, has_pred: bool, has_pdp: bool) -> Vec<String> {
    let mut errs = Vec::new();
    let at = |what: &str| format!("line {}: permission {}.{} {what}", pm.pos.line, o.name, pm.verb);
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

fn check_requires(s: &Spec, o: &Object, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    let mut seen = HashSet::new();
    for rq in &o.requires {
        if seen.contains(&rq.verb) {
            errs.push(format!(
                "line {}: object {} declares `require {}` more than once — a permission carries at most one restrictive clause",
                rq.pos.line,
                quote(&o.name),
                rq.verb
            ));
            continue;
        }
        seen.insert(rq.verb.clone());
        let Some(pm) = o.perms.iter().find(|p| p.verb == rq.verb) else {
            errs.push(format!(
                "line {}: object {} requires {} but declares no permission {} — a RESTRICTIVE policy with no permissive policy beside it denies every caller (V13)",
                rq.pos.line,
                quote(&o.name),
                quote(&rq.verb),
                quote(&rq.verb)
            ));
            continue;
        };
        if !pm.has_layer("rls") && !pm.has_layer("check") {
            errs.push(format!(
                "line {}: object {} requires {}, but permission {} compiles no row predicate (layers {}) — a `require` narrows a predicate and has nothing to narrow here (V13)",
                rq.pos.line,
                quote(&o.name),
                quote(&rq.verb),
                quote(&rq.verb),
                fmt_slice(&pm.layers)
            ));
        }
        if pm.has_layer("rls") && pm.maps().is_empty() && !pm.predicate_only {
            errs.push(format!(
                "line {}: object {} requires {}, but permission {} is @rls with no `maps` table-op — there is no policy to restrict (V13)",
                rq.pos.line,
                quote(&o.name),
                quote(&rq.verb),
                quote(&rq.verb)
            ));
        }
        errs.extend(check_require_terms(s, o, rq, rels));
    }
    errs
}

fn check_require_terms(s: &Spec, o: &Object, rq: &Require, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    let at = |what: String| format!("line {}: require {}.{} {what}", rq.pos.line, o.name, rq.verb);
    if !rq.tree.is_nil() && !perm_positive(&rq.tree) {
        errs.push(at("is not positively gated — a `not` must be combined with `and` with a positive term".into()));
    }
    if let Some(t) = row_term_admitting(&rq.tree) {
        errs.push(at(format!(
            "uses {} by itself — a row term only narrows another term: write it inside an `and`",
            t.display()
        )));
    }
    for t in rq.tree.leaves() {
        let b = t.builtin();
        if b == "external" {
            let f = t.external_fn();
            match s.external_by_name(f) {
                None => errs.push(at(format!(
                    "calls @external({f}) with no `external predicate {f}(...)` declaration (V14)"
                ))),
                Some(ext) if ext.arg_types.len() != t.external_args().len() => errs.push(at(format!(
                    "calls @external({f}) with {} argument(s); it is declared with {} (V14)",
                    t.external_args().len(),
                    ext.arg_types.len()
                ))),
                Some(_) => {}
            }
        } else if !t.grant_ref().is_empty() || matches!(b, "scoped" | "public" | "open") {
            errs.push(at(format!(
                "uses widening term {} — a `require` compiles to a RESTRICTIVE policy, which can only narrow (V13)",
                t.display()
            )));
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

fn validate_admits(s: &Spec, o: &Object, rels: &Rels) -> Vec<String> {
    let mut errs = Vec::new();
    let mapped: HashSet<&str> =
        o.perms.iter().filter(|pm| pm.has_layer("rls") && !pm.predicate_only).map(|pm| pm.maps()).collect();
    for a in &o.admits {
        for op in &a.ops {
            if op_to_cmd(op).is_empty() {
                errs.push(format!("line {}: object {} admits unknown operation {}", a.pos.line, quote(&o.name), quote(op)));
            } else if !mapped.contains(op.as_str()) {
                errs.push(format!(
                    "line {}: object {} admits {}, but no @rls permission maps {}, so there is no policy to join",
                    a.pos.line,
                    quote(&o.name),
                    op,
                    op
                ));
            }
        }
        let pm = a.perm("");
        errs.extend(check_perm_polarity(o, &pm));
        errs.extend(check_perm_terms(s, o, &pm, rels, true, false, false, false));
    }
    errs
}

fn check_field_access(o: &Object) -> Vec<String> {
    if o.field_principals.is_empty() {
        if let Some(f) = o.fields.first() {
            return vec![format!(
                "line {}: object {} declares field rules but no `fields {{ ... }}` principal set",
                f.pos.line,
                quote(&o.name)
            )];
        }
        return Vec::new();
    }
    let mut errs = Vec::new();
    let mut declared = HashSet::new();
    for p in &o.field_principals {
        if declared.contains(p) {
            errs.push(format!(
                "line {}: object {} declares field principal {} more than once",
                o.pos.line,
                quote(&o.name),
                quote(p)
            ));
        }
        declared.insert(p.clone());
    }
    let mut seen = HashSet::new();
    for f in &o.fields {
        if seen.contains(&f.name) {
            errs.push(format!("line {}: object {} declares field {} more than once", f.pos.line, quote(&o.name), quote(&f.name)));
        }
        seen.insert(f.name.clone());
        for tok in f.read.iter().chain(&f.write) {
            if !declared.contains(tok) {
                errs.push(format!(
                    "line {}: object {} field {} references {}, which is not a declared field principal (fields {{ ... }})",
                    f.pos.line,
                    quote(&o.name),
                    quote(&f.name),
                    quote(tok)
                ));
            }
        }
    }
    errs
}

fn check_duplicate_maps(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    for o in &s.objects {
        let mut first_verb: HashMap<&str, &str> = HashMap::new();
        for pm in &o.perms {
            if !pm.has_layer("rls") || pm.predicate_only || op_to_cmd(pm.maps()).is_empty() {
                continue;
            }
            if let Some(prev) = first_verb.get(pm.maps()) {
                errs.push(format!(
                    "line {}: object {} maps {} from both {} and {} — each emits a policy named {}_{} and the second silently replaces the first (V15)",
                    pm.pos.line,
                    quote(&o.name),
                    quote(pm.maps()),
                    quote(prev),
                    quote(&pm.verb),
                    o.table,
                    pm.maps()
                ));
                continue;
            }
            first_verb.insert(pm.maps(), &pm.verb);
        }
    }
    errs
}

fn check_externals(s: &Spec) -> Vec<String> {
    let mut used = HashSet::new();
    for o in &s.objects {
        for rq in &o.requires {
            for t in rq.tree.leaves() {
                if t.builtin() == "external" {
                    used.insert(t.external_fn().to_string());
                }
            }
        }
    }
    s.externals
        .iter()
        .filter(|e| !used.contains(&e.name))
        .map(|e| {
            format!(
                "line {}: external predicate {} is declared but never required — an unused escape hatch is an unaudited one (V14)",
                e.pos.line,
                quote(&e.name)
            )
        })
        .collect()
}

fn validate_grant_stores(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    let mut by_table: BTreeMap<&str, Vec<(&Object, &ViaGrant)>> = BTreeMap::new();
    let mut table_order: Vec<&str> = Vec::new();
    for o in &s.objects {
        let Some((rel, g)) = grant_relation(o) else { continue };
        if g.discrim_col.is_some() != g.discrim_val.is_some() {
            errs.push(format!(
                "object {} grant relation: a discriminator needs both a column and a value (`where <col> = \"<val>\"`)",
                quote(&o.name)
            ));
        }
        for k in &rel.types {
            if s.subject_by_name(k).is_none_or(|sub| sub.identifies().is_empty()) {
                errs.push(format!(
                    "object {} grant relation kind {} is not a claim-bearing subject (no `subject {} {{ ... identifies <claim> }}`)",
                    quote(&o.name),
                    quote(k),
                    k
                ));
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
                errs.push(format!(
                    "object {} shares grant store {} with another grant relation but is not discriminated — add `where <col> = \"<val>\"`",
                    quote(&obj.name),
                    quote(table)
                ));
                continue;
            };
            if dc != col {
                errs.push(format!(
                    "grant relations sharing store {} must discriminate on the SAME column ({} vs {})",
                    quote(table),
                    quote(col),
                    quote(dc)
                ));
            }
            let dv = g.discrim_val.as_deref().unwrap_or("");
            if let Some(prev) = seen.get(dv) {
                errs.push(format!(
                    "objects {} and {} share grant store {} with the SAME discriminator value {} — values must be distinct",
                    quote(prev),
                    quote(&obj.name),
                    quote(table),
                    quote(dv)
                ));
            }
            seen.insert(dv, &obj.name);
        }
    }
    errs
}

fn validate_store_manage(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    for o in &s.objects {
        if !object_uses_store_manage(o) {
            continue;
        }
        let descs = s.store_descriptors(&o.table);
        if descs.is_empty() {
            errs.push(format!(
                "object {} uses @store_manage but no object uses its table {} as a grant store",
                quote(&o.name),
                quote(&o.table)
            ));
            continue;
        }
        for d in descs {
            if object_grant_edge(d).is_some_and(|e| e.discrim_col.is_none()) {
                errs.push(format!(
                    "object {} uses @store_manage but grant store {} on object {} is not discriminated (`where <col> = \"<val>\"`)",
                    quote(&o.name),
                    quote(&o.table),
                    quote(&d.name)
                ));
            }
        }
    }
    errs
}

fn validate_cross_object_acyclic(s: &Spec) -> Vec<String> {
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for o in &s.objects {
        for r in &o.relations {
            let Repr::Object(vo) = &r.repr else { continue };
            if s.object_by_name(&vo.object).is_none() {
                return vec![format!(
                    "object {} relation {} references unknown object {} (via object)",
                    quote(&o.name),
                    quote(&r.name),
                    quote(&vo.object)
                )];
            }
            edges.entry(&o.name).or_default().push(&vo.object);
        }
    }
    fn dfs<'a>(n: &'a str, edges: &HashMap<&'a str, Vec<&'a str>>, color: &mut HashMap<&'a str, u8>) -> bool {
        color.insert(n, 1);
        for &m in edges.get(n).map(Vec::as_slice).unwrap_or(&[]) {
            match color.get(m).copied().unwrap_or(0) {
                1 => return true,
                0 if dfs(m, edges, color) => return true,
                _ => {}
            }
        }
        color.insert(n, 2);
        false
    }
    let mut color: HashMap<&str, u8> = HashMap::new();
    for o in &s.objects {
        if color.get(o.name.as_str()).copied().unwrap_or(0) == 0 && dfs(&o.name, &edges, &mut color) {
            return vec![format!(
                "cross-object `via object` references form a cycle through {} — this would generate mutually-recursive definers",
                quote(&o.name)
            )];
        }
    }
    Vec::new()
}

fn validate_grant_reach(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    let mut bases: HashMap<String, &Grant> = HashMap::new();
    let mut names = HashSet::new();
    for g in &s.grants {
        if names.contains(&g.name) {
            errs.push(format!("line {}: grant {} is declared twice", g.pos.line, quote(&g.name)));
        }
        names.insert(g.name.clone());
        if g.claim_key.is_some() {
            errs.extend(validate_claim_grant(s, g));
            continue;
        }
        errs.extend(validate_grant_scopes(s, g));
        let base = g.definer_base().to_string();
        match bases.get(&base) {
            Some(prior) if !same_grant_emission(prior, g) => errs.push(format!(
                "line {}: grants {} and {} both emit {}_reach from different edges; give one its own definer name with `named`",
                g.pos.line,
                quote(&prior.name),
                quote(&g.name),
                base
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

fn validate_claim_grant(s: &Spec, g: &Grant) -> Vec<String> {
    let mut errs = Vec::new();
    if s.level_is_virtual(&g.level) {
        errs.push(format!(
            "line {}: claim grant {} reaches virtual level {}, which has no column to lift",
            g.pos.line,
            quote(&g.name),
            quote(&g.level)
        ));
    }
    if g.verbs.is_empty() {
        errs.push(format!("line {}: claim grant {} must name the operations it confers", g.pos.line, quote(&g.name)));
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
        errs.push(format!("line {}: claim grant {} has no edge, so it takes no edge options", g.pos.line, quote(&g.name)));
    }
    errs
}

fn validate_grant_scopes(s: &Spec, g: &Grant) -> Vec<String> {
    let mut errs = Vec::new();
    let mut previous = g.level.as_str();
    let mut seen_cols: HashSet<&str> = [g.grantee_col(), g.level_col()].into_iter().collect();
    for scope in &g.scopes {
        if !s.level_descends_from(&scope.level, previous) || s.level_is_virtual(&scope.level) {
            errs.push(format!(
                "line {}: grant {} scope {} must be a non-virtual level below {}",
                g.pos.line,
                quote(&g.name),
                quote(&scope.level),
                quote(previous)
            ));
        }
        if scope.missing != "allow" && scope.missing != "deny" {
            errs.push(format!(
                "line {}: grant {} scope {}: missing must be allow or deny, got {}",
                g.pos.line,
                quote(&g.name),
                quote(&scope.level),
                quote(&scope.missing)
            ));
        }
        if seen_cols.contains(scope.column.as_str()) {
            errs.push(format!(
                "line {}: grant {} scope {} reuses column {}",
                g.pos.line,
                quote(&g.name),
                quote(&scope.level),
                quote(&scope.column)
            ));
        }
        seen_cols.insert(&scope.column);
        previous = &scope.level;
    }
    errs
}

fn validate_grant_uses(s: &Spec, o: &Object) -> Vec<String> {
    let mut errs = Vec::new();
    let mut claimed = HashSet::new();
    for u in &o.reach_uses {
        let g = match s.grant_by_name(&u.grant) {
            Some(g) if g.claim_key.is_none() => g,
            _ => {
                errs.push(format!(
                    "line {}: object {} selects the reach of {}, which is not an edge grant",
                    u.pos.line,
                    quote(&o.name),
                    quote(&u.grant)
                ));
                continue;
            }
        };
        errs.extend(validate_grant_use_target(s, o, g, u));
        let ops: Vec<&str> =
            if u.ops.is_empty() { ORDERED_TABLE_OPS.to_vec() } else { u.ops.iter().map(String::as_str).collect() };
        for op in ops {
            if op_to_cmd(op).is_empty() {
                errs.push(format!(
                    "line {}: object {} reach {} names unknown operation {}",
                    u.pos.line,
                    quote(&o.name),
                    g.name,
                    quote(op)
                ));
                continue;
            }
            if !u.ops.is_empty() && !g.confers(op) {
                errs.push(format!(
                    "line {}: object {} reach {} selects {}, which grant {} does not confer",
                    u.pos.line,
                    quote(&o.name),
                    g.name,
                    op,
                    quote(&g.name)
                ));
            }
            let key = format!("{}:{}", g.name, op);
            if claimed.contains(&key) {
                errs.push(format!(
                    "line {}: object {} selects the reach of {} for {} twice",
                    u.pos.line,
                    quote(&o.name),
                    quote(&g.name),
                    op
                ));
            }
            claimed.insert(key);
        }
    }
    errs
}

fn validate_grant_use_target(s: &Spec, o: &Object, g: &Grant, u: &GrantUse) -> Vec<String> {
    let mut errs = Vec::new();
    if !contains(&o.scoped, &g.level) {
        errs.push(format!(
            "line {}: object {} selects the reach of {} at {}, which is outside its scope",
            u.pos.line,
            quote(&o.name),
            quote(&g.name),
            quote(&g.level)
        ));
    }
    if !s.grant_reached_by_subject(&g.name) {
        errs.push(format!(
            "line {}: object {} selects the reach of {}, which no subject reaches through",
            u.pos.line,
            quote(&o.name),
            quote(&g.name)
        ));
    }
    if let Some(via) = &u.via {
        errs.extend(validate_grant_use_via(s, o, g, u, via));
    } else if g.scopes.is_empty() {
        errs.push(format!(
            "line {}: object {} reach {}: unscoped and bound need a grant with scope levels",
            u.pos.line,
            quote(&o.name),
            g.name
        ));
    } else if let Some(bound) = &u.bound
        && !g.has_scope(bound)
    {
        errs.push(format!(
            "line {}: object {} reach {} bound {}: the level must be one of the grant's scopes",
            u.pos.line,
            quote(&o.name),
            g.name,
            bound
        ));
    }
    errs
}

fn validate_grant_use_via(s: &Spec, o: &Object, g: &Grant, u: &GrantUse, via_name: &str) -> Vec<String> {
    let via = s.grant_by_name(via_name);
    let bad = match via {
        None => true,
        Some(v) => v.claim_key.is_some() || std::ptr::eq(v, g) || v.level != g.level,
    };
    if bad {
        return vec![format!(
            "line {}: object {} reach {} via {}: the replacement must be another edge grant at {}",
            u.pos.line,
            quote(&o.name),
            g.name,
            via_name,
            quote(&g.level)
        )];
    }
    let via = via.unwrap();
    let ops: Vec<&str> = if u.ops.is_empty() { ORDERED_TABLE_OPS.to_vec() } else { u.ops.iter().map(String::as_str).collect() };
    ops.into_iter()
        .filter(|op| g.confers(op) && !via.confers(op))
        .map(|op| {
            format!(
                "line {}: object {} reach {} via {}: {} does not confer {}",
                u.pos.line,
                quote(&o.name),
                g.name,
                via_name,
                quote(via_name),
                op
            )
        })
        .collect()
}

fn validate_borrow_operation(s: &Spec, r: &Relation, vo: &ViaObject) -> Vec<String> {
    let Some(op) = &vo.op else { return Vec::new() };
    if op_to_cmd(op).is_empty() {
        return vec![format!("line {}: relation {} borrows for unknown operation {}", r.pos.line, quote(&r.name), quote(op))];
    }
    let Some(other) = s.object_by_name(&vo.object) else { return Vec::new() };
    for pm in &other.perms {
        if pm.verb == vo.verb && !pm.predicate_only {
            return vec![format!(
                "line {}: relation {} borrows {}->{} for {}, but that permission already maps {}; `for` selects the operation of a predicate-only permission",
                r.pos.line,
                quote(&r.name),
                vo.object,
                vo.verb,
                op,
                pm.maps()
            )];
        }
    }
    Vec::new()
}

fn validate_permission_exports(s: &Spec) -> Vec<String> {
    let mut errs = Vec::new();
    let mut names = HashSet::new();
    for obj in &s.objects {
        for export in &obj.exports {
            if names.contains(&export.name) {
                errs.push(format!("line {}: permission export {} is declared twice", export.pos.line, quote(&export.name)));
            }
            names.insert(export.name.clone());
            errs.extend(validate_permission_export(s, obj, export));
        }
    }
    errs
}

fn validate_permission_export(s: &Spec, obj: &Object, export: &PermissionExport) -> Vec<String> {
    let Some(pm) = mapped_perm(obj, &export.verb) else {
        return vec![format!(
            "line {}: export {}.{} needs a permission that maps a table operation under @rls",
            export.pos.line, obj.name, export.verb
        )];
    };
    let mut errs = Vec::new();
    let mut params = HashSet::new();
    let mut names = HashSet::new();
    for param in &export.params {
        let pname = param.name();
        if names.contains(&pname) || params.contains(&param.column) {
            errs.push(format!(
                "line {}: export {} binds column {} or parameter {} twice",
                export.pos.line,
                quote(&export.name),
                quote(&param.column),
                quote(&pname)
            ));
        }
        names.insert(pname.clone());
        params.insert(param.column.clone());
        if !EXPORT_PARAMETER_TYPES.contains(&param.ty.as_str()) {
            errs.push(format!(
                "line {}: export {} parameter {} has unsupported type {}",
                export.pos.line,
                quote(&export.name),
                quote(&pname),
                quote(&param.ty)
            ));
        }
    }
    for column in exported_columns(s, &exported_row(s, obj, pm)) {
        if !params.contains(&column) {
            errs.push(format!(
                "line {}: export {} reads row column {}, which no parameter binds",
                export.pos.line,
                quote(&export.name),
                quote(&column)
            ));
        }
    }
    errs
}
