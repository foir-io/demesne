use crate::genfn::{DefinerArm, GenFn, binds_every, grant_edge_exists};
use crate::rls::{Virtual, owner_col_present_pub, platform_role_fn};
use crate::Sql;
use demesne_gocompat::quote;
use demesne_model::analysis::*;
use demesne_model::conditional::*;
use demesne_model::topology;
use demesne_model::vocab::to_runtime;
use demesne_syntax::*;
use std::collections::{BTreeSet, HashMap, HashSet};

type R<T> = Result<T, String>;
type Seen = HashSet<String>;

fn kind_cond(rs: &RoleStore, alias: &str) -> Vec<String> {
    match &rs.kind_col {
        None => Vec::new(),
        Some(k) => vec![format!("{alias}{k} = '{}'", rs.kind_val.as_deref().unwrap_or(""))],
    }
}

fn revoked_cond(rs: &RoleStore, alias: &str) -> Vec<String> {
    match &rs.revoked_col {
        None => Vec::new(),
        Some(r) => vec![format!("{alias}{r} IS NULL")],
    }
}

fn or(o: &Option<String>) -> &str {
    o.as_deref().unwrap_or("")
}

fn leaf(obj: &Object) -> &str {
    obj.scoped.last().map(String::as_str).unwrap_or("")
}

fn sql_text_or_null(v: &str) -> String {
    if v.is_empty() { "NULL::text".into() } else { format!("'{v}'::text") }
}

fn accessor_repr_covered(r: &Repr) -> bool {
    match r {
        Repr::Closure(c) => c.claim.is_none(),
        Repr::Column(_) | Repr::Grant(_) | Repr::Role | Repr::Group(_) | Repr::Composition(_) => true,
        _ => false,
    }
}

fn accessor_gen_fn_named(name: String, id_t: &str, branches: &[String]) -> GenFn {
    GenFn {
        name,
        sig: format!("p_id {id_t}"),
        returns: format!("TABLE(source text, principal_kind text, principal_id {id_t}, access text)"),
        raw_body: true,
        body: format!("  {}", branches.join("\n  UNION ALL\n  ")),
        ..Default::default()
    }
}

fn accessor_gen_fn(table: &str, id_t: &str, branches: &[String]) -> GenFn {
    accessor_gen_fn_named(format!("{table}_accessors"), id_t, branches)
}

fn owner_accessor_branch(table: &str, pk: &str, kind: &str, vc: &ViaColumn, first: bool) -> String {
    if first {
        return format!(
            "SELECT 'owner'::text AS source, '{kind}'::text AS principal_kind, {} AS principal_id, 'write'::text AS access\n    FROM {table} WHERE {pk} = p_id AND {}",
            vc.column,
            owner_col_present_pub(vc)
        );
    }
    format!(
        "SELECT 'owner'::text, '{kind}'::text, {}, 'write'::text\n    FROM {table} WHERE {pk} = p_id AND {}",
        vc.column,
        owner_col_present_pub(vc)
    )
}

fn owner_excl_cond(vc: &ViaColumn) -> String {
    match &vc.discrim_col {
        Some(d) => format!("r.{d} IS DISTINCT FROM '{}'", vc.discrim_val.as_deref().unwrap_or("")),
        None => format!("r.{} IS NULL", vc.column),
    }
}

fn grant_accessor_branch(g: &ViaGrant) -> String {
    let mut conds = vec![format!("{} = p_id", g.record_col)];
    if let Some(d) = &g.discrim_col {
        conds.push(format!("{d} = '{}'", g.discrim_val.as_deref().unwrap_or("")));
    }
    format!(
        "SELECT 'grant'::text, {}, {}, {}\n    FROM {} WHERE {}",
        g.kind_col,
        g.principal_col,
        g.access_col,
        g.table,
        conds.join(" AND ")
    )
}

fn group_accessor_branch(table: &str, pk: &str, kind: &str, g: &ViaGroup, flat: &str) -> String {
    if g.materialized && !flat.is_empty() {
        return format!(
            "SELECT 'group'::text, '{kind}'::text, f.principal_id, 'read'::text\n    FROM {flat} f\n    WHERE f.resource_id = p_id"
        );
    }
    format!(
        "SELECT 'group'::text, '{kind}'::text, c.{}, 'read'::text\n    FROM {table} t\n    JOIN {} c ON c.{} = t.{}\n    WHERE t.{pk} = p_id",
        g.member_col, g.closure, g.group_col, g.col
    )
}

fn closure_accessor_branch(table: &str, pk: &str, kind: &str, c: &ViaClosure) -> String {
    format!(
        "SELECT 'closure'::text, '{kind}'::text, x.{}, 'read'::text\n    FROM {table} t\n    JOIN {} x ON x.{} = t.{}\n    WHERE t.{pk} = p_id",
        c.ancestor_col, c.closure, c.descendant_col, c.col
    )
}

fn object_accessor_branch(table: &str, pk: &str, vo: &ViaObject, other_table: &str, schema: &str) -> String {
    format!(
        "SELECT a.source, a.principal_kind, a.principal_id, a.access\n    FROM {table} t\n    JOIN LATERAL {schema}.{other_table}_accessors(t.{}) a ON true\n    WHERE t.{pk} = p_id",
        vo.col
    )
}

fn composition_accessor_branch(table: &str, schema: &str, vc: &ViaComposition) -> String {
    let mut conds = vec![format!("e.{} = p_id", vc.child_col)];
    if let Some(k) = &vc.kind_col {
        conds.push(format!("e.{k} = '{}'", vc.kind_val.as_deref().unwrap_or("")));
    }
    format!(
        "SELECT a.source, a.principal_kind, a.principal_id, a.access\n    FROM {} e\n    JOIN LATERAL {schema}.{table}_direct_accessors(e.{}) a ON true\n    WHERE {}",
        vc.table,
        vc.parent_col,
        conds.join(" AND ")
    )
}

fn def_admin_excl_cond(sel: &Perm, rels: &Rels) -> String {
    for t in sel.tree.leaves() {
        if t.builtin() != "app_scope" {
            continue;
        }
        let mut conds = Vec::new();
        for ex in t.exclude_rels() {
            if let Some(r) = rels.get(ex.as_str())
                && let Repr::Column(vc) = &r.repr
            {
                conds.push(owner_excl_cond(vc));
            }
        }
        if !conds.is_empty() {
            return conds.join(" AND ");
        }
    }
    String::new()
}

fn structural_accessor_coverage(obj: &Object) -> (bool, String) {
    let rels = rels_of(obj);
    let Some(sel) = object_select_perm(obj) else { return (true, String::new()) };
    let op = accessor_tree_op(&sel.tree);
    if !op.is_empty() {
        return (false, format!("its SELECT permission uses {}, which the union enumerator cannot represent", quote(op)));
    }
    for t in sel.tree.leaves() {
        if !t.builtin().is_empty() || !t.walk_verb().is_empty() || t.ident().is_empty() {
            continue;
        }
        let Some(r) = rels.get(t.ident()) else { continue };
        match &r.repr {
            Repr::Role => {}
            Repr::MemberIn(mi) => {
                if mi.reached_by {
                    return (false, format!(
                        "relation {} is `memberin ... reachedby` — the caller-reach gate is not expressible in the structural enumerator, so reverse queries over it are unsupported (the RLS floor still enforces it)",
                        quote(t.ident())
                    ));
                }
            }
            other => {
                return (false, format!(
                    "relation {} ({}) is not enumerable by the structural accessor path (only via-role / via-memberin)",
                    quote(t.ident()),
                    go_type_name(other)
                ));
            }
        }
    }
    (true, String::new())
}

fn grant_access(g: &Grant) -> &'static str {
    if g.verbs.is_empty() {
        return "write";
    }
    for op in ["update", "insert", "delete", "select"] {
        if contains(&g.verbs, op) {
            return access_for(op);
        }
    }
    "read"
}

fn hold_perm_cond(perms_col: &str, implied_by: &str) -> String {
    if implied_by.is_empty() {
        return format!("p_perm = ANY(r.{perms_col})");
    }
    format!("r.{perms_col}::text[] && {implied_by}(p_perm)")
}

impl<'a> Sql<'a> {
    pub fn emit_definers(&self) -> R<Vec<GenFn>> {
        let d = Sql { s: self.s, definer_body: true };
        d.emit_definers_inner()
    }

    fn emit_definers_inner(&self) -> R<Vec<GenFn>> {
        let mut out: Vec<GenFn> = Vec::new();
        let virt: Virtual = topology::chain(self.s)
            .map(|c| c.into_iter().filter(|l| l.is_virtual).map(|l| l.name.clone()).collect())
            .unwrap_or_default();
        self.def_emit_membership(&mut out)?;
        self.def_emit_grant_reach(&mut out);
        let rs = self.s.default_role_store();
        let preset_levels = self.s.preset_level_map();
        let mut seen = Seen::new();
        self.def_emit_role_definers(&mut out, &mut seen, rs, &preset_levels)?;
        self.def_emit_platform_roles(&mut out, &mut seen, rs, &preset_levels);
        self.def_emit_scoped_memberin(&mut out, &mut seen, rs, &preset_levels);
        self.def_emit_holds_perm(&mut out, &mut seen)?;
        self.def_emit_kernel(&mut out, &mut seen)?;
        self.def_emit_grant_relations(&mut out, &mut seen);
        self.def_emit_accessors(&mut out, &mut seen)?;
        self.def_emit_structural_accessors(&mut out, &mut seen)?;
        self.def_emit_closure(&mut out, &mut seen);
        self.def_emit_group(&mut out, &mut seen);
        self.def_emit_cross_object(&mut out, &mut seen, &virt)?;
        self.def_emit_composition(&mut out, &mut seen, &virt)?;
        self.def_emit_store_manage(&mut out, &mut seen, &virt)?;
        self.def_emit_materialized_flat_members(&mut out, &mut seen);
        self.def_emit_permission_exports(&mut out, &virt)?;
        for f in &mut out {
            f.schema = self.s.definer_schema().to_string();
            f.table_schema = self.s.table_schema().to_string();
        }
        Ok(out)
    }

    fn def_emit_membership(&self, out: &mut Vec<GenFn>) -> R<()> {
        for sub in &self.s.subjects {
            let Some(m) = &sub.membership else { continue };
            if m.id_col.is_empty() || m.flag_col.is_empty() {
                return Err(format!("subject {} membership needs (idcol, flagcol)", quote(&sub.name)));
            }
            let mut conj = vec![format!("{} = user_id", m.id_col), m.flag_col.clone()];
            if let Some(ac) = &m.active_col {
                conj.push(format!("{ac} = '{}'", or(&m.active_val)));
            }
            let sig = format!("user_id {}", self.s.id_type());
            let strict = binds_every(&sig, &[&conj]);
            out.push(GenFn { name: m.flag_col.clone(), body: grant_edge_exists(&m.table, &conj), sig, strict, ..Default::default() });
        }
        Ok(())
    }

    fn grant_session_scope_conjuncts(&self, g: &Grant) -> Vec<String> {
        g.scopes
            .iter()
            .map(|scope| {
                let claim = self.session_claim(&self.s.claim_key_for_level(&scope.level));
                let mut terms = vec![format!("{} IS NULL", scope.column)];
                if scope.missing == "allow" {
                    terms.push(format!("{claim} IS NULL"));
                }
                terms.push(format!("{} = {}", scope.column, claim));
                format!("({})", terms.join(" OR "))
            })
            .collect()
    }

    fn grant_scope_definers(&self, g: &Grant, conj: &[String]) -> Vec<GenFn> {
        if g.scopes.is_empty() {
            return Vec::new();
        }
        let id_t = self.s.id_type();
        let base = format!("{}_reach", g.definer_base());
        let mut unscoped = conj.to_vec();
        for scope in &g.scopes {
            unscoped.push(format!("{} IS NULL", scope.column));
        }
        let mut set_conj = vec![conj[0].clone()];
        set_conj.extend(unscoped[2..].iter().cloned());
        let unscoped_sig = format!("user_id {id_t}, check_{}_id {id_t}", g.level);
        let set_sig = format!("user_id {id_t}");
        let mut out = vec![
            GenFn {
                name: format!("{base}_unscoped"),
                strict: binds_every(&unscoped_sig, &[&unscoped]),
                sig: unscoped_sig,
                body: grant_edge_exists(g.table(), &unscoped),
                ..Default::default()
            },
            GenFn {
                name: format!("{base}_unscoped_set"),
                strict: binds_every(&set_sig, &[&set_conj]),
                sig: set_sig,
                returns: format!("SETOF {id_t}"),
                body: format!("{} FROM {} WHERE {}", g.level_col(), g.table(), set_conj.join(" AND ")),
                ..Default::default()
            },
        ];
        let mut explicit = conj.to_vec();
        let mut args = vec![format!("user_id {id_t}"), format!("check_{}_id {id_t}", g.level)];
        for scope in &g.scopes {
            let param = format!("check_{}_id", scope.level);
            let empty = if id_t == "text" { format!("{param} = ''") } else { format!("{param} IS NULL") };
            explicit.push(format!("({c} IS NULL OR {empty} OR {c} = {param})", c = scope.column));
            args.push(format!("{param} {id_t}"));
            let sig = args.join(", ");
            out.push(GenFn {
                name: format!("{base}_in_{}", scope.level),
                strict: binds_every(&sig, &[&explicit]),
                sig,
                body: grant_edge_exists(g.table(), &explicit),
                ..Default::default()
            });
        }
        out
    }

    fn def_emit_grant_reach(&self, out: &mut Vec<GenFn>) {
        let mut gseen = HashSet::new();
        let id_t = self.s.id_type();
        for g in &self.s.grants {
            if g.claim_key.is_some() {
                continue;
            }
            let name = format!("{}_reach", g.definer_base());
            if !gseen.insert(name.clone()) {
                continue;
            }
            let mut conj = vec![format!("{} = user_id", g.grantee_col()), format!("{} = check_{}_id", g.level_col(), g.level)];
            if let Some(a) = &g.active_col {
                conj.push(format!("{a} IS NULL"));
            }
            if let Some(e) = &g.expires_col {
                conj.push(format!("{e} > now()"));
            }
            let mut scoped = conj.clone();
            scoped.extend(self.grant_session_scope_conjuncts(g));
            let sig = format!("user_id {id_t}, check_{}_id {id_t}", g.level);
            out.push(GenFn {
                name: name.clone(),
                strict: binds_every(&sig, &[&scoped]),
                sig,
                body: grant_edge_exists(g.table(), &scoped),
                ..Default::default()
            });
            let mut set_conj = vec![format!("{} = user_id", g.grantee_col())];
            set_conj.extend(scoped[2..].iter().cloned());
            let set_sig = format!("user_id {id_t}");
            out.push(GenFn {
                name: format!("{name}_set"),
                strict: binds_every(&set_sig, &[&set_conj]),
                sig: set_sig,
                returns: format!("SETOF {id_t}"),
                body: format!("{} FROM {} WHERE {}", g.level_col(), g.table(), set_conj.join(" AND ")),
                ..Default::default()
            });
            out.extend(self.grant_scope_definers(g, &conj));
        }
    }

    fn def_emit_role_definers(
        &self,
        out: &mut Vec<GenFn>,
        seen: &mut Seen,
        rs: Option<&RoleStore>,
        preset_levels: &HashMap<String, Vec<String>>,
    ) -> R<()> {
        for obj in &self.s.objects {
            let rels = rels_of(obj);
            for pm in &obj.perms {
                for t in pm.tree.leaves() {
                    if let Some(d) = self.role_definer_for_term(obj, t, &rels, rs, preset_levels)?
                        && seen.insert(d.name.clone())
                    {
                        out.push(d);
                    }
                }
            }
        }
        Ok(())
    }

    fn def_emit_platform_roles(
        &self,
        out: &mut Vec<GenFn>,
        seen: &mut Seen,
        rs: Option<&RoleStore>,
        preset_levels: &HashMap<String, Vec<String>>,
    ) {
        for sub in &self.s.subjects {
            let Some(rs) = rs.filter(|_| self.s.is_platform_role_subject(sub)) else { continue };
            let name = platform_role_fn(sub.anchor());
            if !seen.insert(name.clone()) {
                continue;
            }
            out.push(self.role_definer(&name, rs, sub.anchor(), preset_levels.get(sub.anchor()), ""));
        }
    }

    fn def_emit_scoped_memberin(
        &self,
        out: &mut Vec<GenFn>,
        seen: &mut Seen,
        rs: Option<&RoleStore>,
        preset_levels: &HashMap<String, Vec<String>>,
    ) {
        for obj in &self.s.objects {
            for r in &obj.relations {
                let Repr::MemberIn(mi) = &r.repr else { continue };
                let Some(rs) = rs else { continue };
                let name = format!("{}_memberin_{}", self.s.admin_name(), mi.level);
                if seen.insert(name.clone()) {
                    let s_col = self.scope_col_for_level(rs, &mi.level);
                    let mut conds = vec![format!("{} = p_principal", or(&rs.subject_col)), format!("{} = p_{}", s_col, mi.level)];
                    conds.extend(kind_cond(rs, ""));
                    conds.extend(revoked_cond(rs, ""));
                    let body = format!("EXISTS (SELECT 1 FROM {} WHERE {})", or(&rs.assignments), conds.join(" AND "));
                    let id_t = self.s.id_type();
                    out.push(GenFn { name, sig: format!("p_principal {id_t}, p_{} {id_t}", mi.level), body, ..Default::default() });
                }
                if mi.reached_by && !mi.reach_member {
                    self.def_emit_reach_chain(out, seen, rs, preset_levels, &mi.level);
                }
            }
        }
    }

    fn def_emit_holds_perm(&self, out: &mut Vec<GenFn>, seen: &mut Seen) -> R<()> {
        for obj in &self.s.objects {
            for pm in &obj.perms {
                for t in pm.tree.leaves() {
                    if t.builtin() != "holds" {
                        continue;
                    }
                    self.def_add_holds_perm(out, seen, obj, pm, t)?;
                }
            }
        }
        Ok(())
    }

    fn def_add_holds_perm(&self, out: &mut Vec<GenFn>, seen: &mut Seen, obj: &Object, pm: &Perm, t: &Term) -> R<()> {
        let perm = t.holds_perm();
        let rs = self.s.holds_role_store(perm).map_err(|e| {
            format!("object {} permission {} uses @holds({}): {e}", quote(&obj.name), quote(&pm.verb), quote(perm))
        })?;
        if rs.perms_col.is_none() {
            return Err(format!(
                "object {} permission {} uses @holds({}) but rolestore {} declares no `permissions` column",
                quote(&obj.name),
                quote(&pm.verb),
                quote(perm),
                quote(&rs.name)
            ));
        }
        let name = self.s.holds_perm_fn(rs);
        if !seen.insert(name.clone()) {
            return Ok(());
        }
        let mut implied_by = String::new();
        if let Ok(vocab) = self.s.rolestore_vocab(rs)
            && !vocab.implications.is_empty()
        {
            let f = self.perm_implied_by_definer(rs, vocab)?;
            implied_by = format!("{}.{}", f.schema(), f.name);
            out.push(f);
        }
        out.push(self.holds_perm_definer(&name, rs, &implied_by));
        Ok(())
    }

    fn holds_perm_definer(&self, name: &str, rs: &RoleStore, implied_by: &str) -> GenFn {
        let chain = topology::chain(self.s).unwrap_or_default();
        let plane_depth = self.s.rolestore_plane_depth(rs);
        let id_t = self.s.id_type();
        let mut args = vec![format!("user_id {id_t}")];
        let mut scope = Vec::new();
        let mut i = 0;
        for l in chain {
            if l.is_virtual {
                continue;
            }
            if i >= rs.scope_cols.len() {
                break;
            }
            let col = &rs.scope_cols[i];
            if i < plane_depth {
                let arg = format!("check_{}_id", l.name);
                args.push(format!("{arg} {id_t}"));
                scope.push(format!("(ra.{col} IS NULL OR ra.{col} = {arg})"));
            } else {
                scope.push(format!("ra.{col} IS NULL"));
            }
            i += 1;
        }
        args.push("p_perm text".into());
        let mut conds = kind_cond(rs, "ra.");
        conds.push(format!("ra.{} = user_id", or(&rs.subject_col)));
        conds.extend(scope);
        conds.extend(revoked_cond(rs, "ra."));
        conds.push(hold_perm_cond(or(&rs.perms_col), implied_by));
        let body = format!(
            "EXISTS (SELECT 1 FROM {} ra JOIN {} r ON r.{} = ra.{} WHERE {})",
            or(&rs.assignments),
            or(&rs.roles_table),
            or(&rs.roles_id),
            or(&rs.role_col),
            conds.join(" AND ")
        );
        GenFn { name: name.to_string(), sig: args.join(", "), body, ..Default::default() }
    }

    fn perm_implied_by_definer(&self, rs: &RoleStore, vocab: &Vocabulary) -> R<GenFn> {
        let rv = to_runtime(vocab);
        let mut impliers: HashMap<String, Vec<String>> = HashMap::new();
        for p in &vocab.permissions {
            for target in rv.implied_permissions(p).map_err(|e| e.to_string())? {
                impliers.entry(target).or_default().push(p.clone());
            }
        }
        let mut rows = Vec::new();
        for p in &vocab.permissions {
            let mut set = impliers.get(p).cloned().unwrap_or_default();
            set.sort();
            let lits: Vec<String> = set.iter().map(|q| format!("'{q}'")).collect();
            rows.push(format!("('{}', ARRAY[{}]::text[])", p, lits.join(", ")));
        }
        Ok(GenFn {
            name: self.s.perm_implied_by_fn(rs),
            sig: "p_perm text".into(),
            returns: "text[]".into(),
            body: format!(
                "COALESCE((SELECT m.impliers FROM (VALUES {}) AS m(perm, impliers) WHERE m.perm = p_perm), ARRAY[p_perm]::text[])",
                rows.join(", ")
            ),
            ..Default::default()
        })
    }

    fn def_emit_reach_chain(
        &self,
        out: &mut Vec<GenFn>,
        seen: &mut Seen,
        rs: &RoleStore,
        preset_levels: &HashMap<String, Vec<String>>,
        level: &str,
    ) {
        let Ok(path) = topology::ancestor_path(self.s, level) else { return };
        for lvl in path {
            if lvl.is_virtual {
                continue;
            }
            let f = format!("is_{}_{}", lvl.name, self.s.admin_name());
            if !seen.insert(f.clone()) {
                continue;
            }
            out.push(self.role_definer(&f, rs, &lvl.name, preset_levels.get(&lvl.name), &self.operator_reach(&lvl.name)));
        }
    }

    fn def_emit_kernel(&self, out: &mut Vec<GenFn>, seen: &mut Seen) -> R<()> {
        for obj in &self.s.objects {
            for pm in &obj.perms {
                if !pm.has_layer("kernel") {
                    continue;
                }
                let d = self.kernel_definer(obj)?;
                if seen.insert(d.name.clone()) {
                    out.push(d);
                }
            }
        }
        Ok(())
    }

    fn def_emit_grant_relations(&self, out: &mut Vec<GenFn>, seen: &mut Seen) {
        for obj in &self.s.objects {
            let Some((r, vg)) = grant_relation(obj) else { continue };
            for i in 0..r.types.len() {
                let (name, kind, param, _) = self.s.grant_rel_binding(obj, vg, r, i);
                if !seen.insert(name.clone()) {
                    continue;
                }
                let mut conjuncts = vec![format!("{} = p_{}_id", vg.record_col, obj.name)];
                if let Some(d) = &vg.discrim_col {
                    conjuncts.push(format!("{d} = '{}'", or(&vg.discrim_val)));
                }
                conjuncts.push(format!("{} = '{}'", vg.kind_col, kind));
                conjuncts.push(format!("{} = p_{}_id", vg.principal_col, param));
                conjuncts.push(format!("{} = p_access", vg.access_col));
                let mut body = grant_edge_exists(&vg.table, &conjuncts);
                let mut disjuncts: Vec<Vec<String>> = vec![conjuncts];
                if vg.group_closure.is_some() {
                    body.push_str(&format!(" OR {}", grant_group_exists(vg, obj, &param)));
                    disjuncts.push(grant_group_conds(vg, obj, &param));
                }
                let sig = format!("p_{}_id text, p_{}_id text, p_access text", param, obj.name);
                let refs: Vec<&[String]> = disjuncts.iter().map(Vec::as_slice).collect();
                out.push(GenFn { name, strict: binds_every(&sig, &refs), sig, body, ..Default::default() });
            }
        }
    }

    fn def_emit_accessors(&self, out: &mut Vec<GenFn>, seen: &mut Seen) -> R<()> {
        for obj in &self.s.objects {
            if grant_relation(obj).is_none() {
                continue;
            }
            let cond = self.s.conditional_accessors(obj);
            let name = if cond.is_empty() {
                format!("{}_accessors", obj.table)
            } else {
                format!("{}_accessors_conditional", obj.table)
            };
            if seen.contains(&name) {
                continue;
            }
            let (ok, reason) = self.accessor_coverage(obj);
            if !ok {
                return Err(format!(
                    "object {}: cannot soundly enumerate accessors (auth.{} would under-report) — {}",
                    quote(&obj.name),
                    name,
                    reason
                ));
            }
            seen.insert(name);
            out.extend(self.accessor_definers(obj, &cond));
        }
        Ok(())
    }

    fn accessor_coverage(&self, obj: &Object) -> (bool, String) {
        self.accessor_coverage_seen(obj, &mut HashSet::new())
    }

    fn accessor_coverage_seen(&self, obj: &Object, seen: &mut HashSet<String>) -> (bool, String) {
        if !seen.insert(obj.name.clone()) {
            return (true, String::new());
        }
        let rels = rels_of(obj);
        let Some(sel) = object_select_perm(obj) else { return (true, String::new()) };
        if !accessor_tree_op(&sel.tree).is_empty() {
            if let Err(e) = self.accessor_tree_sql(obj, &sel.tree, &rels) {
                return (false, e);
            }
            return (true, String::new());
        }
        for t in sel.tree.leaves() {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()) else { continue };
            if let Repr::Object(vo) = &r.repr {
                let (cov, reason) = self.via_object_covered(vo, seen);
                if !cov {
                    return (false, format!(
                        "relation {} borrows {}->{}, not soundly enumerable ({})",
                        quote(t.ident()),
                        vo.object,
                        vo.verb,
                        reason
                    ));
                }
                continue;
            }
            if !accessor_repr_covered(&r.repr) {
                return (false, format!(
                    "relation {} ({}) has no accessor branch yet (reverse builder is WS1)",
                    quote(t.ident()),
                    go_type_name(&r.repr)
                ));
            }
        }
        (true, String::new())
    }

    fn via_object_covered(&self, vo: &ViaObject, seen: &mut HashSet<String>) -> (bool, String) {
        let Some(other) = self.s.object_by_name(&vo.object) else {
            return (false, format!("borrowed object {} not found", quote(&vo.object)));
        };
        let read_verb = object_select_perm(other).map(|p| p.verb.as_str()).unwrap_or("");
        if read_verb.is_empty() || vo.verb != read_verb {
            return (false, format!(
                "only a read borrow is reversible ({} is not {}'s select verb)",
                quote(&vo.verb),
                quote(&vo.object)
            ));
        }
        if grant_relation(other).is_none() {
            return (false, format!("borrowed object {} has no accessor enumerator", quote(&vo.object)));
        }
        let cond = self.s.conditional_accessors(other);
        if !cond.is_empty() {
            return (false, format!(
                "borrowed object {} admits readers its enumeration cannot name ({}), so it enumerates conditionally and has no plain accessor to borrow",
                quote(&vo.object),
                admission_names(&cond)
            ));
        }
        self.accessor_coverage_seen(other, seen)
    }

    fn def_emit_structural_accessors(&self, out: &mut Vec<GenFn>, seen: &mut Seen) -> R<()> {
        for obj in &self.s.objects {
            if !obj.is_level_entity() {
                continue;
            }
            let name = format!("{}_accessors", obj.table);
            if seen.contains(&name) {
                continue;
            }
            if let Some(d) = self.structural_accessor_definer(obj)? {
                let (cov, reason) = structural_accessor_coverage(obj);
                if !cov {
                    return Err(format!(
                        "object {}: cannot soundly enumerate structural accessors (auth.{} would under-report) — {}",
                        quote(&obj.name),
                        name,
                        reason
                    ));
                }
                seen.insert(name);
                out.push(d);
            }
        }
        Ok(())
    }

    fn def_emit_closure(&self, out: &mut Vec<GenFn>, seen: &mut Seen) {
        for obj in &self.s.objects {
            for r in &obj.relations {
                let Repr::Closure(c) = &r.repr else { continue };
                let name = format!("{}_reachable", c.closure);
                if !seen.insert(name.clone()) {
                    continue;
                }
                let sig = "p_ancestor text, p_descendant text".to_string();
                let conj = vec![format!("{} = p_ancestor", c.ancestor_col), format!("{} = p_descendant", c.descendant_col)];
                out.push(GenFn { name, strict: binds_every(&sig, &[&conj]), sig, body: grant_edge_exists(&c.closure, &conj), ..Default::default() });
            }
        }
    }

    fn def_emit_group(&self, out: &mut Vec<GenFn>, seen: &mut Seen) {
        for obj in &self.s.objects {
            for r in &obj.relations {
                let Repr::Group(g) = &r.repr else { continue };
                let name = format!("{}_member", g.closure);
                if !seen.insert(name.clone()) {
                    continue;
                }
                out.push(GenFn {
                    name,
                    sig: "p_group text, p_member text".into(),
                    body: format!("EXISTS (SELECT 1 FROM {} WHERE {} = p_group AND {} = p_member)", g.closure, g.group_col, g.member_col),
                    ..Default::default()
                });
            }
        }
    }

    fn def_emit_materialized_flat_members(&self, out: &mut Vec<GenFn>, seen: &mut Seen) {
        for f in self.emit_materialized_flats() {
            let name = format!("{}_member", f.flat);
            if seen.insert(name) {
                out.push(f.member_definer());
            }
            let rname = format!("{}_resources", f.flat);
            if f.has_reverse() && seen.insert(rname) {
                out.push(f.resources_definer());
            }
        }
    }

    fn def_emit_cross_object(&self, out: &mut Vec<GenFn>, seen: &mut Seen, virt: &Virtual) -> R<()> {
        for obj in &self.s.objects {
            for r in &obj.relations {
                let Repr::Object(vo) = &r.repr else { continue };
                let name = vo.function_name();
                if !seen.insert(name.clone()) {
                    continue;
                }
                let Some(other) = self.s.object_by_name(&vo.object) else {
                    return Err(format!("relation {} references unknown object {}", quote(&r.name), quote(&vo.object)));
                };
                let pred = self.object_verb_predicate_for(other, &vo.verb, vo.op.as_deref().unwrap_or(""), virt)?;
                let sig = format!("p_{}_id text", vo.object);
                let key = format!("{}.{} = p_{}_id", other.table, other.pk(), vo.object);
                let strict = binds_every(&sig, &[std::slice::from_ref(&key)]);
                out.push(GenFn {
                    name,
                    sig,
                    body: grant_edge_exists(&other.table, &[key, format!("({pred})")]),
                    strict,
                    ..Default::default()
                });
            }
        }
        Ok(())
    }

    fn def_emit_composition(&self, out: &mut Vec<GenFn>, seen: &mut Seen, virt: &Virtual) -> R<()> {
        let plain = Sql { s: self.s, definer_body: false };
        let branches = [("read", "select"), ("write", "update"), ("delete", "delete")];
        for obj in &self.s.objects {
            let base = without_composition(obj);
            for r in &obj.relations {
                let Repr::Composition(vc) = &r.repr else { continue };
                let name = format!("{}_composition_{}", obj.name, r.name);
                if !seen.insert(name.clone()) {
                    continue;
                }
                let kind_filter = match &vc.kind_col {
                    Some(k) => format!(" AND e.{k} = '{}'", or(&vc.kind_val)),
                    None => String::new(),
                };
                let mut arms = Vec::new();
                for (access, op) in branches {
                    let pred = plain.op_predicate(&base, op, virt)?;
                    if pred.is_empty() {
                        continue;
                    }
                    arms.push(DefinerArm {
                        value: access.into(),
                        body: format!(
                            "EXISTS (SELECT 1 FROM {} e WHERE e.{} = p_{}_id{} AND EXISTS (SELECT 1 FROM {} WHERE {}.{} = e.{} AND ({})))",
                            vc.table, vc.child_col, obj.name, kind_filter, obj.table, obj.table, obj.pk(), vc.parent_col, pred
                        ),
                    });
                }
                if arms.is_empty() {
                    return Err(format!(
                        "object {} composition relation {}: object has no cascadable @rls verb predicate",
                        quote(&obj.name),
                        quote(&r.name)
                    ));
                }
                out.push(GenFn {
                    name,
                    sig: format!("p_{}_id text, p_access text", obj.name),
                    arm_param: "p_access".into(),
                    arms,
                    strict: true,
                    ..Default::default()
                });
            }
        }
        Ok(())
    }

    fn op_predicate(&self, obj: &Object, op: &str, virt: &Virtual) -> R<String> {
        for pm in &obj.perms {
            if pm.has_layer("rls") && pm.maps() == op {
                let cust = self.s.owner_subject(leaf(obj));
                return self.perm_predicate(obj, pm, cust, virt);
            }
        }
        Ok(String::new())
    }

    fn def_emit_store_manage(&self, out: &mut Vec<GenFn>, seen: &mut Seen, virt: &Virtual) -> R<()> {
        let stores: BTreeSet<&str> =
            self.s.objects.iter().filter(|o| object_uses_store_manage(o)).map(|o| o.table.as_str()).collect();
        for store in stores {
            let whens = self.def_store_manage_whens(out, seen, virt, store)?;
            let name = store_manage_name(store);
            if !seen.insert(name.clone()) {
                continue;
            }
            out.push(GenFn {
                name,
                sig: format!("p_type text, p_id {}", self.s.id_type()),
                body: format!("(CASE p_type {} ELSE false END)", whens.join(" ")),
                ..Default::default()
            });
        }
        Ok(())
    }

    fn def_store_manage_whens(&self, out: &mut Vec<GenFn>, seen: &mut Seen, virt: &Virtual, store: &str) -> R<Vec<String>> {
        let mut whens = Vec::new();
        for o in self.s.store_descriptors(store) {
            let can_edit = format!("{}_can_edit", o.name);
            if seen.insert(can_edit.clone()) {
                let pred = self
                    .object_verb_predicate(o, "edit", virt)
                    .map_err(|e| format!("@store_manage dispatch for {}: {e}", quote(store)))?;
                let sig = format!("p_id {}", self.s.id_type());
                let key = format!("{}.{} = p_id", o.table, o.pk());
                let strict = binds_every(&sig, &[std::slice::from_ref(&key)]);
                out.push(GenFn {
                    name: can_edit.clone(),
                    sig,
                    body: grant_edge_exists(&o.table, &[key, format!("({pred})")]),
                    strict,
                    ..Default::default()
                });
            }
            let dv = object_grant_edge(o).and_then(|e| e.discrim_val.clone()).unwrap_or_default();
            whens.push(format!("WHEN '{}' THEN {}.{}(p_id)", dv, self.s.definer_schema(), can_edit));
        }
        Ok(whens)
    }

    fn role_definer_for_term(
        &self,
        obj: &Object,
        t: &Term,
        rels: &Rels,
        rs: Option<&RoleStore>,
        preset_levels: &HashMap<String, Vec<String>>,
    ) -> R<Option<GenFn>> {
        let Some(rs) = rs else { return Ok(None) };
        if !t.walk_verb().is_empty() {
            let Some(parent) = rels.get(t.ident()) else {
                return Err(format!("walk references unknown relation {}", quote(t.ident())));
            };
            let lvl = &parent.types[0];
            let f = format!("is_{}_{}", lvl, self.s.admin_name());
            return Ok(Some(self.role_definer(&f, rs, lvl, preset_levels.get(lvl), &self.operator_reach(lvl))));
        }
        let rel_name = if t.builtin() == "session" && !t.session_rel().is_empty() { t.session_rel() } else { t.ident() };
        let Some(r) = rels.get(rel_name) else { return Ok(None) };
        if !matches!(r.repr, Repr::Role) {
            return Ok(None);
        }
        if let Some(first) = r.types.first()
            && let Some(st) = self.s.subject_by_name(first)
            && self.s.is_platform_role_subject(st)
        {
            return Ok(None);
        }
        let obj_level = leaf(obj);
        Ok(Some(self.role_definer(
            &format!("{}_has_{}_role", self.s.admin_name(), obj.name),
            rs,
            obj_level,
            preset_levels.get(obj_level),
            "",
        )))
    }

    fn role_definer(&self, name: &str, rs: &RoleStore, level: &str, keys: Option<&Vec<String>>, recurse: &str) -> GenFn {
        let chain = topology::chain(self.s).unwrap_or_default();
        let non_virtual: Vec<&str> = chain.iter().filter(|l| !l.is_virtual).map(|l| l.name.as_str()).collect();
        let on_path: HashSet<String> = topology::ancestor_path(self.s, level)
            .map(|p| p.into_iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default();
        let id_t = self.s.id_type();
        let mut args = vec![format!("user_id {id_t}")];
        let mut scope = Vec::new();
        for (i, lvl) in non_virtual.iter().enumerate() {
            if i >= rs.scope_cols.len() {
                break;
            }
            let col = &rs.scope_cols[i];
            if on_path.contains(*lvl) {
                let arg = format!("check_{lvl}_id");
                args.push(format!("{arg} {id_t}"));
                scope.push(format!("ra.{col} = {arg}"));
            } else {
                scope.push(format!("ra.{col} IS NULL"));
            }
        }
        let mut keys: Vec<String> = keys.cloned().unwrap_or_default();
        keys.sort();
        let quoted: Vec<String> = keys.iter().map(|k| format!("'{k}'")).collect();
        let mut conds = kind_cond(rs, "ra.");
        conds.push(format!("ra.{} = user_id", or(&rs.subject_col)));
        conds.extend(scope);
        conds.extend(revoked_cond(rs, "ra."));
        conds.push(format!("r.{} IN ({})", or(&rs.key_col), quoted.join(", ")));
        let exists = format!(
            "EXISTS (SELECT 1 FROM {} ra JOIN {} r ON r.{} = ra.{} WHERE {})",
            or(&rs.assignments),
            or(&rs.roles_table),
            or(&rs.roles_id),
            or(&rs.role_col),
            conds.join(" AND ")
        );
        let body = if recurse.is_empty() { exists } else { format!("{}.{} OR {}", self.s.definer_schema(), recurse, exists) };
        GenFn { name: name.to_string(), sig: args.join(", "), body, ..Default::default() }
    }

    fn operator_reach(&self, level: &str) -> String {
        for sub in &self.s.subjects {
            if let Some(m) = &sub.membership {
                return format!("{}(user_id)", m.flag_col);
            }
            if sub.reach() == "grant"
                && let Some(g) = self.s.grant_by_name(sub.reach_grant())
                && g.level == level
            {
                return format!("{}_reach(user_id, check_{}_id)", g.definer_base(), g.level);
            }
        }
        String::new()
    }

    fn pure_accessor_definers(&self, obj: &Object) -> Vec<GenFn> {
        let rels = rels_of(obj);
        let sel = object_select_perm(obj);
        let mut branches: Vec<String> = Vec::new();
        let mut admin_excl = String::new();
        let mut composed_tree = false;
        if let Some(sel) = sel
            && !accessor_tree_op(&sel.tree).is_empty()
            && let Ok(composed) = self.accessor_tree_sql(obj, &sel.tree, &rels)
        {
            branches.push(composed);
            composed_tree = true;
        }
        if let Some(sel) = sel {
            admin_excl = def_admin_excl_cond(sel, &rels);
            if !composed_tree {
                branches.extend(self.def_owner_accessor_branches(obj, sel, &rels));
            }
        }
        if !composed_tree && let Some((_, vg)) = grant_relation(obj) {
            branches.push(grant_accessor_branch(vg));
        }
        if let Some(rb) = self.role_accessor_branch(obj, &admin_excl) {
            branches.push(rb);
        }
        if !composed_tree {
            branches.extend(self.def_group_accessor_branches(obj, sel, &rels));
            branches.extend(self.def_closure_accessor_branches(obj, sel, &rels));
            branches.extend(self.def_object_accessor_branches(obj, sel, &rels));
        }
        let comp = self.def_composition_accessor_branches(obj, sel, &rels);
        let id_t = self.s.id_type();
        if comp.is_empty() {
            return vec![accessor_gen_fn(&obj.table, id_t, &branches)];
        }
        let direct = accessor_gen_fn_named(format!("{}_direct_accessors", obj.table), id_t, &branches);
        let mut full_branches = vec![format!(
            "SELECT d.source, d.principal_kind, d.principal_id, d.access FROM {}.{}_direct_accessors(p_id) d",
            self.s.definer_schema(),
            obj.table
        )];
        full_branches.extend(comp);
        vec![direct, accessor_gen_fn(&obj.table, id_t, &full_branches)]
    }

    fn accessor_definers(&self, obj: &Object, cond: &[ConditionalAdmission]) -> Vec<GenFn> {
        let mut fns = self.pure_accessor_definers(obj);
        if cond.is_empty() || fns.is_empty() {
            return fns;
        }
        let last = fns.len() - 1;
        fns[last] = self.conditional_accessor_gen_fn(obj, &fns[last], cond);
        fns
    }

    fn conditional_accessor_gen_fn(&self, obj: &Object, base: &GenFn, adms: &[ConditionalAdmission]) -> GenFn {
        let id_t = self.s.id_type();
        let mut branches = vec![format!(
            "SELECT b.source, b.principal_kind, b.principal_id, b.access, NULL::text AS via_claim_key, NULL::text AS via_claim_value\n    FROM (\n{}\n    ) b(source, principal_kind, principal_id, access)",
            base.body
        )];
        for a in adms {
            let mut where_ = format!("{} = p_id", obj.pk());
            if !a.row_cond.is_empty() {
                where_.push_str(&format!(" AND {}", a.row_cond));
            }
            let mut claim_val = sql_text_or_null(&a.claim_val);
            if !a.claim_val_col.is_empty() {
                claim_val = format!("{}::text", a.claim_val_col);
            }
            branches.push(format!(
                "SELECT '{}'::text, {}, NULL::{}, 'read'::text, {}, {}\n    FROM {} WHERE {}",
                a.source,
                sql_text_or_null(&a.principal_kind),
                id_t,
                sql_text_or_null(&a.claim_key),
                claim_val,
                obj.table,
                where_
            ));
        }
        GenFn {
            name: format!("{}_accessors_conditional", obj.table),
            sig: format!("p_id {id_t}"),
            returns: format!(
                "TABLE(source text, principal_kind text, principal_id {id_t}, access text, via_claim_key text, via_claim_value text)"
            ),
            raw_body: true,
            body: format!("  {}", branches.join("\n  UNION ALL\n  ")),
            ..Default::default()
        }
    }

    fn sel_leaves(sel: Option<&Perm>) -> Vec<&Term> {
        sel.map(|s| s.tree.leaves()).unwrap_or_default()
    }

    fn def_composition_accessor_branches(&self, obj: &Object, sel: Option<&Perm>, rels: &Rels) -> Vec<String> {
        let mut out = Vec::new();
        for t in Self::sel_leaves(sel) {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()) else { continue };
            if let Repr::Composition(vc) = &r.repr {
                out.push(composition_accessor_branch(&obj.table, self.s.definer_schema(), vc));
            }
        }
        out
    }

    fn def_group_accessor_branches(&self, obj: &Object, sel: Option<&Perm>, rels: &Rels) -> Vec<String> {
        let mut out = Vec::new();
        for t in Self::sel_leaves(sel) {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()) else { continue };
            if let Repr::Group(g) = &r.repr {
                let kind = r.types.first().map(String::as_str).unwrap_or("");
                out.push(group_accessor_branch(&obj.table, obj.pk(), kind, g, &self.group_flat_name(obj, r, g)));
            }
        }
        out
    }

    fn def_closure_accessor_branches(&self, obj: &Object, sel: Option<&Perm>, rels: &Rels) -> Vec<String> {
        let mut out = Vec::new();
        for t in Self::sel_leaves(sel) {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()) else { continue };
            if let Repr::Closure(c) = &r.repr {
                let kind = r.types.first().map(String::as_str).unwrap_or("");
                out.push(closure_accessor_branch(&obj.table, obj.pk(), kind, c));
            }
        }
        out
    }

    fn def_object_accessor_branches(&self, obj: &Object, sel: Option<&Perm>, rels: &Rels) -> Vec<String> {
        let mut out = Vec::new();
        for t in Self::sel_leaves(sel) {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()) else { continue };
            if let Repr::Object(vo) = &r.repr
                && let Some(other) = self.s.object_by_name(&vo.object)
            {
                out.push(object_accessor_branch(&obj.table, obj.pk(), vo, &other.table, self.s.definer_schema()));
            }
        }
        out
    }

    fn def_owner_accessor_branches(&self, obj: &Object, sel: &Perm, rels: &Rels) -> Vec<String> {
        let mut out = Vec::new();
        let mut first = true;
        for t in sel.tree.leaves() {
            if t.ident().is_empty() {
                continue;
            }
            let Some(r) = rels.get(t.ident()).copied() else { continue };
            let Repr::Column(vc) = &r.repr else { continue };
            if self.s.transient_column(Some(r)).is_some() {
                continue;
            }
            let kind = r.types.first().map(String::as_str).unwrap_or("");
            out.push(owner_accessor_branch(&obj.table, obj.pk(), kind, vc, first));
            first = false;
        }
        out
    }

    fn accessor_branch_for_term(&self, obj: &Object, t: &Term, rels: &Rels) -> R<String> {
        if t.builtin() == "claim" {
            return Err(format!(
                "term {} is a condition on the request, not a subject, so it cannot be a branch of an accessor union; a claim can only narrow a conjunction or widen a disjunct (which makes the object enumerate conditionally) — it cannot be negated or nested where neither applies",
                quote(&t.display())
            ));
        }
        if t.ident().is_empty() {
            return Err(format!(
                "term {} has no accessor branch (only owner/grant/group/closure/object relation leaves enumerate)",
                quote(&t.display())
            ));
        }
        let name = grant_selector(t.ident(), rels).map(|(rn, _)| rn).unwrap_or(t.ident());
        let Some(r) = rels.get(name).copied() else {
            return Err(format!("term {} names no relation the accessor enumerator can reverse", quote(t.ident())));
        };
        let kind = r.types.first().map(String::as_str).unwrap_or("");
        match &r.repr {
            Repr::Column(vc) => Ok(owner_accessor_branch(&obj.table, obj.pk(), kind, vc, false)),
            Repr::Grant(vg) => Ok(grant_accessor_branch(vg)),
            Repr::Group(g) => Ok(group_accessor_branch(&obj.table, obj.pk(), kind, g, &self.group_flat_name(obj, r, g))),
            Repr::Closure(c) => {
                if let Some(claim) = &c.claim {
                    return Err(format!(
                        "relation {} is confined by the caller's {} claim, which names no principal to enumerate",
                        quote(name),
                        quote(claim)
                    ));
                }
                Ok(closure_accessor_branch(&obj.table, obj.pk(), kind, c))
            }
            Repr::Object(vo) => {
                let (ok, reason) = self.via_object_covered(vo, &mut HashSet::new());
                if !ok {
                    return Err(format!(
                        "relation {} borrows {}->{}, not soundly enumerable ({})",
                        quote(name),
                        vo.object,
                        vo.verb,
                        reason
                    ));
                }
                let Some(other) = self.s.object_by_name(&vo.object) else {
                    return Err(format!("relation {} borrows unknown object {}", quote(name), quote(&vo.object)));
                };
                Ok(object_accessor_branch(&obj.table, obj.pk(), vo, &other.table, self.s.definer_schema()))
            }
            other => Err(format!(
                "relation {} ({}) has no accessor branch (only owner/grant/group/closure/object leaves compose)",
                quote(name),
                go_type_name(other)
            )),
        }
    }

    fn accessor_tree_sql(&self, obj: &Object, n: &PermNode, rels: &Rels) -> R<String> {
        if n.is_nil() {
            return Err("empty permission tree".into());
        }
        match n {
            PermNode::Leaf(t) => self.accessor_branch_for_term(obj, t, rels),
            PermNode::Or(kids) => {
                let mut parts = Vec::new();
                for k in kids {
                    if self.s.is_conditional_leaf(k, rels) || self.s.conditional_conjunction(k, rels).is_some() || is_composition_leaf(k, rels) {
                        continue;
                    }
                    parts.push(format!("({})", self.accessor_tree_sql(obj, k, rels)?));
                }
                if parts.is_empty() {
                    return Err("empty union in the SELECT permission tree".into());
                }
                Ok(parts.join("\n  UNION ALL\n  "))
            }
            PermNode::And(_) => self.accessor_and_sql(obj, n, rels),
            PermNode::Not(_) => Err(format!("permission node {} is not enumerable", quote("not"))),
        }
    }

    fn accessor_and_sql(&self, obj: &Object, n: &PermNode, rels: &Rels) -> R<String> {
        let PermNode::And(kids) = n else { unreachable!() };
        let mut positives: Vec<&PermNode> = Vec::new();
        let mut negatives: Vec<&PermNode> = Vec::new();
        let mut dropped: Vec<String> = Vec::new();
        for k in kids {
            if let PermNode::Not(inner) = k {
                if is_claim_leaf(inner) || is_row_leaf(inner) {
                    dropped.push(format!("not {}", inner.term().unwrap().display()));
                    continue;
                }
                negatives.push(inner);
            } else if narrowing_accessor_leaf(k) {
                dropped.push(k.term().unwrap().display());
            } else {
                positives.push(k);
            }
        }
        if positives.is_empty() {
            if !dropped.is_empty() {
                return Err(format!(
                    "a conjunction of only narrowing terms ({}) leaves no relational term to enumerate",
                    dropped.join(", ")
                ));
            }
            return Err("a conjunction needs a positive relational term to enumerate".into());
        }
        let base = self.accessor_tree_sql(obj, positives[0], rels)?;
        let mut filters = Vec::new();
        for p in &positives[1..] {
            let sub = self.accessor_tree_sql(obj, p, rels)?;
            filters.push(format!(
                "(a.principal_kind, a.principal_id) IN (SELECT b.principal_kind, b.principal_id FROM ({sub}) b(source, principal_kind, principal_id, access))"
            ));
        }
        for ng in &negatives {
            let sub = self.accessor_tree_sql(obj, ng, rels)?;
            filters.push(format!(
                "(a.principal_kind, a.principal_id) NOT IN (SELECT b.principal_kind, b.principal_id FROM ({sub}) b(source, principal_kind, principal_id, access))"
            ));
        }
        if filters.is_empty() {
            return Ok(base);
        }
        Ok(format!(
            "SELECT a.* FROM ({}) a(source, principal_kind, principal_id, access)\n    WHERE {}",
            base,
            filters.join("\n      AND ")
        ))
    }

    fn role_accessor_branch(&self, obj: &Object, admin_excl: &str) -> Option<String> {
        let rs = self.s.default_role_store()?;
        if !self.s.select_uses_app_scope(obj) {
            return None;
        }
        let n = obj.scoped.len().min(rs.scope_cols.len());
        let mut scope_conds = Vec::new();
        for (i, lvl) in obj.scoped.iter().enumerate() {
            if i >= rs.scope_cols.len() {
                break;
            }
            let rs_col = &rs.scope_cols[i];
            let row_col = self.s.scope_col(obj, lvl);
            if i + 1 == n {
                scope_conds.push(format!("(ra.{rs_col} IS NULL OR ra.{rs_col} = r.{row_col})"));
            } else {
                scope_conds.push(format!("ra.{rs_col} = r.{row_col}"));
            }
        }
        let mut where_ = vec![format!("r.{} = p_id", obj.pk())];
        if !admin_excl.is_empty() {
            where_.push(admin_excl.to_string());
        }
        let mut on = kind_cond(rs, "ra.");
        on.extend(revoked_cond(rs, "ra."));
        on.extend(scope_conds);
        Some(format!(
            "SELECT 'role'::text, '{}'::text, ra.{}, 'read'::text\n    FROM {} r\n    JOIN {} ra ON {}\n    WHERE {}",
            or(&rs.kind_val),
            or(&rs.subject_col),
            obj.table,
            or(&rs.assignments),
            on.join(" AND "),
            where_.join(" AND ")
        ))
    }

    fn structural_accessor_definer(&self, obj: &Object) -> R<Option<GenFn>> {
        let Some(rs) = self.s.default_role_store() else { return Ok(None) };
        let Some(sel) = object_select_perm(obj) else { return Ok(None) };
        let rels = rels_of(obj);
        let preset_levels = self.s.preset_level_map();
        let mut branches = Vec::new();
        for t in sel.tree.leaves() {
            branches.extend(self.structural_term_enum(obj, t, &rels, rs, &preset_levels)?);
        }
        for g in &self.s.grants {
            if let Some(e) = self.s.enumerated_grant(obj, g) {
                branches.push(self.grant_enum_sql(obj, e));
            }
        }
        if branches.is_empty() {
            return Ok(None);
        }
        let id_t = self.s.id_type();
        Ok(Some(GenFn {
            name: format!("{}_accessors", obj.table),
            sig: format!("p_id {id_t}"),
            returns: format!("TABLE(source text, principal_kind text, principal_id {id_t}, access text)"),
            raw_body: true,
            body: format!("  {}", branches.join("\n  UNION\n  ")),
            ..Default::default()
        }))
    }

    fn structural_term_enum(
        &self,
        obj: &Object,
        t: &Term,
        rels: &Rels,
        rs: &RoleStore,
        preset_levels: &HashMap<String, Vec<String>>,
    ) -> R<Vec<String>> {
        if !t.walk_verb().is_empty() {
            let Some(parent) = rels.get(t.ident()) else {
                return Err(format!("structural accessors: walk references unknown relation {}", quote(t.ident())));
            };
            let lvl = &parent.types[0];
            return Ok(vec![self.role_enum_sql(obj, rs, lvl, preset_levels.get(lvl), "role", "read")]);
        }
        if !t.builtin().is_empty() {
            return Ok(Vec::new());
        }
        let Some(r) = rels.get(t.ident()) else { return Ok(Vec::new()) };
        match &r.repr {
            Repr::Role => {
                if let Some(first) = r.types.first()
                    && let Some(st) = self.s.subject_by_name(first)
                    && self.s.is_platform_role_subject(st)
                {
                    return Ok(vec![self.role_enum_sql(obj, rs, st.anchor(), preset_levels.get(st.anchor()), &st.name, "write")]);
                }
                let obj_level = leaf(obj);
                Ok(vec![self.role_enum_sql(obj, rs, obj_level, preset_levels.get(obj_level), "role", "read")])
            }
            Repr::MemberIn(mi) => Ok(vec![self.memberin_enum_sql(obj, rs, &mi.level)]),
            _ => Ok(Vec::new()),
        }
    }

    fn role_enum_sql(&self, obj: &Object, rs: &RoleStore, level: &str, presets: Option<&Vec<String>>, source: &str, access: &str) -> String {
        let chain = topology::chain(self.s).unwrap_or_default();
        let non_virtual: Vec<&str> = chain.iter().filter(|l| !l.is_virtual).map(|l| l.name.as_str()).collect();
        let on_path: HashSet<String> = topology::ancestor_path(self.s, level)
            .map(|p| p.into_iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default();
        let mut conds = Vec::new();
        for (i, lvl) in non_virtual.iter().enumerate() {
            if i >= rs.scope_cols.len() {
                break;
            }
            let ra_col = &rs.scope_cols[i];
            if on_path.contains(*lvl) {
                conds.push(format!("ra.{} = e.{}", ra_col, self.s.scope_col(obj, lvl)));
            } else {
                conds.push(format!("ra.{ra_col} IS NULL"));
            }
        }
        let mut join = String::new();
        if let Some(presets) = presets.filter(|p| !p.is_empty()) {
            let mut ks = presets.clone();
            ks.sort();
            let q: Vec<String> = ks.iter().map(|p| format!("'{p}'")).collect();
            join = format!(
                " JOIN {} rr ON rr.{} = ra.{} AND rr.{} IN ({})",
                or(&rs.roles_table),
                or(&rs.roles_id),
                or(&rs.role_col),
                or(&rs.key_col),
                q.join(", ")
            );
        }
        let mut on = kind_cond(rs, "ra.");
        on.extend(revoked_cond(rs, "ra."));
        on.extend(conds);
        format!(
            "SELECT '{}'::text AS source, '{}'::text AS principal_kind, ra.{} AS principal_id, '{}'::text AS access\n    FROM {} e JOIN {} ra ON {}{}\n    WHERE e.{} = p_id",
            source,
            or(&rs.kind_val),
            or(&rs.subject_col),
            access,
            obj.table,
            or(&rs.assignments),
            on.join(" AND "),
            join,
            obj.pk()
        )
    }

    fn memberin_enum_sql(&self, obj: &Object, rs: &RoleStore, level: &str) -> String {
        let mut on = kind_cond(rs, "ra.");
        on.extend(revoked_cond(rs, "ra."));
        on.push(format!("ra.{} = e.{}", self.scope_col_for_level(rs, level), self.s.scope_col(obj, level)));
        format!(
            "SELECT 'role'::text, '{}'::text, ra.{}, 'read'::text\n    FROM {} e JOIN {} ra ON {}\n    WHERE e.{} = p_id",
            or(&rs.kind_val),
            or(&rs.subject_col),
            obj.table,
            or(&rs.assignments),
            on.join(" AND "),
            obj.pk()
        )
    }

    fn grant_enum_sql(&self, obj: &Object, g: &Grant) -> String {
        let mut conds = vec![format!("ig.{} = e.{}", g.level_col(), self.s.scope_col(obj, &g.level))];
        if let Some(a) = &g.active_col {
            conds.push(format!("ig.{a} IS NULL"));
        }
        if let Some(e) = &g.expires_col {
            conds.push(format!("ig.{e} > now()"));
        }
        let kind = match self.s.default_role_store() {
            Some(rs) => or(&rs.kind_val).to_string(),
            None => g.name.clone(),
        };
        format!(
            "SELECT '{}'::text, '{}'::text, ig.{}, '{}'::text\n    FROM {} e JOIN {} ig ON {}\n    WHERE e.{} = p_id",
            g.name,
            kind,
            g.grantee_col(),
            grant_access(g),
            obj.table,
            g.table(),
            conds.join(" AND "),
            obj.pk()
        )
    }

    fn kernel_definer(&self, obj: &Object) -> R<GenFn> {
        let mut owner_vc: Option<&ViaColumn> = None;
        for r in &obj.relations {
            if r.name == "owner"
                && let Repr::Column(vc) = &r.repr
            {
                owner_vc = Some(vc);
            }
        }
        let Some(vc) = owner_vc else {
            return Err(format!("object {} has a @kernel perm but no owner column", quote(&obj.name)));
        };
        let principal = self.s.owner_principal_name(obj);
        let mut owner_match = format!("r.{} = p_{}_id", vc.column, principal);
        if let Some(d) = &vc.discrim_col {
            owner_match = format!("{owner_match} AND r.{d} = '{}'", or(&vc.discrim_val));
        }
        let body = format!("EXISTS (SELECT 1 FROM {} r WHERE r.{} = p_{}_id AND {})", obj.table, obj.pk(), obj.name, owner_match);
        Ok(GenFn {
            name: format!("{}_can_access_{}", principal, obj.name),
            sig: format!("p_{}_id text, p_{}_id text, p_access text", principal, obj.name),
            body,
            ..Default::default()
        })
    }

    fn scope_col_for_level(&self, rs: &RoleStore, level: &str) -> String {
        let chain = topology::chain(self.s).unwrap_or_default();
        let mut i = 0;
        for l in chain {
            if l.is_virtual {
                continue;
            }
            if l.name == level {
                if i < rs.scope_cols.len() {
                    return rs.scope_cols[i].clone();
                }
                break;
            }
            i += 1;
        }
        format!("{level}_id")
    }

    fn def_emit_permission_exports(&self, out: &mut Vec<GenFn>, virt: &Virtual) -> R<()> {
        let mut seen: HashSet<String> = out.iter().map(|f| f.name.clone()).collect();
        for obj in &self.s.objects {
            for export in &obj.exports {
                if !seen.insert(export.name.clone()) {
                    return Err(format!("permission export {} collides with a generated function", quote(&export.name)));
                }
                let Some(pm) = mapped_perm(obj, &export.verb) else {
                    return Err(format!(
                        "permission export {}: object {} has no mapped permission {}",
                        quote(&export.name),
                        quote(&obj.name),
                        quote(&export.verb)
                    ));
                };
                let pred = self.admission_with_require(obj, pm, self.s.owner_subject(leaf(obj)), virt)?;
                let args: Vec<String> = export.params.iter().map(|p| format!("{} {}", p.name(), p.ty)).collect();
                let columns: Vec<String> = export.params.iter().map(|p| format!("{} AS {}", p.name(), p.column)).collect();
                out.push(GenFn {
                    name: export.name.clone(),
                    sig: args.join(", "),
                    body: format!("{} FROM (SELECT {}) AS {}", pred, columns.join(", "), obj.table),
                    ..Default::default()
                });
            }
        }
        Ok(())
    }
}

pub(crate) fn grant_group_conds(vg: &ViaGrant, obj: &Object, param: &str) -> Vec<String> {
    let mut conds = vec![format!("g.{} = p_{}_id", vg.record_col, obj.name)];
    if let Some(d) = &vg.discrim_col {
        conds.push(format!("g.{d} = '{}'", or(&vg.discrim_val)));
    }
    conds.push(format!("g.{} = '{}'", vg.kind_col, or(&vg.group_kind_val)));
    conds.push(format!("gc.{} = p_{}_id", or(&vg.group_member_col), param));
    conds.push(format!("g.{} = p_access", vg.access_col));
    conds
}

pub(crate) fn grant_group_exists(vg: &ViaGrant, obj: &Object, param: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM {} g JOIN {} gc ON gc.{} = g.{} WHERE {})",
        vg.table,
        or(&vg.group_closure),
        or(&vg.group_group_col),
        vg.principal_col,
        grant_group_conds(vg, obj, param).join(" AND ")
    )
}
