use crate::gofmt::{Elem, kv_block, struct_fields};
use demesne_emit_sql::Sql;
use demesne_gocompat::{go_export, quote, unexport};
use demesne_model::topology;
use demesne_model::{SpecExt, SurfaceExt};
use demesne_runtime::{AppObjectSurface, HoldsResolver};
use demesne_syntax::{Object, Perm, RoleStore, Spec, Vocabulary};
use std::collections::{HashMap, HashSet};

type R<T> = Result<T, String>;

pub fn go_str_slice<S: AsRef<str>>(ss: &[S]) -> String {
    if ss.is_empty() {
        return "[]string{}".into();
    }
    let parts: Vec<String> = ss.iter().map(|s| quote(s.as_ref())).collect();
    format!("[]string{{{}}}", parts.join(", "))
}

struct Check {
    object: String,
    verb: String,
    method: String,
}

#[derive(Debug)]
pub struct VocabField {
    pub exp: String,
    pub perm: String,
}

#[derive(Debug)]
pub struct VocabDomain {
    pub exp: String,
    pub fields: Vec<VocabField>,
}

/// Groups dotted permissions into capability domains, returning wildcard permissions it skipped.
///
/// # Errors
///
/// Two permissions that generate the same accessor name.
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
            return Err(format!("vocab caps: {} collides on {}.{}", quote(p), dexp, fexp));
        }
        let di = *idx.entry(dexp.clone()).or_insert_with(|| {
            domains.push(VocabDomain { exp: dexp.clone(), fields: Vec::new() });
            domains.len() - 1
        });
        domains[di].fields.push(VocabField { exp: fexp, perm: p.clone() });
    }
    Ok((domains, skipped))
}

struct Gen<'a> {
    pkg: String,
    s: &'a Spec,
    b: String,
    checks: Vec<Check>,
    pdp_checks: Vec<Check>,
}

/// Emits the typed Go framework package for a spec, named `pkg` (default `authz`).
///
/// # Errors
///
/// The claims contract or app surface cannot be built, or generated names collide.
pub fn emit_framework(s: &Spec, pkg: &str) -> R<String> {
    let pkg = if pkg.is_empty() { "authz" } else { pkg };
    let contract = s.claims_contract()?;
    let surf = Sql::new(s).emit_app_surface()?;
    check_accessor_collisions(s, &surf.objects)?;
    let skipped: Vec<&Object> = s.objects.iter().filter(|o| !o.point_checkable()).collect();
    let orphan = orphan_pdp_verbs(s);
    let mut g = Gen { pkg: pkg.to_string(), s, b: String::new(), checks: Vec::new(), pdp_checks: Vec::new() };
    g.header();
    g.preamble();
    g.claims(&contract);
    g.banner(&skipped);
    g.pdp_banner(&orphan);
    for o in surf.objects.iter() {
        if let Some(obj) = s.object_by_name(&o.object) {
            g.object(o, obj);
        }
    }
    let mut emitted_caps = HashSet::new();
    let mut emitted_roles = HashSet::new();
    for rs in &s.role_stores {
        let suffix = if s.role_stores.len() > 1 { go_export(&rs.name) } else { String::new() };
        g.holds(rs, &suffix)?;
        let v = s.rolestore_vocab(rs)?;
        if emitted_caps.insert(v.name.clone()) {
            g.vocab_caps_func(v, &suffix)?;
        }
        g.holds_roles(rs, &suffix)?;
        if emitted_roles.insert(v.name.clone()) {
            g.role_tiers_func(v, &suffix)?;
        }
    }
    g.check_func();
    g.check_handler();
    Ok(collapse_blank_lines(&g.b))
}

fn collapse_blank_lines(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut blank = 0;
    for line in src.split_inclusive('\n') {
        if line == "\n" {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

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

/// Returns the SQL a generated row check runs for permission `pm`, or `None` when it gets no row check.
///
/// A `select` permission always checks with the object's check SQL. An `update` permission or an `@check`
/// permission checks only when the surface compiled SQL for it.
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

/// Refuses objects whose generated accessor names collide with the framework's own helpers.
///
/// # Errors
///
/// The first object whose accessor collides.
pub fn check_accessor_collisions(s: &Spec, objects: &[AppObjectSurface]) -> R<()> {
    let reserved = framework_reserved_names(s);
    for o in objects {
        if reserved.contains(&go_export(&o.object).to_lowercase()) {
            return Err(format!(
                "framework emit: object {} generates the accessor {}, which collides with a generated framework helper of the same name; rename the object (the role-tier accessor is RoleTiers/roleTiers, verb caps is Caps/caps, the reusable check is Check/check)",
                quote(&o.object),
                quote(&go_export(&o.object))
            ));
        }
    }
    Ok(())
}

/// Returns the role-tier fields generated for a vocabulary: each preset key and its accessor name.
///
/// # Errors
///
/// Two presets that generate the same accessor name.
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
            return Err(format!("role tier: preset {} collides on field {}", quote(key), exp));
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

impl Gen<'_> {
    fn w(&mut self, s: &str) {
        self.b.push_str(s);
    }

    fn header(&mut self) {
        self.w("// Code generated by Demesne. DO NOT EDIT.\n\n");
        let pkg = self.pkg.clone();
        self.w(&format!("package {pkg}\n\n"));
        self.w("import (\n\t\"context\"\n\t\"encoding/json\"\n\t\"net/http\"\n\n\tdemesne \"github.com/foir-io/demesne/go\"\n)\n\n");
    }

    fn preamble(&mut self) {
        self.w("type Decision = demesne.Decision\n\nconst (\n\tAllow       = demesne.Allow\n\tDeny        = demesne.Deny\n\tNotGoverned = demesne.NotGoverned\n)\n\n");
    }

    fn claims(&mut self, contract: &[String]) {
        let session = self.s.session();
        self.w(&format!("var claimsContract = {}\n\n", go_str_slice(contract)));
        self.w("type Claims struct {\n");
        let mut fields: Vec<(String, String)> = contract.iter().map(|k| (go_export(k), "string".to_string())).collect();
        fields.push(("Extra".into(), "map[string]string".into()));
        self.w(&struct_fields("\t", &fields));
        self.w("}\n\n");
        self.w("func (c Claims) values() map[string]string {\n\tm := map[string]string{}\n");
        for k in contract {
            let e = go_export(k);
            self.w(&format!("\tif c.{e} != \"\" {{\n\t\tm[{}] = c.{e}\n\t}}\n", quote(k)));
        }
        self.w("\treturn m\n}\n\n");
        self.w("func (c Claims) Mint() (string, error) {\n\treturn demesne.MintClaimsValuesWithExtra(claimsContract, c.values(), c.Extra)\n}\n\n");
        self.w(&format!("const ConnectionRole = {}\n", quote(&session.role)));
        self.w(&format!("const claimsGUC = {}\n\n", quote(&session.setting)));
        self.w("func SetRoleSQL(local bool) string {\n\tif local {\n\t\treturn \"SET LOCAL ROLE \" + ConnectionRole\n\t}\n\treturn \"SET ROLE \" + ConnectionRole\n}\n\nfunc ClaimsSetSQL(local bool) string {\n\tif local {\n\t\treturn \"SELECT set_config('\" + claimsGUC + \"', $1, true)\"\n\t}\n\treturn \"SELECT set_config('\" + claimsGUC + \"', $1, false)\"\n}\n\nfunc SessionSetupSQL(local bool) []string {\n\treturn []string{SetRoleSQL(local), ClaimsSetSQL(local)}\n}\n\n");
    }

    fn banner(&mut self, skipped: &[&Object]) {
        if skipped.is_empty() {
            return;
        }
        self.w("// These objects declare a composite primary key — no single-column row identity, so no\n");
        self.w("// Can / ListResources / CheckMany is generated for them. Reach such rows via your own\n");
        self.w("// predicate or a related object:\n");
        for o in skipped {
            self.w(&format!("//   - {} (table {}, pk {})\n", o.name, o.table, o.pk_cols.join(", ")));
        }
        self.w("\n");
    }

    fn pdp_banner(&mut self, orphan: &[String]) {
        if orphan.is_empty() {
            return;
        }
        self.w("// These @pdp verbs need a permission no rolestore vocabulary covers, so no Holds\n");
        self.w("// resolver is generated for them — resolve their held input yourself, or add a rolestore\n");
        self.w("// for the permission's vocabulary:\n");
        for v in orphan {
            self.w(&format!("//   - {v}\n"));
        }
        self.w("\n");
    }

    fn object(&mut self, o: &AppObjectSurface, obj: &Object) {
        let recv = format!("{}Access", unexport(&o.object));
        let exp = go_export(&o.object);
        self.w(&format!("type {recv} struct{{}}\n\n"));
        self.w(&format!("var {exp} = {recv}{{}}\n\n"));
        for pm in &obj.perms {
            if pm.has_layer("pdp") {
                self.pdp_can(&recv, pm);
                self.pdp_checks.push(Check { object: o.object.to_string(), verb: pm.verb.clone(), method: String::new() });
            } else if let Some(sql) = row_check_sql(o, pm) {
                self.row_can(&recv, &exp, &o.object, &pm.verb, &format!("Can{}", go_export(&pm.verb)), &sql);
            }
        }
        let list_sql = if o.flat_list_fn.is_empty() { o.list_resources_sql() } else { o.list_resources_fast_sql() };
        self.w(&format!("func ({recv}) ListResources(ctx context.Context, q demesne.Querier, after *string, limit int) ([]string, error) {{\n"));
        self.w(&format!("\trows, err := q.QueryContext(ctx, {}, after, limit)\n", quote(&list_sql)));
        self.scan_ids();
        self.w(&format!("func ({recv}) CheckMany(ctx context.Context, q demesne.Querier, ids []string) ([]string, error) {{\n"));
        self.w(&format!("\trows, err := q.QueryContext(ctx, {}, ids)\n", quote(&o.check_many_sql())));
        self.scan_ids();
    }

    fn scan_ids(&mut self) {
        self.w("\tif err != nil {\n\t\treturn nil, err\n\t}\n\tdefer rows.Close()\n");
        self.w("\tvar out []string\n\tfor rows.Next() {\n\t\tvar id string\n\t\tif err := rows.Scan(&id); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\tout = append(out, id)\n\t}\n\treturn out, rows.Err()\n}\n\n");
    }

    fn row_can(&mut self, recv: &str, exp: &str, object: &str, verb: &str, method: &str, sql: &str) {
        self.w(&format!("func ({recv}) {method}(ctx context.Context, q demesne.Querier, id string) (Decision, error) {{\n"));
        self.w("\tvar ok bool\n");
        self.w(&format!("\tif err := q.QueryRowContext(ctx, {}, id).Scan(&ok); err != nil {{\n", quote(sql)));
        self.w("\t\treturn Deny, err\n\t}\n");
        self.w("\treturn demesne.ComposeCan(true, ok, demesne.NotGoverned), nil\n}\n\n");
        self.checks.push(Check { object: object.into(), verb: verb.into(), method: format!("{exp}.{method}") });
    }

    fn pdp_can(&mut self, recv: &str, pm: &Perm) {
        let mut perms = Vec::new();
        for t in pm.tree.leaves() {
            if !t.ident().is_empty() {
                perms.push(t.ident().to_string());
            } else if t.builtin() == "holds" && !t.holds_perm().is_empty() {
                perms.push(t.holds_perm().to_string());
            }
        }
        let method = format!("Can{}", go_export(&pm.verb));
        self.w(&format!("func ({recv}) {method}(held demesne.EffectivePerms) Decision {{\n"));
        for p in perms {
            self.w(&format!("\tif !held.Holds({}) {{\n\t\treturn Deny\n\t}}\n", quote(&p)));
        }
        self.w("\treturn Allow\n}\n\n");
    }

    fn holds(&mut self, rs: &RoleStore, suffix: &str) -> R<()> {
        let r = self.s.holds_resolver(&rs.name)?;
        self.w(&format!("var holdsResolver{suffix} = {}\n\n", resolver_lit(&r)));
        self.w(&format!("const AssignmentsSQL{suffix} = {}\n\n", quote(&r.assignments_sql())));
        self.w(&format!("func ResolveHeld{suffix}(assignments []demesne.RoleAssignment, scope []string) (demesne.EffectivePerms, error) {{\n"));
        self.w(&format!("\treturn holdsResolver{suffix}.Resolve(assignments, scope)\n}}\n\n"));
        self.w(&format!("func Holds{suffix}(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectivePerms, error) {{\n"));
        self.w(&format!("\trows, err := q.QueryContext(ctx, AssignmentsSQL{suffix}, principalID)\n"));
        self.w("\tif err != nil {\n\t\treturn demesne.EffectivePerms{}, err\n\t}\n\tdefer rows.Close()\n");
        self.w("\tvar assignments []demesne.RoleAssignment\n\tfor rows.Next() {\n");
        self.scan_assignment(&r, "demesne.EffectivePerms{}");
        self.w("\tif err := rows.Err(); err != nil {\n\t\treturn demesne.EffectivePerms{}, err\n\t}\n");
        self.w(&format!("\treturn ResolveHeld{suffix}(assignments, scope)\n}}\n\n"));
        Ok(())
    }

    fn scan_assignment(&mut self, r: &HoldsResolver, zero: &str) {
        let sel = r.selected_scope_cols().len();
        self.w(&format!("\t\ta := demesne.RoleAssignment{{Scope: make([]string, {sel})}}\n"));
        let mut dest: Vec<String> = Vec::new();
        if sel > 0 {
            let names: Vec<String> = (0..sel).map(|i| format!("s{i}")).collect();
            dest.extend((0..sel).map(|i| format!("&s{i}")));
            self.w(&format!("\t\tvar {} *string\n", names.join(", ")));
        }
        dest.push("&a.RoleKey".into());
        if !r.perms_col.is_empty() {
            dest.push("&a.Permissions".into());
        }
        self.w(&format!("\t\tif err := rows.Scan({}); err != nil {{\n", dest.join(", ")));
        self.w(&format!("\t\t\treturn {zero}, err\n\t\t}}\n"));
        for i in 0..sel {
            self.w(&format!("\t\tif s{i} != nil {{\n\t\t\ta.Scope[{i}] = *s{i}\n\t\t}}\n"));
        }
        self.w("\t\tassignments = append(assignments, a)\n\t}\n");
    }

    fn check_func(&mut self) {
        self.w("func Check(ctx context.Context, q demesne.Querier, object, verb, id string) (Decision, error) {\n");
        self.w("\tswitch object + \".\" + verb {\n");
        let checks = std::mem::take(&mut self.checks);
        for c in &checks {
            self.w(&format!("\tcase {}:\n\t\treturn {}(ctx, q, id)\n", quote(&format!("{}.{}", c.object, c.verb)), c.method));
        }
        let pdp = std::mem::take(&mut self.pdp_checks);
        for c in &pdp {
            self.w(&format!("\tcase {}:\n\t\treturn NotGoverned, demesne.CapabilityGateErr(object, verb)\n", quote(&format!("{}.{}", c.object, c.verb))));
        }
        self.w("\tdefault:\n\t\treturn NotGoverned, nil\n\t}\n}\n\n");
    }

    fn vocab_caps_func(&mut self, v: &Vocabulary, suffix: &str) -> R<()> {
        let (domains, skipped) = vocab_caps_tree(&v.permissions)?;
        if !skipped.is_empty() {
            self.w("// These vocabulary permissions are parameterized (a '*' model segment) and have no static\n");
            self.w("// caps field — check them with held.Holds(\"<domain>:<verb>:<model>\") directly:\n");
            for p in &skipped {
                self.w(&format!("//   - {p}\n"));
            }
            self.w("\n");
        }
        if domains.is_empty() {
            return Ok(());
        }
        let set = format!("CapSet{suffix}");
        self.w(&format!("type {set} struct {{\n"));
        let fields: Vec<(String, String)> = domains.iter().map(|d| (d.exp.clone(), format!("{}Caps{suffix}", d.exp))).collect();
        self.w(&struct_fields("\t", &fields));
        self.w("}\n\n");
        for d in &domains {
            self.w(&format!("type {}Caps{suffix} struct {{\n", d.exp));
            let fields: Vec<(String, String)> = d.fields.iter().map(|f| (f.exp.clone(), "bool".to_string())).collect();
            self.w(&struct_fields("\t", &fields));
            self.w("}\n\n");
        }
        self.w(&format!("func Caps{suffix}(held demesne.EffectivePerms) {set} {{\n"));
        self.w(&format!("\treturn {set}{{\n"));
        let elems: Vec<Elem> = domains
            .iter()
            .map(|d| {
                let inner: Vec<Elem> = d.fields.iter().map(|f| Elem::Pair { key: f.exp.clone(), value: format!("held.Holds({})", quote(&f.perm)) }).collect();
                Elem::Multi(format!("{}: {}Caps{suffix}{{\n{}\t\t}}", d.exp, d.exp, kv_block("\t\t\t", &inner)))
            })
            .collect();
        self.w(&kv_block("\t\t", &elems));
        self.w("\t}\n}\n\n");
        Ok(())
    }

    fn holds_roles(&mut self, rs: &RoleStore, suffix: &str) -> R<()> {
        let r = self.s.holds_resolver(&rs.name)?;
        self.w(&format!("func ResolveHeldRoles{suffix}(assignments []demesne.RoleAssignment, scope []string) demesne.EffectiveRoles {{\n"));
        self.w("\treturn demesne.ResolveRoles(assignments, scope)\n}\n\n");
        self.w(&format!(
            "func HoldsRoles{suffix}(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectiveRoles, error) {{\n"
        ));
        self.w(&format!("\trows, err := q.QueryContext(ctx, AssignmentsSQL{suffix}, principalID)\n"));
        self.w("\tif err != nil {\n\t\treturn demesne.EffectiveRoles{}, err\n\t}\n\tdefer rows.Close()\n");
        self.w("\tvar assignments []demesne.RoleAssignment\n\tfor rows.Next() {\n");
        self.scan_assignment(&r, "demesne.EffectiveRoles{}");
        self.w("\tif err := rows.Err(); err != nil {\n\t\treturn demesne.EffectiveRoles{}, err\n\t}\n");
        self.w(&format!("\treturn ResolveHeldRoles{suffix}(assignments, scope), nil\n}}\n\n"));
        Ok(())
    }

    fn role_tiers_func(&mut self, v: &Vocabulary, suffix: &str) -> R<()> {
        let fields = role_tier_fields(self.s, v)?;
        if fields.is_empty() {
            return Ok(());
        }
        let set = format!("RoleSet{suffix}");
        self.w(&format!("type {set} struct {{\n"));
        let sf: Vec<(String, String)> = fields.iter().map(|(e, _)| (e.clone(), "bool".to_string())).collect();
        self.w(&struct_fields("\t", &sf));
        self.w("}\n\n");
        self.w(&format!("func RoleTiers{suffix}(held demesne.EffectiveRoles) {set} {{\n"));
        self.w(&format!("\treturn {set}{{\n"));
        let elems: Vec<Elem> = fields.iter().map(|(e, k)| Elem::Pair { key: e.clone(), value: format!("held.Holds({})", quote(k)) }).collect();
        self.w(&kv_block("\t\t", &elems));
        self.w("\t}\n}\n\n");
        Ok(())
    }

    fn check_handler(&mut self) {
        self.w("func CheckHandler(q demesne.Querier) http.HandlerFunc {\n");
        self.w("\treturn func(w http.ResponseWriter, r *http.Request) {\n");
        self.w("\t\td, err := Check(r.Context(), q, r.FormValue(\"object\"), r.FormValue(\"verb\"), r.FormValue(\"id\"))\n");
        self.w("\t\tif err != nil {\n\t\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\t\treturn\n\t\t}\n");
        self.w("\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n");
        self.w("\t\t_ = json.NewEncoder(w).Encode(map[string]string{\"decision\": d.String()})\n");
        self.w("\t}\n}\n");
    }
}

fn resolver_lit(r: &HoldsResolver) -> String {
    let mut elems = vec![
        Elem::Pair { key: "Assignments".into(), value: quote(&r.assignments) },
        Elem::Pair { key: "KindCol".into(), value: quote(&r.kind_col) },
        Elem::Pair { key: "KindVal".into(), value: quote(&r.kind_val) },
        Elem::Pair { key: "SubjectCol".into(), value: quote(&r.subject_col) },
        Elem::Pair { key: "ScopeCols".into(), value: go_str_slice(&r.scope_cols) },
        Elem::Pair { key: "RevokedCol".into(), value: quote(&r.revoked_col) },
    ];
    if !r.plane.is_empty() {
        elems.push(Elem::Pair { key: "Plane".into(), value: quote(&r.plane) });
        elems.push(Elem::Pair { key: "PlaneDepth".into(), value: r.plane_depth.to_string() });
    }
    elems.extend([
        Elem::Pair { key: "RoleCol".into(), value: quote(&r.role_col) },
        Elem::Pair { key: "RolesTable".into(), value: quote(&r.roles_table) },
        Elem::Pair { key: "RolesID".into(), value: quote(&r.roles_id) },
        Elem::Pair { key: "KeyCol".into(), value: quote(&r.key_col) },
        Elem::Pair { key: "PermsCol".into(), value: quote(&r.perms_col) },
        Elem::Multi(format!("Vocab: {}", vocab_lit(&r.vocab))),
    ]);
    format!("&demesne.HoldsResolver{{\n{}}}", kv_block("\t", &elems))
}

fn vocab_lit(v: &demesne_runtime::Vocabulary) -> String {
    let mut elems =
        vec![Elem::Pair { key: "Name".into(), value: quote(&v.name) }, Elem::Pair { key: "Permissions".into(), value: go_str_slice(&v.permissions) }];
    if !v.implications.is_empty() {
        let items: Vec<Elem> =
            v.implications.iter().map(|im| Elem::Item(format!("{{Perm: {}, Star: {}, Set: {}}}", quote(&im.perm), im.star, go_str_slice(&im.set)))).collect();
        elems.push(Elem::Multi(format!("Implications: []*demesne.Implication{{\n{}\t\t}}", kv_block("\t\t\t", &items))));
    }
    if !v.presets.is_empty() {
        let items: Vec<Elem> = v
            .presets
            .iter()
            .map(|p| Elem::Item(format!("{{Name: {}, Level: {}, Star: {}, Set: {}}}", quote(&p.name), quote(&p.level), p.star, go_str_slice(&p.set))))
            .collect();
        elems.push(Elem::Multi(format!("Presets: []*demesne.Preset{{\n{}\t\t}}", kv_block("\t\t\t", &items))));
    }
    elems.push(Elem::Pair { key: "Rank".into(), value: go_str_slice(&v.rank) });
    format!("&demesne.Vocabulary{{\n{}\t}}", kv_block("\t\t", &elems))
}
