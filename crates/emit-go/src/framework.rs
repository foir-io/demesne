use crate::error::Error;
use crate::{Package, decode, header, strings};
use demesne_emit_sql::Sql;
use demesne_emit_ts::projections;
use demesne_gocompat::{go_export, quote};
use demesne_model::framework::{check_accessor_collisions, orphan_pdp_verbs, role_tier_fields, row_check_sql, vocab_caps_tree};
use demesne_model::{SpecExt, SurfaceExt};
use demesne_runtime::{AppObjectSurface, HoldsResolver, SettingLifetime};
use demesne_syntax::{Object, Perm, Spec, Vocabulary};
use std::collections::HashSet;
use std::fmt::Write as _;

type R<T> = Result<T, Error>;

struct Gen<'a> {
    s: &'a Spec,
    b: String,
    checks: Vec<(String, String)>,
    gates: Vec<(String, String)>,
}

/// Emits the typed Go framework package for a spec, over the Go module `github.com/foir-io/demesne/go`.
///
/// # Errors
///
/// The claims contract or app surface cannot be built, or generated names collide.
pub fn emit_framework_go(s: &Spec, pkg: &Package) -> R<String> {
    let contract = s.claims_contract()?;
    let surf = Sql::new(s).emit_app_surface()?;
    check_accessor_collisions(s, &surf.objects)?;
    let mut g = Gen { s, b: String::new(), checks: Vec::new(), gates: Vec::new() };
    g.claims(&contract);
    let skipped: Vec<&Object> = s.objects.iter().filter(|o| !o.point_checkable()).collect();
    g.banner(&skipped);
    g.pdp_banner(&orphan_pdp_verbs(s));
    let objects: Vec<(&AppObjectSurface, &Object)> = surf.objects.iter().filter_map(|o| s.object_by_name(&o.object).map(|obj| (o, obj))).collect();
    g.surface(&objects, &contract);
    for (o, obj) in &objects {
        g.object(o, obj);
    }
    let mut emitted_caps = HashSet::new();
    let mut emitted_roles = HashSet::new();
    for rs in &s.role_stores {
        let suffix = if s.role_stores.len() > 1 { go_export(&rs.name) } else { String::new() };
        let r = s.holds_resolver(&rs.name)?;
        g.holds(&r, &suffix);
        let v = s.rolestore_vocab(rs)?;
        if emitted_caps.insert(v.name.clone()) {
            g.vocab_caps(v, &suffix)?;
        }
        g.holds_roles(&r, &suffix);
        if emitted_roles.insert(v.name.clone()) {
            g.role_tiers(v, &suffix)?;
        }
    }
    g.check_func();
    g.check_handler();
    Ok(g.assemble(pkg))
}

fn fields(rows: &[(String, String)]) -> String {
    let width = rows.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
    let mut b = String::new();
    for (n, t) in rows {
        let pad = width + 1 - n.chars().count();
        writeln!(b, "\t{n}{}{t}", " ".repeat(pad)).expect("fmt::Write for String never fails");
    }
    b
}

fn capability_gate_msg(object: &str, verb: &str) -> String {
    format!(
        "{object}.{verb} is a capability (@pdp) verb with no row-level check: resolve held permissions and call {}.Can{}(held)",
        go_export(object),
        go_export(verb)
    )
}

impl Gen<'_> {
    fn w(&mut self, s: &str) {
        self.b.push_str(s);
    }

    fn assemble(&self, pkg: &Package) -> String {
        let mut head = header(pkg);
        head.push_str("\nimport (\n\t\"context\"\n\t\"encoding/json\"\n");
        if !self.gates.is_empty() {
            head.push_str("\t\"errors\"\n");
        }
        head.push_str("\t\"net/http\"\n\n\tdemesne \"github.com/foir-io/demesne/go\"\n)\n\n");
        head.push_str("type Decision = demesne.Decision\n\nconst (\n\tAllow       = demesne.Allow\n\tDeny        = demesne.Deny\n\tNotGoverned = demesne.NotGoverned\n)\n\n");
        head + &self.b
    }

    fn claims(&mut self, contract: &[String]) {
        let session = self.s.session();
        self.w(&format!("var claimsContract = {}\n\n", strings(contract)));
        let mut rows: Vec<(String, String)> = contract.iter().map(|k| (go_export(k), "string".to_string())).collect();
        rows.push(("Extra".to_string(), "map[string]string".to_string()));
        self.w(&format!("type Claims struct {{\n{}}}\n\n", fields(&rows)));
        self.w(&format!("const ConnectionRole = {}\n\n", quote(&session.role)));
        let both = |f: &dyn Fn(SettingLifetime) -> String| {
            format!("\tif local {{\n\t\treturn {}\n\t}}\n\treturn {}\n", quote(&f(SettingLifetime::Transaction)), quote(&f(SettingLifetime::Session)))
        };
        self.w(&format!("func SetRoleSQL(local bool) string {{\n{}}}\n\n", both(&|l| session.set_role_sql(l))));
        self.w(&format!("func ClaimsSetSQL(local bool) string {{\n{}}}\n\n", both(&|l| session.claims_set_sql(l))));
        self.w("func SessionSetupSQL(local bool) []string {\n\treturn []string{SetRoleSQL(local), ClaimsSetSQL(local)}\n}\n\n");
    }

    fn banner(&mut self, skipped: &[&Object]) {
        if skipped.is_empty() {
            return;
        }
        self.w("// These objects declare a composite primary key, so they have no single-column row identity and no\n");
        self.w("// CanView, ListResources or CheckMany is generated for them. Reach such rows through your own\n");
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
        self.w("// These @pdp verbs need a permission no rolestore vocabulary covers, so no holds resolver is\n");
        self.w("// generated for them. Resolve their held input yourself, or add a rolestore for the\n");
        self.w("// permission's vocabulary:\n");
        for v in orphan {
            self.w(&format!("//   - {v}\n"));
        }
        self.w("\n");
    }

    fn surface(&mut self, objects: &[(&AppObjectSurface, &Object)], contract: &[String]) {
        let mut rows = vec![("r".to_string(), "*demesne.Runtime".to_string())];
        rows.extend(objects.iter().map(|(o, _)| (go_export(&o.object), format!("{}Access", go_export(&o.object)))));
        self.w(&format!("type Surface struct {{\n{}}}\n\n", fields(&rows)));
        self.w("func New(r *demesne.Runtime) *Surface {\n\ts := &Surface{r: r}\n");
        for (o, _) in objects {
            let exp = go_export(&o.object);
            self.w(&format!("\ts.{exp} = {exp}Access{{r}}\n"));
        }
        self.w("\treturn s\n}\n\n");
        self.w("func (s *Surface) Mint(ctx context.Context, c Claims) (string, error) {\n\tvalues := map[string]string{}\n");
        for k in contract {
            let f = go_export(k);
            self.w(&format!("\tif c.{f} != \"\" {{\n\t\tvalues[{}] = c.{f}\n\t}}\n", quote(k)));
        }
        self.w("\treturn s.r.MintClaimsValuesWithExtra(ctx, claimsContract, values, c.Extra)\n}\n\n");
    }

    fn object(&mut self, o: &AppObjectSurface, obj: &Object) {
        let exp = go_export(&o.object);
        let ty = format!("{exp}Access");
        self.w(&format!("type {ty} struct{{ r *demesne.Runtime }}\n\n"));
        for pm in &obj.perms {
            let method = format!("Can{}", go_export(&pm.verb));
            let case = quote(&format!("{}.{}", o.object, pm.verb));
            if pm.has_layer("pdp") {
                self.w(&pdp_can(&ty, &method, pm));
                self.gates.push((case, capability_gate_msg(&o.object, &pm.verb)));
                continue;
            }
            let Some(sql) = row_check_sql(o, pm) else { continue };
            self.w(&row_can(&ty, &method, &sql));
            self.checks.push((case, format!("s.{exp}.{method}(ctx, q, id)")));
        }
        let list_sql = if o.flat_list_fn.is_empty() { o.list_resources_sql() } else { o.list_resources_fast_sql() };
        self.w(&format!(
            "func ({ty}) ListResources(ctx context.Context, q demesne.Querier, after *string, limit int) ([]string, error) {{\n\treturn demesne.QueryIDs(ctx, q, {}, after, limit)\n}}\n\n",
            quote(&list_sql)
        ));
        self.w(&format!(
            "func ({ty}) CheckMany(ctx context.Context, q demesne.Querier, ids []string) ([]string, error) {{\n\treturn demesne.QueryIDs(ctx, q, {}, ids)\n}}\n\n",
            quote(&o.check_many_sql())
        ));
    }

    fn assignments(&mut self, r: &HoldsResolver, suffix: &str, zero: &str) {
        self.w(&format!(
            "\tassignments, err := demesne.QueryAssignments(ctx, q, AssignmentsSQL{suffix}, principalID, {}, {})\n\tif err != nil {{\n\t\treturn {zero}, err\n\t}}\n",
            r.selected_scope_cols().len(),
            !r.perms_col.is_empty()
        ));
    }

    fn holds(&mut self, r: &HoldsResolver, suffix: &str) {
        self.w(&format!("var holdsResolver{suffix} = {}\n\n", decode("demesne.HoldsResolver", &projections::holds(r))));
        self.w(&format!("const AssignmentsSQL{suffix} = {}\n\n", quote(&r.assignments_sql())));
        self.w(&format!(
            "func (s *Surface) ResolveHeld{suffix}(ctx context.Context, assignments []demesne.RoleAssignment, scope []string) (demesne.EffectivePerms, error) {{\n\treturn holdsResolver{suffix}.Resolve(ctx, s.r, assignments, scope)\n}}\n\n"
        ));
        self.w(&format!(
            "func (s *Surface) Holds{suffix}(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectivePerms, error) {{\n"
        ));
        self.assignments(r, suffix, "demesne.EffectivePerms{}");
        self.w(&format!("\treturn s.ResolveHeld{suffix}(ctx, assignments, scope)\n}}\n\n"));
    }

    fn vocab_caps(&mut self, v: &Vocabulary, suffix: &str) -> R<()> {
        let (domains, skipped) = vocab_caps_tree(&v.permissions)?;
        if !skipped.is_empty() {
            self.w("// These vocabulary permissions are parameterized (a '*' model segment) and have no static\n");
            self.w("// caps field. Check them with held.Holds(\"<domain>:<verb>:<model>\") directly:\n");
            for p in &skipped {
                self.w(&format!("//   - {p}\n"));
            }
            self.w("\n");
        }
        if domains.is_empty() {
            return Ok(());
        }
        let rows: Vec<(String, String)> = domains.iter().map(|d| (d.exp.clone(), format!("{}Caps{suffix}", d.exp))).collect();
        self.w(&format!("type CapSet{suffix} struct {{\n{}}}\n\n", fields(&rows)));
        for d in &domains {
            let rows: Vec<(String, String)> = d.fields.iter().map(|f| (f.exp.clone(), "bool".to_string())).collect();
            self.w(&format!("type {}Caps{suffix} struct {{\n{}}}\n\n", d.exp, fields(&rows)));
        }
        self.w(&format!("func Caps{suffix}(held demesne.EffectivePerms) CapSet{suffix} {{\n\tvar c CapSet{suffix}\n"));
        for d in &domains {
            for f in &d.fields {
                self.w(&format!("\tc.{}.{} = held.Holds({})\n", d.exp, f.exp, quote(&f.perm)));
            }
        }
        self.w("\treturn c\n}\n\n");
        Ok(())
    }

    fn holds_roles(&mut self, r: &HoldsResolver, suffix: &str) {
        self.w(&format!(
            "func (s *Surface) ResolveHeldRoles{suffix}(ctx context.Context, assignments []demesne.RoleAssignment, scope []string) (demesne.EffectiveRoles, error) {{\n\treturn s.r.ResolveRoles(ctx, assignments, scope)\n}}\n\n"
        ));
        self.w(&format!(
            "func (s *Surface) HoldsRoles{suffix}(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectiveRoles, error) {{\n"
        ));
        self.assignments(r, suffix, "demesne.EffectiveRoles{}");
        self.w(&format!("\treturn s.ResolveHeldRoles{suffix}(ctx, assignments, scope)\n}}\n\n"));
    }

    fn role_tiers(&mut self, v: &Vocabulary, suffix: &str) -> R<()> {
        let tiers = role_tier_fields(self.s, v)?;
        if tiers.is_empty() {
            return Ok(());
        }
        let rows: Vec<(String, String)> = tiers.iter().map(|(exp, _)| (exp.clone(), "bool".to_string())).collect();
        self.w(&format!("type RoleSet{suffix} struct {{\n{}}}\n\n", fields(&rows)));
        self.w(&format!("func RoleTiers{suffix}(held demesne.EffectiveRoles) RoleSet{suffix} {{\n\tvar t RoleSet{suffix}\n"));
        for (exp, key) in &tiers {
            self.w(&format!("\tt.{exp} = held.Holds({})\n", quote(key)));
        }
        self.w("\treturn t\n}\n\n");
        Ok(())
    }

    fn check_func(&mut self) {
        let mut b = String::from("func (s *Surface) Check(ctx context.Context, q demesne.Querier, object, verb, id string) (Decision, error) {\n");
        b.push_str("\tswitch object + \".\" + verb {\n");
        for (case, call) in &self.checks {
            write!(b, "\tcase {case}:\n\t\treturn {call}\n").expect("fmt::Write for String never fails");
        }
        for (case, message) in &self.gates {
            write!(b, "\tcase {case}:\n\t\treturn Deny, errors.New({})\n", quote(message)).expect("fmt::Write for String never fails");
        }
        b.push_str("\tdefault:\n\t\treturn NotGoverned, nil\n\t}\n}\n\n");
        self.w(&b);
    }

    fn check_handler(&mut self) {
        self.w("func (s *Surface) CheckHandler(q demesne.Querier) http.Handler {\n");
        self.w("\treturn http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {\n");
        self.w("\t\tp := req.URL.Query()\n");
        self.w("\t\td, err := s.Check(req.Context(), q, p.Get(\"object\"), p.Get(\"verb\"), p.Get(\"id\"))\n");
        self.w("\t\tif err != nil {\n\t\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\t\treturn\n\t\t}\n");
        self.w("\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n");
        self.w("\t\t_ = json.NewEncoder(w).Encode(map[string]Decision{\"decision\": d})\n");
        self.w("\t})\n}\n");
    }
}

fn row_can(ty: &str, method: &str, sql: &str) -> String {
    format!(
        "func (a {ty}) {method}(ctx context.Context, q demesne.Querier, id string) (Decision, error) {{\n\tvar ok bool\n\tif err := q.QueryRowContext(ctx, {}, id).Scan(&ok); err != nil {{\n\t\treturn Deny, err\n\t}}\n\treturn a.r.ComposeCan(ctx, true, ok, NotGoverned)\n}}\n\n",
        quote(sql)
    )
}

fn pdp_can(ty: &str, method: &str, pm: &Perm) -> String {
    let mut b = format!("func ({ty}) {method}(held demesne.EffectivePerms) Decision {{\n");
    for t in pm.tree.leaves() {
        let perm = if !t.ident().is_empty() {
            t.ident()
        } else if t.builtin() == "holds" && !t.holds_perm().is_empty() {
            t.holds_perm()
        } else {
            continue;
        };
        writeln!(b, "\tif !held.Holds({}) {{\n\t\treturn Deny\n\t}}", quote(perm)).expect("fmt::Write for String never fails");
    }
    b.push_str("\treturn Allow\n}\n\n");
    b
}
