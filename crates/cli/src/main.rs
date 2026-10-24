use demesne_emit_sql::{Sql, definers_sql};
use demesne_gocompat::quote;
use demesne_model::{SpecExt, pdp::emit_pdp};
use demesne_syntax::Spec;
use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "demesne — RLS-compiled ReBAC authorization, point it at your database.

USAGE:
  demesne validate <spec.demesne>              parse + validate a spec
  demesne emit     <spec.demesne> [kind]       print generated SQL/Go
                                               kind: rls|definers|enablement|triggers|claims|pdp|framework|all (default all)
                                               --target ts: emit TypeScript (@foir/demesne)
                                                            kind: claims|pdp|projections|framework|all
                                               --profile supabase: emit the Supabase
                                                            deployment profile (access-token hook)
                                               framework [pkg]: typed Go app package (default pkg \"authz\")
  demesne introspect <dsn>                     summarise the live schema (tables/columns/FKs)
  demesne scaffold   [-i] <dsn>                generate a STARTER spec from the schema (-i: interactive)
  demesne check    <spec.demesne> <dsn>        validate the spec, bind it to the live schema, check the RLS role
  demesne diff     <spec.demesne> <dsn> [--exit-code]   generated-vs-live policy drift; --exit-code fails (exit 1) on any drift (CI guard)
  demesne coverage <spec.demesne> <dsn> [--exit-code]   ungoverned tables (no object → no RLS); --exit-code fails (exit 1) if any (CI guard)
  demesne version                              print the build version

<dsn> may be omitted to use $DATABASE_URL. A Postgres connection string, e.g.
  postgres://user:pass@host:5432/db
";

type R = Result<(), String>;

struct Out {
    buf: Vec<u8>,
}

impl Out {
    fn print(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }
}

fn build_version() -> &'static str {
    option_env!("DEMESNE_VERSION").unwrap_or("dev")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    let mut out = Out { buf: Vec::new() };
    let res = match cmd.as_str() {
        "validate" => cmd_validate(&mut out, rest),
        "emit" => cmd_emit(&mut out, rest),
        "version" | "--version" | "-v" => {
            println!("{}", build_version());
            return ExitCode::SUCCESS;
        }
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "introspect" => cmd_introspect(&mut out, rest),
        "scaffold" => cmd_scaffold(&mut out, rest),
        "check" => cmd_check(&mut out, rest),
        "diff" => cmd_diff(&mut out, rest),
        "coverage" => cmd_coverage(&mut out, rest),
        other => {
            eprint!("demesne: unknown command {}\n\n{USAGE}", quote(other));
            return ExitCode::from(2);
        }
    };
    let _ = io::stdout().write_all(&out.buf);
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("demesne: {e}");
            ExitCode::from(1)
        }
    }
}

fn go_read_error(path: &str, e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => format!("open {path}: no such file or directory"),
        io::ErrorKind::PermissionDenied => format!("open {path}: permission denied"),
        io::ErrorKind::IsADirectory => format!("read {path}: is a directory"),
        _ => format!("open {path}: {e}"),
    }
}

fn load_spec(path: &str) -> Result<Spec, String> {
    let src = std::fs::read(path).map_err(|e| go_read_error(path, &e))?;
    let s = demesne_syntax::parse_bytes(&src).map_err(|e| format!("parse {path}: {e}"))?;
    demesne_emit_sql::validate(&s).map_err(|e| format!("validate {path}: {e}"))?;
    Ok(s)
}

fn need(args: &[String], n: usize, what: &str) -> R {
    if args.len() < n {
        return Err(format!("missing argument: {what}"));
    }
    Ok(())
}

fn cmd_validate(out: &mut Out, args: &[String]) -> R {
    need(args, 1, "<spec.demesne>")?;
    let s = load_spec(&args[0])?;
    let rls = Sql::new(&s).emit_rls()?;
    out.print(&format!(
        "ok: {} objects, {} levels, {} policies, {} reachability grants\n",
        s.objects.len(),
        s.levels().len(),
        rls.policies.len(),
        s.reach_grants().len()
    ));
    Ok(())
}

fn strip_flag(args: &[String], name: &str, def: &str) -> (String, Vec<String>) {
    let mut val = def.to_string();
    let pfx = format!("--{name}=");
    let flag = format!("--{name}");
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if *a == flag {
            if i + 1 < args.len() {
                val = args[i + 1].clone();
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix(&pfx) {
            val = v.to_string();
        } else {
            out.push(a.clone());
        }
        i += 1;
    }
    (val, out)
}

fn cmd_emit(out: &mut Out, args: &[String]) -> R {
    let (target, args) = strip_flag(args, "target", "go");
    let (profile, args) = strip_flag(&args, "profile", "");
    need(&args, 1, "<spec.demesne>")?;
    let s = load_spec(&args[0])?;
    let kind = args.get(1).map(String::as_str).unwrap_or("all");
    if !profile.is_empty() {
        return emit_profile(out, &s, &profile);
    }
    match target.as_str() {
        "go" => {}
        "ts" => return emit_ts(out, &s, kind),
        other => return Err(format!("unknown --target {} (go|ts)", quote(other))),
    }
    let sql = Sql::new(&s);
    match kind {
        "definers" => emit_definers_sql(out, &sql),
        "rls" | "policies" => emit_rls_sql(out, &sql),
        "enablement" => emit_enablement_sql(out, &sql),
        "triggers" => {
            out.print(&sql.triggers_sql());
            Ok(())
        }
        "claims" => {
            out.print(&demesne_emit_go::render_claims_contract_go(&s, "ClaimsContract")?);
            Ok(())
        }
        "pdp" => emit_pdp_report(out, &s),
        "framework" => {
            let pkg = args.get(2).map(String::as_str).unwrap_or("authz");
            out.print(&demesne_emit_go::emit_framework(&s, pkg)?);
            Ok(())
        }
        "all" => emit_all_sql(out, &sql),
        other => Err(format!(
            "unknown emit kind {} (rls|definers|enablement|triggers|claims|pdp|framework|all)",
            quote(other)
        )),
    }
}

fn emit_profile(out: &mut Out, s: &Spec, profile: &str) -> R {
    match profile {
        "supabase" => {
            let p = Sql::new(s).emit_supabase_profile()?;
            out.print(&p);
            out.print("\n");
            Ok(())
        }
        other => Err(format!("unknown --profile {} (supabase)", quote(other))),
    }
}

fn emit_definers_sql(out: &mut Out, sql: &Sql) -> R {
    let defs = sql.emit_definers()?;
    out.print(&definers_sql(&defs));
    Ok(())
}

fn emit_rls_sql(out: &mut Out, sql: &Sql) -> R {
    let res = sql.emit_rls()?;
    if !res.unsupported.is_empty() {
        return Err(format!("spec has uncompilable @rls permissions: {}", res.unsupported.join("; ")));
    }
    out.print(&res.policy_sql("authenticated"));
    Ok(())
}

fn emit_enablement_sql(out: &mut Out, sql: &Sql) -> R {
    let res = sql.emit_rls()?;
    out.print(&res.enablement_sql());
    Ok(())
}

fn emit_pdp_report(out: &mut Out, s: &Spec) -> R {
    let pdps = emit_pdp(s)?;
    for (site, p) in &pdps {
        out.print(&format!("# PDP {}: {} governed, {} ungoverned\n", quote(site), p.policy.len(), p.ungoverned.len()));
        for (pr, perm) in p.policy.iter() {
            out.print(&format!("{pr} -> {perm}\n"));
        }
    }
    Ok(())
}

fn emit_all_sql(out: &mut Out, sql: &Sql) -> R {
    let f = sql.flats_sql();
    if !f.is_empty() {
        out.print(&f);
        out.print("\n");
    }
    emit_definers_sql(out, sql)?;
    out.print("\n");
    emit_enablement_sql(out, sql)?;
    out.print("\n");
    emit_rls_sql(out, sql)?;
    let t = sql.triggers_sql();
    if !t.is_empty() {
        out.print(&format!("\n{t}"));
    }
    let c = sql.changelog_sql();
    if !c.is_empty() {
        out.print(&format!("\n{c}"));
    }
    let a = sql.async_sql();
    if !a.is_empty() {
        out.print(&format!("\n{a}"));
    }
    Ok(())
}

fn emit_ts(out: &mut Out, s: &Spec, kind: &str) -> R {
    match kind {
        "all" | "projections" => {
            out.print(&demesne_emit_ts::emit_ts(s)?);
            Ok(())
        }
        "claims" => {
            out.print(&demesne_emit_ts::render_claims_contract_ts(s, "ClaimsContract")?);
            Ok(())
        }
        "pdp" => {
            let pdps = emit_pdp(s)?;
            for (i, (site, p)) in pdps.iter().enumerate() {
                if i > 0 {
                    out.print("\n");
                }
                out.print(&demesne_emit_ts::render_pdp_ts(p, &format!("{site}Policy")));
            }
            Ok(())
        }
        "framework" => {
            out.print(&demesne_emit_ts::emit_framework_ts(s)?);
            Ok(())
        }
        "rls" | "policies" | "definers" | "enablement" | "triggers" => Err(format!(
            "emit kind {} is language-neutral SQL/DDL — it has no TypeScript target; emit it without --target ts",
            quote(kind)
        )),
        other => Err(format!("unknown emit kind {} for --target ts (claims|pdp|projections|framework|all)", quote(other))),
    }
}

fn dsn_arg(args: &[String], i: usize) -> Result<String, String> {
    if let Some(a) = args.get(i).filter(|a| !a.is_empty()) {
        return Ok(a.clone());
    }
    match std::env::var("DATABASE_URL") {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err("no <dsn> given and $DATABASE_URL is empty".into()),
    }
}

fn introspect(dsn: &str) -> Result<(demesne_model::Schema, demesne_postgres::IntrospectMeta, postgres::Client), String> {
    let mut client = demesne_postgres::connect(dsn)?;
    let (sc, meta) = demesne_postgres::introspect(&mut client)?;
    Ok((sc, meta, client))
}

fn strip_bool_flag(args: &[String], name: &str) -> (bool, Vec<String>) {
    let flag = format!("--{name}");
    let found = args.iter().any(|a| *a == flag);
    (found, args.iter().filter(|a| **a != flag).cloned().collect())
}

fn cmd_introspect(out: &mut Out, args: &[String]) -> R {
    let dsn = dsn_arg(args, 0)?;
    let (_, meta, _) = introspect(&dsn)?;
    out.print(&format!("schema: {} tables, {} columns, {} foreign keys\n", meta.tables, meta.columns, meta.fks));
    Ok(())
}

fn cmd_scaffold(out: &mut Out, args: &[String]) -> R {
    let interactive = args.iter().any(|a| a == "-i" || a == "--interactive");
    let rest: Vec<String> = args.iter().filter(|a| *a != "-i" && *a != "--interactive").cloned().collect();
    let dsn = dsn_arg(&rest, 0)?;
    let (sc, _, _) = introspect(&dsn)?;
    if interactive {
        return scaffold_interactive(out, &sc);
    }
    out.print(&demesne_model::scaffold::scaffold(&sc, Default::default())?);
    Ok(())
}

fn scaffold_interactive(out: &mut Out, sc: &demesne_model::Schema) -> R {
    use std::io::BufRead;
    let stdin = io::stdin();
    let mut lines = stdin.lock();
    let mut ask = |label: &str, def: &str| -> String {
        eprint!("{label} [{def}]: ");
        let mut line = String::new();
        let _ = lines.read_line(&mut line);
        let line = line.trim();
        if line.is_empty() { def.to_string() } else { line.to_string() }
    };
    eprintln!("Introspected {} tables. A few deployment questions (Enter = default):", sc.tables().len());
    let role = ask("RLS connection role", "authenticated");
    let def_schema = ask("definer (function) schema", "auth");
    let tbl_schema = ask("governed-table schema", "public");
    let body = demesne_model::scaffold::scaffold(sc, Default::default())?;
    let mut b = String::new();
    if role != "authenticated" {
        b.push_str(&format!("claims via \"request.jwt.claims\" json role {role}\n"));
    }
    if def_schema != "auth" {
        b.push_str(&format!("definers schema {}\n", quote(&def_schema)));
    }
    if tbl_schema != "public" {
        b.push_str(&format!("tables schema {}\n", quote(&tbl_schema)));
    }
    if !b.is_empty() {
        b.push('\n');
    }
    b.push_str(&body);
    if let Ok(spec) = demesne_syntax::parse(&body) {
        let cov = demesne_model::table_coverage(&spec, &sc.tables());
        if !cov.ungoverned.is_empty() {
            b.push_str("\n// ── Ungoverned tables (no object → no RLS). Model each, or delete this block. ──\n");
            for t in &cov.ungoverned {
                b.push_str(&format!("// object {t} {{ table {t}; scoped <levels>; use contained }}\n"));
            }
        }
    }
    out.print(&b);
    Ok(())
}

fn cmd_check(out: &mut Out, args: &[String]) -> R {
    need(args, 1, "<spec.demesne>")?;
    let s = load_spec(&args[0])?;
    let dsn = dsn_arg(args, 1)?;
    let (sc, _, mut client) = introspect(&dsn)?;
    demesne_model::validate_against(&s, &sc).map_err(|e| format!("spec does not bind to the live schema:\n{e}"))?;
    out.print("ok: spec is valid AND binds to the live schema (every referenced table/column exists)\n");
    let role = s.session().role;
    match demesne_postgres::role_bypasses_rls(&mut client, &role) {
        Err(e) => out.print(&format!("warning: could not verify the RLS role {}: {e}\n", quote(&role))),
        Ok((false, _)) => out.print(&format!("warning: the RLS connection role {} does not exist on this database\n", quote(&role))),
        Ok((true, true)) => {
            out.print(&format!(
                "DANGER: the RLS connection role {} has BYPASSRLS — it ignores every policy, defeating the moat. Use a non-BYPASSRLS role for sessions.\n",
                quote(&role)
            ));
            return Err(format!("RLS role {} is BYPASSRLS", quote(&role)));
        }
        Ok((true, false)) => out.print(&format!("ok: the RLS connection role {} is not BYPASSRLS\n", quote(&role))),
    }
    report_global_assignments(out, &s, &mut client);
    Ok(())
}

fn report_global_assignments(out: &mut Out, s: &Spec, client: &mut postgres::Client) {
    use demesne_model::SurfaceExt;
    if s.role_stores.is_empty() {
        return;
    }
    let Ok(hr) = s.holds_resolver("") else { return };
    let query = hr.global_assignments_sql();
    if query.is_empty() {
        return;
    }
    let n = demesne_postgres::count_global_assignments(client, &query);
    let mut plane = String::new();
    for rs in &s.role_stores {
        let Ok(r) = s.holds_resolver(&rs.name) else { continue };
        if r.plane.is_empty() || r.plane_depth != 0 {
            continue;
        }
        if r.assignments == hr.assignments && r.kind_val == hr.kind_val {
            plane = rs.name.clone();
            break;
        }
    }
    let col0 = &hr.scope_cols[0];
    match n {
        Err(e) => out.print(&format!("warning: could not audit globally scoped role assignments: {e}\n")),
        Ok(n) if n > 0 && !plane.is_empty() => out.print(&format!(
            "note: {n} active role assignment(s) leave {}.{col0} NULL. Rolestore {} declares a global plane over the same table, so those rows may be its assignments; anything else there is a cross-{col0} grant. List them with:\n  {query}\n",
            hr.assignments,
            quote(&plane)
        )),
        Ok(n) if n > 0 => out.print(&format!(
            "DANGER: {n} active role assignment(s) leave {}.{col0} NULL, which is the GLOBAL scope — they confer their permissions across every value of {col0}. List them with:\n  {query}\n",
            hr.assignments
        )),
        Ok(_) => out.print(&format!("ok: no active role assignment leaves {col0} NULL (the global scope)\n")),
    }
}

fn cmd_coverage(out: &mut Out, args: &[String]) -> R {
    let (exit_code, args) = strip_bool_flag(args, "exit-code");
    need(&args, 1, "<spec.demesne>")?;
    let s = load_spec(&args[0])?;
    let dsn = dsn_arg(&args, 1)?;
    let (sc, _, _) = introspect(&dsn)?;
    let cov = demesne_model::table_coverage(&s, &sc.tables());
    out.print(&format!(
        "{} governed (RLS), {} referenced (policy-free stores), {} UNGOVERNED\n",
        cov.governed.len(),
        cov.referenced.len(),
        cov.ungoverned.len()
    ));
    for t in &cov.ungoverned {
        out.print(&format!(
            "UNGOVERNED  {t} — no object in the spec, so no RLS. Model it with an object, or confirm it is intentionally exempt.\n"
        ));
    }
    if cov.ungoverned.is_empty() {
        out.print("ok: every live table is governed by an object or referenced as a policy-free store\n");
    }
    if exit_code && !cov.ungoverned.is_empty() {
        return Err(format!(
            "{} ungoverned table(s) — no object governs them, so any RLS on them is hand-authored; model each or mark it a policy-free store",
            cov.ungoverned.len()
        ));
    }
    Ok(())
}

fn cmd_diff(out: &mut Out, args: &[String]) -> R {
    use std::collections::BTreeSet;
    let (exit_code, args) = strip_bool_flag(args, "exit-code");
    need(&args, 1, "<spec.demesne>")?;
    let s = load_spec(&args[0])?;
    let dsn = dsn_arg(&args, 1)?;
    let res = Sql::new(&s).emit_rls()?;
    let gen_set: BTreeSet<String> = res.policies.iter().map(|p| format!("{}.{}", p.table, p.name)).collect();
    let governed: Vec<String> =
        res.policies.iter().map(|p| p.table.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let mut client = demesne_postgres::connect(&dsn)?;
    let live = demesne_postgres::live_policy_surface(&mut client, &governed)?;
    let missing: Vec<&String> = gen_set.iter().filter(|k| !live.contains(*k)).collect();
    let orphan: Vec<&String> = live.iter().filter(|k| !gen_set.contains(*k)).collect();
    for m in &missing {
        out.print(&format!("MISSING  {m} — generated but not present live (apply it)\n"));
    }
    for o in &orphan {
        out.print(&format!("ORPHAN   {o} — live on a governed table but not generated (remove it, or model it)\n"));
    }
    if missing.is_empty() && orphan.is_empty() {
        out.print(&format!(
            "in sync: {} generated policies all present, no orphans across {} governed tables\n",
            gen_set.len(),
            governed.len()
        ));
    }
    if exit_code && missing.len() + orphan.len() > 0 {
        return Err(format!(
            "policy drift: {} generated-but-missing, {} orphan — the live database is not the spec's; the spec must be the only source of policy",
            missing.len(),
            orphan.len()
        ));
    }
    Ok(())
}
