use demesne_cli::{Files, OsFiles, Out, R, finish, load_spec, need, run_pure, strip_flag};
use demesne_emit_sql::Sql;
use demesne_gocompat::quote;
use demesne_model::SpecExt;
use demesne_syntax::Spec;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let o = run_pure(&args, &OsFiles).unwrap_or_else(|| {
        let mut out = Out::default();
        let rest = &args[1..];
        let res = match args[0].as_str() {
            "introspect" => cmd_introspect(&mut out, rest),
            "scaffold" => cmd_scaffold(&mut out, rest),
            "check" => cmd_check(&mut out, rest),
            "diff" => cmd_diff(&mut out, rest),
            _ => cmd_coverage(&mut out, rest),
        };
        finish(out, res)
    });
    let _ = io::stdout().write_all(&o.stdout);
    let _ = io::stderr().write_all(&o.stderr);
    ExitCode::from(o.code)
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
    let found = args.contains(&flag);
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
    out.print(&demesne_model::scaffold::scaffold(&sc, demesne_model::scaffold::ScaffoldOptions::default())?);
    Ok(())
}

#[expect(clippy::print_stderr, reason = "the interactive scaffold asks its questions on stderr, as the Go CLI does")]
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
    let body = demesne_model::scaffold::scaffold(sc, demesne_model::scaffold::ScaffoldOptions::default())?;
    let mut b = String::new();
    if role != "authenticated" {
        writeln!(b, "claims via \"request.jwt.claims\" json role {role}").expect("fmt::Write for String never fails");
    }
    if def_schema != "auth" {
        writeln!(b, "definers schema {}", quote(&def_schema)).expect("fmt::Write for String never fails");
    }
    if tbl_schema != "public" {
        writeln!(b, "tables schema {}", quote(&tbl_schema)).expect("fmt::Write for String never fails");
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
                writeln!(b, "// object {t} {{ table {t}; scoped <levels>; use contained }}").expect("fmt::Write for String never fails");
            }
        }
    }
    out.print(&b);
    Ok(())
}

fn cmd_check(out: &mut Out, args: &[String]) -> R {
    need(args, 1, "<spec.demesne>")?;
    let s = load_spec(&OsFiles, &args[0])?;
    out.warn_spec(&args[0], &s);
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
    report_schema_traps(out, &s, &mut client)
}

fn report_schema_traps(out: &mut Out, s: &Spec, client: &mut postgres::Client) -> R {
    let mut sql = String::new();
    let governed: Vec<String> = match Sql::new(s).write_all_sql(&mut sql).and_then(|()| demesne_emit_sql::objects(&sql)) {
        Ok(objs) => objs.into_iter().filter_map(|(o, _)| if let demesne_emit_sql::Object::Rls(t) = o { Some(t) } else { None }).collect(),
        Err(e) => {
            out.print(&format!("warning: could not look for schema traps, as the spec's SQL does not compile: {e}\n"));
            return Ok(());
        }
    };
    let schema = s.table_schema();
    let mut scope: Vec<(String, String)> = Vec::new();
    for obj in &s.objects {
        for lvl in obj.scoped.iter().filter(|l| !s.level_is_virtual(l)) {
            scope.push((format!("{schema}.{}", obj.table), s.scope_col(obj, lvl)));
        }
    }
    for rs in &s.role_stores {
        if let Some(t) = &rs.assignments {
            scope.extend(rs.scope_cols.iter().map(|c| (format!("{schema}.{t}"), c.clone())));
        }
    }
    let traps = match demesne_postgres::schema_traps(client, &governed, &scope) {
        Ok(t) => t,
        Err(e) => {
            out.print(&format!("warning: could not look for schema traps: {e}\n"));
            return Ok(());
        }
    };
    if traps.is_empty() {
        out.print("ok: no schema traps: views over governed tables read as their caller, unique indexes constrain NULL scope rows, and policies compare bare columns\n");
    }
    for t in &traps {
        let label = match t.severity {
            demesne_postgres::Severity::Danger => "DANGER",
            demesne_postgres::Severity::Warning => "warning",
        };
        out.print(&format!("{label}: {}\n", t.message));
    }
    let dangers = traps.iter().filter(|t| t.severity == demesne_postgres::Severity::Danger).count();
    if dangers > 0 {
        return Err(format!("{dangers} schema trap(s) let rows past the policies"));
    }
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
            plane.clone_from(&rs.name);
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
    let s = load_spec(&OsFiles, &args[0])?;
    out.warn_spec(&args[0], &s);
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
        out.print(&format!("UNGOVERNED  {t} — no object in the spec, so no RLS. Model it with an object, or confirm it is intentionally exempt.\n"));
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
    let (exit_code, args) = strip_bool_flag(args, "exit-code");
    let (allow_path, args) = strip_flag(&args, "allow", "");
    need(&args, 1, "<spec.demesne>")?;
    let s = load_spec(&OsFiles, &args[0])?;
    out.warn_spec(&args[0], &s);
    let dsn = dsn_arg(&args, 1)?;
    let mut sql = String::new();
    Sql::new(&s).write_all_sql(&mut sql)?;
    let allow: Vec<String> = if allow_path.is_empty() {
        Vec::new()
    } else {
        String::from_utf8_lossy(&OsFiles.read(&allow_path)?).lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
    };
    let mut client = demesne_postgres::connect(&dsn)?;
    let d = demesne_postgres::drift(&mut client, &sql, &allow)?;
    for f in &d.findings {
        out.print(&format!("{:<8} {} — {}\n", f.kind.label(), f.object, f.detail));
    }
    if d.findings.is_empty() {
        out.print(&format!("in sync: {} policies, {} functions and {} triggers match the spec, with no orphans\n", d.policies, d.functions, d.triggers));
    }
    if exit_code && !d.findings.is_empty() {
        let mut counts: std::collections::BTreeMap<demesne_postgres::DriftKind, usize> = std::collections::BTreeMap::new();
        for f in &d.findings {
            *counts.entry(f.kind).or_default() += 1;
        }
        let summary: Vec<String> = counts.iter().map(|(k, n)| format!("{n} {}", k.label().to_lowercase())).collect();
        return Err(format!("drift: {} — the live database is not the spec's; the spec must be the only source of policy", summary.join(", ")));
    }
    Ok(())
}
