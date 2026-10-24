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
        "introspect" | "scaffold" | "check" | "diff" | "coverage" => Err(format!("{cmd}: not yet ported")),
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
        "ts" => return Err("emit --target ts: not yet ported".into()),
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
        "claims" => Err("emit claims: not yet ported".into()),
        "pdp" => emit_pdp_report(out, &s),
        "framework" => Err("emit framework: not yet ported".into()),
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
        for (pr, perm) in &p.policy {
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
