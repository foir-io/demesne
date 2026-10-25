#![doc = "The demesne command line's pure commands (validate, emit, help, version) over a `Files` source, shared by the native binary and the WASM build."]

use demesne_emit_sql::{Manifest, Sql, definers_sql};
use demesne_gocompat::quote;
use demesne_model::{SpecExt, pdp::emit_pdp};
use demesne_syntax::Spec;
use std::io;

pub const USAGE: &str = "demesne — RLS-compiled ReBAC authorization, point it at your database.

USAGE:
  demesne validate <spec.demesne>              parse + validate a spec
  demesne emit     <spec.demesne> [kind]       print generated SQL/Go
                                               kind: rls|definers|enablement|triggers|claims|pdp|framework|all (default all)
                                               manifest: JSON record of every object the SQL creates
                                               migrate <manifest.json>: all, then exact drops of what that
                                                            manifest's surface had and this spec no longer emits
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

pub type R = Result<(), String>;

#[derive(Debug, Default)]
pub struct Out {
    pub buf: Vec<u8>,
    pub err: Vec<u8>,
}

impl Out {
    pub fn print(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn warn_spec(&mut self, path: &str, s: &Spec) {
        for w in demesne_emit_sql::validate_warnings(s) {
            self.err.extend_from_slice(format!("warning: {path}: {w}\n").as_bytes());
        }
    }
}

#[must_use]
pub fn build_version() -> &'static str {
    match option_env!("DEMESNE_VERSION") {
        Some(v) => v,
        None => env!("CARGO_PKG_VERSION"),
    }
}

pub trait Files {
    /// Reads the whole file at `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be read. The message matches the Go CLI's.
    fn read(&self, path: &str) -> Result<Vec<u8>, String>;
}

#[derive(Debug)]
pub struct OsFiles;

impl Files for OsFiles {
    fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| go_read_error(path, &e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: u8,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[must_use]
pub fn finish(out: Out, res: R) -> Output {
    match res {
        Ok(()) => Output { code: 0, stdout: out.buf, stderr: out.err },
        Err(e) => {
            let mut stderr = out.err;
            stderr.extend_from_slice(format!("demesne: {e}\n").as_bytes());
            Output { code: 1, stdout: out.buf, stderr }
        }
    }
}

pub const LIVE_COMMANDS: &[&str] = &["introspect", "scaffold", "check", "diff", "coverage"];

pub fn run_pure(args: &[String], files: &dyn Files) -> Option<Output> {
    let Some(cmd) = args.first() else {
        return Some(Output { code: 2, stdout: Vec::new(), stderr: USAGE.as_bytes().to_vec() });
    };
    let rest = &args[1..];
    let mut out = Out::default();
    let res = match cmd.as_str() {
        "validate" => cmd_validate(&mut out, files, rest),
        "emit" => cmd_emit(&mut out, files, rest),
        "version" | "--version" | "-v" => return Some(Output { code: 0, stdout: format!("{}\n", build_version()).into_bytes(), stderr: Vec::new() }),
        "help" | "-h" | "--help" => return Some(Output { code: 0, stdout: USAGE.as_bytes().to_vec(), stderr: Vec::new() }),
        c if LIVE_COMMANDS.contains(&c) => return None,
        other => {
            return Some(Output { code: 2, stdout: Vec::new(), stderr: format!("demesne: unknown command {}\n\n{USAGE}", quote(other)).into_bytes() });
        }
    };
    Some(finish(out, res))
}

#[must_use]
pub fn go_read_error(path: &str, e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => format!("open {path}: no such file or directory"),
        io::ErrorKind::PermissionDenied => format!("open {path}: permission denied"),
        io::ErrorKind::IsADirectory => format!("read {path}: is a directory"),
        _ => format!("open {path}: {e}"),
    }
}

/// Reads, parses and validates the spec at `path`.
///
/// # Errors
///
/// The file cannot be read, or the spec does not parse or validate.
pub fn load_spec(files: &dyn Files, path: &str) -> Result<Spec, String> {
    let src = files.read(path)?;
    let s = demesne_syntax::parse_bytes(&src).map_err(|e| format!("parse {path}: {e}"))?;
    demesne_emit_sql::validate(&s).map_err(|e| format!("validate {path}: {e}"))?;
    Ok(s)
}

/// Checks a command received at least `n` arguments.
///
/// # Errors
///
/// Fewer than `n` arguments; the message names the missing `what`.
pub fn need(args: &[String], n: usize, what: &str) -> R {
    if args.len() < n {
        return Err(format!("missing argument: {what}"));
    }
    Ok(())
}

fn cmd_validate(out: &mut Out, files: &dyn Files, args: &[String]) -> R {
    need(args, 1, "<spec.demesne>")?;
    let s = load_spec(files, &args[0])?;
    out.warn_spec(&args[0], &s);
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

#[must_use]
pub fn strip_flag(args: &[String], name: &str, def: &str) -> (String, Vec<String>) {
    let mut val = def.to_string();
    let pfx = format!("--{name}=");
    let flag = format!("--{name}");
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if *a == flag {
            if i + 1 < args.len() {
                val.clone_from(&args[i + 1]);
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

fn cmd_emit(out: &mut Out, files: &dyn Files, args: &[String]) -> R {
    let (target, args) = strip_flag(args, "target", "go");
    let (profile, args) = strip_flag(&args, "profile", "");
    need(&args, 1, "<spec.demesne>")?;
    let s = load_spec(files, &args[0])?;
    out.warn_spec(&args[0], &s);
    let kind = args.get(1).map_or("all", String::as_str);
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
            let pkg = args.get(2).map_or("authz", String::as_str);
            out.print(&demesne_emit_go::emit_framework(&s, pkg)?);
            Ok(())
        }
        "all" => emit_all_sql(out, &sql),
        "manifest" => {
            out.print(&sql.manifest()?.to_json());
            Ok(())
        }
        "migrate" => {
            need(&args, 3, "<spec.demesne> migrate <previous manifest.json>")?;
            let src = files.read(&args[2])?;
            let previous = Manifest::from_json(&String::from_utf8_lossy(&src)).map_err(|e| format!("{}: {e}", args[2]))?;
            out.print(&sql.migration(&previous)?);
            Ok(())
        }
        other => Err(format!("unknown emit kind {} (rls|definers|enablement|triggers|claims|pdp|framework|all|manifest|migrate)", quote(other))),
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
    let mut b = String::new();
    let res = sql.write_all_sql(&mut b);
    out.print(&b);
    res
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
        "rls" | "policies" | "definers" | "enablement" | "triggers" => {
            Err(format!("emit kind {} is language-neutral SQL/DDL — it has no TypeScript target; emit it without --target ts", quote(kind)))
        }
        other => Err(format!("unknown emit kind {} for --target ts (claims|pdp|projections|framework|all)", quote(other))),
    }
}
