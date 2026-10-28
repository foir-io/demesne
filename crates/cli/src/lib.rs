#![doc = "The demesne command line's pure commands (validate, emit, help, version) over a `Files` source, shared by the native binary and the WASM build. Its errors are messages to print; the library crates (`demesne-model`, `demesne-emit-sql`, `demesne-postgres` and the emitters) return typed errors."]

use demesne_emit_sql::{Manifest, Sql, definers_sql};
use demesne_gocompat::quote;
use demesne_model::{SpecExt, pdp::emit_pdp};
use demesne_syntax::{Spec, SpecFiles};
use std::io;

pub const USAGE: &str = "demesne — RLS-compiled ReBAC authorization, point it at your database.

USAGE:
  demesne validate <spec.demesne>...           parse + validate a spec
  demesne emit     <spec.demesne>... [kind]    print generated SQL
                                               kind: rls|definers|enablement|triggers|pdp|all (default all)
                                               manifest: JSON record of every object the SQL creates
                                               migrate <manifest.json>: all, then exact drops of what that
                                                            manifest's surface had and this spec no longer emits
                                               --file <spec.demesne>: one file's share of a spec in several
                                                            files (kind all, manifest or migrate)
                                               --target ts: emit TypeScript (@foir/demesne)
                                                            kind: claims|pdp|projections|framework|all
                                               --profile supabase: emit the Supabase
                                                            deployment profile (access-token hook)
                                               v1 generates no Go; use demesne v0.93.1 for Go
  demesne introspect <dsn>                     summarise the live schema (tables/columns/FKs)
  demesne scaffold   [-i] <dsn>                generate a STARTER spec from the schema (-i: interactive)
  demesne check    <spec.demesne> <dsn>        validate the spec, bind it to the live schema, check the RLS role,
                                               and look for schema traps (owner-rights views, NULL-blind unique
                                               scope indexes, policy comparisons that can't use an index)
  demesne diff     <spec.demesne> <dsn> [--exit-code] [--allow <file>]
                                               generated-vs-live drift, both ways: policies, definers, triggers
                                               and orphans; --exit-code fails (exit 1) on any drift (CI guard);
                                               --allow lists orphans to leave unreported, one per line
  demesne coverage <spec.demesne> <dsn> [--exit-code]   ungoverned tables (no object → no RLS); --exit-code fails (exit 1) if any (CI guard)
  demesne version                              print the build version

<spec.demesne>... is a spec in one file, or in several, given in order: each file may refer to what the
files before it declare, and may `replace` a declaration of theirs.
<dsn> may be omitted to use $DATABASE_URL. A Postgres connection string, e.g.
  postgres://user:pass@host:5432/db
";

pub type R = Result<(), String>;

const NO_GO: &str = "v1 generates no Go: use --target ts for TypeScript, or demesne v0.93.1 for Go";

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

    /// Prints the warnings a loaded spec earns, each naming its file.
    pub fn warn_loaded(&mut self, paths: &[String], loaded: &Loaded) {
        match loaded {
            Loaded::One(s) => self.warn_spec(&paths[0], s),
            Loaded::Many(files) => {
                for w in demesne_emit_sql::validate_files_warnings(files) {
                    self.err.extend_from_slice(format!("warning: {w}\n").as_bytes());
                }
            }
        }
    }
}

/// A spec a command has loaded: written in one file, or in several compiled as one model.
#[derive(Debug, Clone)]
pub enum Loaded {
    One(Box<Spec>),
    Many(SpecFiles),
}

impl Loaded {
    /// Returns the spec, of every file when it has several.
    #[must_use]
    pub fn spec(&self) -> &Spec {
        match self {
            Loaded::One(s) => s,
            Loaded::Many(files) => files.spec(),
        }
    }
}

/// Splits a command's arguments into its spec files and the arguments after them.
///
/// The spec files are the first argument and every argument straight after it that ends in `.demesne`.
#[must_use]
pub fn spec_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let n = args.iter().skip(1).take_while(|a| a.ends_with(".demesne")).count() + usize::from(!args.is_empty());
    (args[..n].to_vec(), args[n..].to_vec())
}

/// Reads, parses and validates a spec in one file or in several.
///
/// # Errors
///
/// A file cannot be read, or the spec does not parse or validate. A spec in several files validates one prefix at a
/// time, and each finding names its file.
pub fn load_specs(files: &dyn Files, paths: &[String]) -> Result<Loaded, String> {
    if let [path] = paths {
        return load_spec(files, path).map(|s| Loaded::One(Box::new(s)));
    }
    let texts = paths.iter().map(|p| files.read(p)).collect::<Result<Vec<_>, _>>()?;
    let spec = demesne_syntax::parse_files(paths.iter().map(String::as_str).zip(texts.iter().map(Vec::as_slice))).map_err(|e| format!("parse: {e}"))?;
    demesne_emit_sql::validate_files(&spec).map_err(|e| format!("validate: {e}"))?;
    Ok(Loaded::Many(spec))
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
    let (paths, _) = spec_args(args);
    let loaded = load_specs(files, &paths)?;
    out.warn_loaded(&paths, &loaded);
    let s = loaded.spec();
    let rls = Sql::new(s).emit_rls().map_err(|e| e.to_string())?;
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
    let (target, args) = strip_flag(args, "target", "");
    let (profile, args) = strip_flag(&args, "profile", "");
    let (file, args) = strip_flag(&args, "file", "");
    need(&args, 1, "<spec.demesne>")?;
    let (paths, rest) = spec_args(&args);
    let loaded = load_specs(files, &paths)?;
    out.warn_loaded(&paths, &loaded);
    let kind = rest.first().map_or("all", String::as_str);
    if !file.is_empty() {
        if !target.is_empty() || !profile.is_empty() {
            return Err("--file picks one file's share of the SQL; --target and --profile emit the whole spec, so give them the files it is made of".into());
        }
        return emit_file(out, files, &paths, &loaded, &file, kind, &rest);
    }
    let s = loaded.spec();
    if !profile.is_empty() {
        return emit_profile(out, s, &profile);
    }
    match target.as_str() {
        "" => {}
        "ts" => return emit_ts(out, s, kind),
        "go" => return Err(NO_GO.to_string()),
        other => return Err(format!("unknown --target {} (ts)", quote(other))),
    }
    let sql = Sql::new(s);
    match kind {
        "definers" => emit_definers_sql(out, &sql),
        "rls" | "policies" => emit_rls_sql(out, &sql),
        "enablement" => emit_enablement_sql(out, &sql),
        "triggers" => {
            out.print(&sql.triggers_sql());
            Ok(())
        }
        "claims" | "framework" => Err(format!("emit kind {} generated Go. {NO_GO}", quote(kind))),
        "pdp" => emit_pdp_report(out, s),
        "all" => emit_all_sql(out, &sql),
        "manifest" => {
            out.print(&sql.manifest().map_err(|e| e.to_string())?.to_json());
            Ok(())
        }
        "migrate" => {
            out.print(&sql.migration(&previous_manifest(files, &rest)?).map_err(|e| e.to_string())?);
            Ok(())
        }
        other => Err(format!("unknown emit kind {} (rls|definers|enablement|triggers|pdp|all|manifest|migrate)", quote(other))),
    }
}

fn previous_manifest(files: &dyn Files, rest: &[String]) -> Result<Manifest, String> {
    let path = rest.get(1).ok_or("missing argument: <spec.demesne> migrate <previous manifest.json>")?;
    let src = files.read(path)?;
    Manifest::from_json(&String::from_utf8_lossy(&src)).map_err(|e| format!("{path}: {e}"))
}

fn emit_file(out: &mut Out, files: &dyn Files, paths: &[String], loaded: &Loaded, file: &str, kind: &str, rest: &[String]) -> R {
    let k = paths.iter().position(|p| p == file).ok_or_else(|| format!("--file {} names none of the spec's files ({})", quote(file), paths.join(", ")))?;
    let spec = match loaded {
        Loaded::Many(spec) => spec.clone(),
        Loaded::One(_) => {
            let texts = paths.iter().map(|p| files.read(p)).collect::<Result<Vec<_>, _>>()?;
            demesne_syntax::parse_files(paths.iter().map(String::as_str).zip(texts.iter().map(Vec::as_slice))).map_err(|e| format!("parse: {e}"))?
        }
    };
    let text = match kind {
        "all" => demesne_emit_sql::file_sql(&spec, k).map_err(|e| e.to_string())?,
        "manifest" => Sql::new(spec.prefix(k)).manifest().map_err(|e| e.to_string())?.to_json(),
        "migrate" => demesne_emit_sql::file_migration(&spec, k, &previous_manifest(files, rest)?).map_err(|e| e.to_string())?,
        other => {
            return Err(format!("--file takes the emit kinds all, manifest and migrate, and {} covers the whole spec: emit it without --file", quote(other)));
        }
    };
    out.print(&text);
    Ok(())
}

fn emit_profile(out: &mut Out, s: &Spec, profile: &str) -> R {
    match profile {
        "supabase" => {
            let p = Sql::new(s).emit_supabase_profile().map_err(|e| e.to_string())?;
            out.print(&p);
            out.print("\n");
            Ok(())
        }
        other => Err(format!("unknown --profile {} (supabase)", quote(other))),
    }
}

fn emit_definers_sql(out: &mut Out, sql: &Sql) -> R {
    let defs = sql.emit_definers().map_err(|e| e.to_string())?;
    out.print(&definers_sql(&defs));
    Ok(())
}

fn emit_rls_sql(out: &mut Out, sql: &Sql) -> R {
    let res = sql.emit_rls().map_err(|e| e.to_string())?;
    if !res.unsupported.is_empty() {
        return Err(format!("spec has uncompilable @rls permissions: {}", res.unsupported.join("; ")));
    }
    out.print(&res.policy_sql("authenticated"));
    Ok(())
}

fn emit_enablement_sql(out: &mut Out, sql: &Sql) -> R {
    let res = sql.emit_rls().map_err(|e| e.to_string())?;
    out.print(&res.enablement_sql());
    Ok(())
}

fn emit_pdp_report(out: &mut Out, s: &Spec) -> R {
    let pdps = emit_pdp(s).map_err(|e| e.to_string())?;
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
    res.map_err(|e| e.to_string())
}

fn emit_ts(out: &mut Out, s: &Spec, kind: &str) -> R {
    match kind {
        "all" | "projections" => {
            out.print(&demesne_emit_ts::emit_ts(s).map_err(|e| e.to_string())?);
            Ok(())
        }
        "claims" => {
            out.print(&demesne_emit_ts::render_claims_contract_ts(s, "ClaimsContract").map_err(|e| e.to_string())?);
            Ok(())
        }
        "pdp" => {
            let pdps = emit_pdp(s).map_err(|e| e.to_string())?;
            for (i, (site, p)) in pdps.iter().enumerate() {
                if i > 0 {
                    out.print("\n");
                }
                out.print(&demesne_emit_ts::render_pdp_ts(p, &format!("{site}Policy")));
            }
            Ok(())
        }
        "framework" => {
            out.print(&demesne_emit_ts::emit_framework_ts(s).map_err(|e| e.to_string())?);
            Ok(())
        }
        "rls" | "policies" | "definers" | "enablement" | "triggers" => {
            Err(format!("emit kind {} is language-neutral SQL/DDL — it has no TypeScript target; emit it without --target ts", quote(kind)))
        }
        other => Err(format!("unknown emit kind {} for --target ts (claims|pdp|projections|framework|all)", quote(other))),
    }
}
