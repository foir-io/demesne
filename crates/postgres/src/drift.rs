use crate::{Error, query_error};
use demesne_emit_sql::{Object, objects, revoked_from_public};
use demesne_runtime::quote_literal;
use postgres::{Client, Transaction};
use std::collections::{BTreeMap, BTreeSet};

/// How a live object differs from the spec's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DriftKind {
    /// The spec creates it and the database has no such object.
    Missing,
    /// Both have it, with different definitions.
    Changed,
    /// The spec's statement for it does not compile against the live database.
    Invalid,
    /// The database has it where the spec governs, and the spec does not create it.
    Orphan,
    /// An allow-list entry that no live orphan matches.
    Stale,
}

impl DriftKind {
    /// The label `demesne diff` prints for it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Missing => "MISSING",
            Self::Changed => "CHANGED",
            Self::Invalid => "INVALID",
            Self::Orphan => "ORPHAN",
            Self::Stale => "STALE",
        }
    }
}

/// One difference between the live database and the spec's SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// What kind of difference it is.
    pub kind: DriftKind,
    /// The object, such as `policy notes_select on public.notes` or `function auth.f(text)`.
    pub object: String,
    /// What differs, or what to do about it.
    pub detail: String,
}

/// Every difference between the live database and the spec's SQL, and how many objects match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    /// The differences: tables, policies, functions, then triggers, each in the order the SQL creates them, then orphans and stale allow entries.
    pub findings: Vec<Finding>,
    /// Policies whose live definition is the generated one.
    pub policies: usize,
    /// Functions whose live definition is the generated one.
    pub functions: usize,
    /// Triggers whose live definition is the generated one.
    pub triggers: usize,
}

/// Compares the live database with `sql`, the spec's whole SQL, in both directions.
///
/// Policies are compared by command, roles, permissive, `USING` and `WITH CHECK`, and functions and triggers by their whole definition. A function the SQL revokes `EXECUTE` on from PUBLIC is also changed when PUBLIC may execute it live. Orphans are the policies on a governed table, and the functions in a definer schema or triggers calling them, that the SQL does not create.
///
/// Each generated object is created as a temporary copy and read back, so both sides are compared as Postgres deparses them. Nothing outside the session's temporary schema is created, and the transaction is rolled back. An `allow` entry is an orphan's object text, such as `function auth.f(text)`, to leave unreported; an entry that matches no orphan is reported as stale.
///
/// # Errors
///
/// The SQL creates an object the manifest does not record, or a catalog query fails.
pub fn drift(client: &mut Client, sql: &str, allow: &[String]) -> Result<Drift, Error> {
    let objs = objects(sql).map_err(|e| Error::sql(e.to_string()))?;
    let revoked = revoked_from_public(sql).into_iter().collect();
    compare(client, &objs, &revoked, allow).map_err(Error::query)
}

fn compare(client: &mut Client, objs: &[(Object, String)], revoked: &BTreeSet<String>, allow: &[String]) -> Result<Drift, String> {
    let mut tx = client.transaction().map_err(|e| query_error(&e))?;
    tx.batch_execute("SET LOCAL check_function_bodies = off; SELECT set_config('search_path', current_setting('search_path') || ', pg_temp', true)")
        .map_err(|e| query_error(&e))?;
    let mut c = Comparison {
        objs,
        revoked,
        live: BTreeMap::new(),
        shadow: BTreeMap::new(),
        governed: BTreeSet::new(),
        scratch: BTreeMap::new(),
        invalid: BTreeMap::new(),
        schemas: Vec::new(),
        out: Drift::default(),
        orphans: Vec::new(),
    };
    c.shadow_tables(&mut tx)?;
    c.create_generated(&mut tx);
    tx.batch_execute("SET LOCAL search_path = ''").map_err(|e| query_error(&e))?;
    c.policies(&mut tx)?;
    c.functions(&mut tx)?;
    c.triggers(&mut tx)?;
    tx.rollback().map_err(|e| query_error(&e))?;
    Ok(c.finish(allow))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyDef {
    cmd: String,
    permissive: bool,
    roles: Vec<String>,
    using: String,
    check: String,
}

struct Comparison<'a> {
    objs: &'a [(Object, String)],
    revoked: &'a BTreeSet<String>,
    live: BTreeMap<String, u32>,
    shadow: BTreeMap<String, (String, u32)>,
    governed: BTreeSet<String>,
    scratch: BTreeMap<Object, String>,
    invalid: BTreeMap<Object, String>,
    schemas: Vec<u32>,
    out: Drift,
    orphans: Vec<Finding>,
}

impl Comparison<'_> {
    fn found(&mut self, kind: DriftKind, object: String, detail: String) {
        self.out.findings.push(Finding { kind, object, detail });
    }

    fn shadow_tables(&mut self, tx: &mut Transaction<'_>) -> Result<(), String> {
        let mut tables = BTreeSet::new();
        for (o, _) in self.objs {
            match o {
                Object::Policy { table, .. } | Object::Rls(table) => {
                    tables.insert(table.clone());
                    self.governed.insert(table.clone());
                }
                Object::Trigger { table, .. } => {
                    tables.insert(table.clone());
                }
                _ => {}
            }
        }
        let mut used = BTreeSet::new();
        for (i, t) in tables.into_iter().enumerate() {
            let row = tx
                .query_one(
                    "SELECT to_regclass($1)::oid, (SELECT string_agg(format('%I %s', attname, format_type(atttypid, atttypmod)), ', ' ORDER BY attnum)
                       FROM pg_attribute WHERE attrelid = to_regclass($1) AND attnum > 0 AND NOT attisdropped)",
                    &[&t],
                )
                .map_err(|e| query_error(&e))?;
            let Some(oid) = row.get::<_, Option<u32>>(0) else {
                self.found(DriftKind::Missing, format!("table {t}"), "the spec governs it, but the database has no such table".into());
                continue;
            };
            let bare = t.rsplit_once('.').map_or(t.as_str(), |(_, b)| b).to_string();
            let name = if used.insert(bare.clone()) { bare } else { format!("demesne_shadow_{i}") };
            let cols: Option<String> = row.get(1);
            tx.batch_execute(&format!("CREATE TEMP TABLE {name} ({})", cols.unwrap_or_default())).map_err(|e| query_error(&e))?;
            let shadow_oid: u32 =
                tx.query_one(&format!("SELECT {}::regclass::oid", quote_literal(&format!("pg_temp.{name}"))), &[]).map_err(|e| query_error(&e))?.get(0);
            self.live.insert(t.clone(), oid);
            self.shadow.insert(t, (name, shadow_oid));
        }
        Ok(())
    }

    fn create_generated(&mut self, tx: &mut Transaction<'_>) {
        for (i, (o, stmt)) in self.objs.iter().enumerate() {
            let scratch = match o {
                Object::Function(sig) => {
                    let name = format!("pg_temp.demesne_fn_{i}");
                    self.scratch.insert(o.clone(), format!("{name}{}", arguments(sig)));
                    renamed(stmt, &name)
                }
                Object::Policy { table, .. } | Object::Trigger { table, .. } => {
                    self.shadow.get(table).and_then(|(name, _)| retarget(stmt, table, &format!("pg_temp.{name}")))
                }
                _ => None,
            };
            let Some(scratch) = scratch else { continue };
            if let Err(e) = attempt(tx, &scratch) {
                self.invalid.insert(o.clone(), e);
            }
        }
    }

    fn policies(&mut self, tx: &mut Transaction<'_>) -> Result<(), String> {
        let mut by_oid: BTreeMap<u32, (String, bool)> = self.live.iter().map(|(t, oid)| (*oid, (t.clone(), false))).collect();
        by_oid.extend(self.shadow.iter().map(|(t, (_, oid))| (*oid, (t.clone(), true))));
        let oids: Vec<u32> = by_oid.keys().copied().collect();
        let rows = tx
            .query(
                "SELECT pol.polrelid, pol.polname::text, pol.polcmd::text, pol.polpermissive,
                        ARRAY(SELECT CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r)::text END FROM unnest(pol.polroles) r ORDER BY 1),
                        coalesce(pg_get_expr(pol.polqual, pol.polrelid), ''), coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')
                   FROM pg_policy pol WHERE pol.polrelid = ANY($1)",
                &[&oids],
            )
            .map_err(|e| query_error(&e))?;
        let mut live = BTreeMap::new();
        let mut generated = BTreeMap::new();
        for row in rows {
            let Some((table, is_shadow)) = by_oid.get(&row.get::<_, u32>(0)) else { continue };
            let def =
                PolicyDef { cmd: command(&row.get::<_, String>(2)).into(), permissive: row.get(3), roles: row.get(4), using: row.get(5), check: row.get(6) };
            let side = if *is_shadow { &mut generated } else { &mut live };
            side.insert((table.clone(), row.get::<_, String>(1)), def);
        }
        let mut wanted = BTreeSet::new();
        for (o, _) in self.objs {
            let Object::Policy { table, name } = o else { continue };
            let key = (table.clone(), name.clone());
            wanted.insert(key.clone());
            let object = format!("policy {name} on {table}");
            if !self.live.contains_key(table) {
                continue;
            }
            if let Some(e) = self.invalid.get(o).cloned() {
                self.found(DriftKind::Invalid, object, format!("the generated policy does not compile against the live database: {e}"));
                continue;
            }
            match (live.get(&key), generated.get(&key)) {
                (None, _) => self.found(DriftKind::Missing, object, "generated but not live (apply it)".into()),
                (Some(l), Some(g)) if l != g => self.found(DriftKind::Changed, object, policy_change(l, g)),
                _ => self.out.policies += 1,
            }
        }
        for (table, name) in live.keys() {
            if self.governed.contains(table) && !wanted.contains(&(table.clone(), name.clone())) {
                self.orphans.push(Finding {
                    kind: DriftKind::Orphan,
                    object: format!("policy {name} on {table}"),
                    detail: "live on a governed table but not generated (remove it, or model it)".into(),
                });
            }
        }
        Ok(())
    }

    fn functions(&mut self, tx: &mut Transaction<'_>) -> Result<(), String> {
        let mut schemas = BTreeSet::new();
        let mut generated_oids: Vec<u32> = Vec::new();
        for (o, _) in self.objs {
            let Object::Function(sig) = o else { continue };
            let object = format!("function {sig}");
            let row = tx.query_one("SELECT to_regnamespace($1)::oid, to_regprocedure($2)::oid", &[&schema_of(sig), sig]).map_err(|e| query_error(&e))?;
            schemas.extend(row.get::<_, Option<u32>>(0));
            let live_oid = row.get::<_, Option<u32>>(1);
            generated_oids.extend(live_oid);
            if let Some(e) = self.invalid.get(o).cloned() {
                self.found(DriftKind::Invalid, object, format!("the generated function does not compile against the live database: {e}"));
                continue;
            }
            let Some(live_oid) = live_oid else {
                self.found(DriftKind::Missing, object, "generated but not live (apply it)".into());
                continue;
            };
            let open = self.revoked.contains(sig)
                && tx.query_one("SELECT has_function_privilege('public', $1::oid, 'EXECUTE')", &[&live_oid]).map_err(|e| query_error(&e))?.get::<_, bool>(0);
            if open {
                self.found(DriftKind::Changed, object.clone(), "PUBLIC may execute it, and the generated SQL revokes that (re-apply it)".into());
            }
            let scratch = self.scratch.get(o).cloned().unwrap_or_default();
            let defs = tx
                .query_one("SELECT pg_get_functiondef($1), pg_get_functiondef(to_regprocedure($2)::oid)", &[&live_oid, &scratch])
                .map_err(|e| query_error(&e))?;
            let (live, generated): (String, String) = (defs.get(0), defs.get(1));
            match first_difference(after_name(&live), after_name(&generated)) {
                Some((l, g)) => {
                    self.found(DriftKind::Changed, object, format!("its live definition is not the generated one (re-apply it): live `{l}`, generated `{g}`"));
                }
                None if !open => self.out.functions += 1,
                None => {}
            }
        }
        self.schemas = schemas.into_iter().collect();
        let rows = tx
            .query(
                "SELECT p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace = ANY($1) AND NOT (p.oid = ANY($2)) ORDER BY 1",
                &[&self.schemas, &generated_oids],
            )
            .map_err(|e| query_error(&e))?;
        for row in rows {
            self.orphans.push(Finding {
                kind: DriftKind::Orphan,
                object: format!("function {}", row.get::<_, String>(0)),
                detail: "live in a definer schema but not generated (drop it, or allow it)".into(),
            });
        }
        Ok(())
    }

    fn triggers(&mut self, tx: &mut Transaction<'_>) -> Result<(), String> {
        let mut wanted = BTreeSet::new();
        for (o, _) in self.objs {
            let Object::Trigger { table, name } = o else { continue };
            wanted.insert((table.clone(), name.clone()));
            let object = format!("trigger {name} on {table}");
            let (Some(live_oid), Some((shadow, shadow_oid))) = (self.live.get(table).copied(), self.shadow.get(table).cloned()) else { continue };
            if let Some(e) = self.invalid.get(o).cloned() {
                self.found(DriftKind::Invalid, object, format!("the generated trigger does not compile against the live database: {e}"));
                continue;
            }
            let row = tx
                .query_one(
                    "SELECT (SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid = $1 AND tgname = $3 AND NOT tgisinternal),
                            (SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid = $2 AND tgname = $3),
                            $1::regclass::text",
                    &[&live_oid, &shadow_oid, name],
                )
                .map_err(|e| query_error(&e))?;
            let (live, generated, live_table): (Option<String>, Option<String>, String) = (row.get(0), row.get(1), row.get(2));
            let Some(live) = live else {
                self.found(DriftKind::Missing, object, "generated but not live (apply it)".into());
                continue;
            };
            let generated = generated.unwrap_or_default().replacen(&format!("pg_temp.{shadow}"), &live_table, 1);
            if live == generated {
                self.out.triggers += 1;
            } else {
                self.found(DriftKind::Changed, object, format!("live `{live}`, generated `{generated}`"));
            }
        }
        let by_oid: BTreeMap<u32, String> = self.live.iter().map(|(t, oid)| (*oid, t.clone())).collect();
        let oids: Vec<u32> = by_oid.keys().copied().collect();
        let rows = tx
            .query(
                "SELECT t.tgrelid, t.tgname::text FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
                  WHERE NOT t.tgisinternal AND t.tgrelid = ANY($1) AND p.pronamespace = ANY($2) ORDER BY 1, 2",
                &[&oids, &self.schemas],
            )
            .map_err(|e| query_error(&e))?;
        for row in rows {
            let (Some(table), name) = (by_oid.get(&row.get::<_, u32>(0)), row.get::<_, String>(1)) else { continue };
            if !wanted.contains(&(table.clone(), name.clone())) {
                self.orphans.push(Finding {
                    kind: DriftKind::Orphan,
                    object: format!("trigger {name} on {table}"),
                    detail: "live, calling a definer-schema function, but not generated (drop it, or allow it)".into(),
                });
            }
        }
        Ok(())
    }

    fn finish(mut self, allow: &[String]) -> Drift {
        let allowed: BTreeSet<&str> = allow.iter().map(String::as_str).collect();
        let orphaned: BTreeSet<String> = self.orphans.iter().map(|f| f.object.clone()).collect();
        self.out.findings.extend(self.orphans.into_iter().filter(|f| !allowed.contains(f.object.as_str())));
        self.out.findings.extend(allowed.into_iter().filter(|a| !orphaned.contains(*a)).map(|a| Finding {
            kind: DriftKind::Stale,
            object: a.to_string(),
            detail: "allowed as an orphan, but nothing live matches it (remove the entry)".into(),
        }));
        self.out
    }
}

fn attempt(tx: &mut Transaction<'_>, stmt: &str) -> Result<(), String> {
    let mut sp = tx.savepoint("demesne_diff").map_err(|e| query_error(&e))?;
    match sp.batch_execute(stmt) {
        Ok(()) => sp.commit().map_err(|e| query_error(&e)),
        Err(e) => Err(e.as_db_error().map_or_else(|| query_error(&e), |d| d.message().to_string())),
    }
}

fn command(polcmd: &str) -> &'static str {
    match polcmd {
        "r" => "SELECT",
        "a" => "INSERT",
        "w" => "UPDATE",
        "d" => "DELETE",
        _ => "ALL",
    }
}

fn policy_change(live: &PolicyDef, generated: &PolicyDef) -> String {
    let mut parts = Vec::new();
    if live.cmd != generated.cmd {
        parts.push(format!("command: live {}, generated {}", live.cmd, generated.cmd));
    }
    if live.permissive != generated.permissive {
        let kind = |p: bool| if p { "permissive" } else { "restrictive" };
        parts.push(format!("live {}, generated {}", kind(live.permissive), kind(generated.permissive)));
    }
    if live.roles != generated.roles {
        parts.push(format!("roles: live {}, generated {}", live.roles.join(", "), generated.roles.join(", ")));
    }
    if live.using != generated.using {
        parts.push(format!("USING: live `{}`, generated `{}`", live.using, generated.using));
    }
    if live.check != generated.check {
        parts.push(format!("WITH CHECK: live `{}`, generated `{}`", live.check, generated.check));
    }
    parts.join("; ")
}

fn schema_of(sig: &str) -> String {
    let name = sig.split('(').next().unwrap_or_default();
    name.rsplit_once('.').map(|(schema, _)| schema.to_string()).unwrap_or_default()
}

fn arguments(sig: &str) -> &str {
    sig.find('(').map_or("()", |k| &sig[k..])
}

fn renamed(stmt: &str, name: &str) -> Option<String> {
    let start = stmt.find("FUNCTION")? + "FUNCTION".len();
    let open = start + stmt[start..].find('(')?;
    Some(format!("{} {name}{}", &stmt[..start], &stmt[open..]))
}

fn retarget(stmt: &str, table: &str, to: &str) -> Option<String> {
    let needle = format!(" ON {table}");
    let mut from = 0;
    while let Some(k) = stmt[from..].find(&needle).map(|k| from + k) {
        let end = k + needle.len();
        if stmt[end..].chars().next().is_none_or(char::is_whitespace) {
            return Some(format!("{} ON {to}{}", &stmt[..k], &stmt[end..]));
        }
        from = end;
    }
    None
}

fn after_name(def: &str) -> &str {
    def.split_once('(').map_or(def, |(_, rest)| rest)
}

fn first_difference<'a>(live: &'a str, generated: &'a str) -> Option<(&'a str, &'a str)> {
    if live == generated {
        return None;
    }
    let mut l = live.lines();
    let mut g = generated.lines();
    loop {
        match (l.next(), g.next()) {
            (Some(a), Some(b)) if a == b => {}
            (a, b) => return Some((a.unwrap_or("<end>").trim(), b.unwrap_or("<end>").trim())),
        }
    }
}
