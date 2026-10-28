#![doc = "demesne's runtime behind one JSON call, shared by its WebAssembly builds: `call` runs one runtime operation, its projection and inputs arriving as a JSON object and its result returning as `{\"ok\": value}` or `{\"error\": message}`, and `authorize` runs the PDP against the host's `holds` answer."]
#![forbid(unsafe_code)]

use demesne_gocompat::json::{self, Value};
use demesne_runtime::{self as rt, Decision, SqlArg, projection};
use std::collections::BTreeMap;

type R = Result<Value, String>;

struct Args<'a> {
    op: &'a str,
    members: &'a [(String, Value)],
}

impl<'a> Args<'a> {
    fn get(&self, k: &str) -> Option<&'a Value> {
        self.members.iter().find(|(key, _)| key == k).map(|(_, v)| v).filter(|v| !matches!(v, Value::Null))
    }

    fn wrong(&self, k: &str, want: &str) -> String {
        format!("demesne runtime: {}: {k} must be {want}", self.op)
    }

    fn text(&self, k: &str) -> Result<String, String> {
        self.get(k).and_then(Value::as_str).map(String::from).ok_or_else(|| self.wrong(k, "a string"))
    }

    fn optional_text(&self, k: &str) -> Result<Option<String>, String> {
        self.get(k).map(|v| v.as_str().map(String::from).ok_or_else(|| self.wrong(k, "a string"))).transpose()
    }

    fn list(&self, k: &str) -> Result<Vec<String>, String> {
        self.get(k).and_then(Value::as_strings).ok_or_else(|| self.wrong(k, "an array of strings"))
    }

    fn flag(&self, k: &str) -> Result<bool, String> {
        self.get(k).and_then(Value::as_bool).ok_or_else(|| self.wrong(k, "a boolean"))
    }

    fn str_map(&self, k: &str) -> Result<BTreeMap<String, String>, String> {
        self.get(k).and_then(Value::as_string_map).map(|m| m.into_iter().collect()).ok_or_else(|| self.wrong(k, "an object of strings"))
    }

    fn count(&self, k: &str) -> Result<usize, String> {
        self.get(k).and_then(Value::as_i64).and_then(|n| usize::try_from(n).ok()).ok_or_else(|| self.wrong(k, "a non-negative integer"))
    }

    fn decision(&self, k: &str) -> Result<Decision, String> {
        match self.text(k)?.as_str() {
            "allow" => Ok(Decision::Allow),
            "deny" => Ok(Decision::Deny),
            "ungoverned" => Ok(Decision::NotGoverned),
            _ => Err(self.wrong(k, r#""allow", "deny" or "ungoverned""#)),
        }
    }

    fn lifetime(&self) -> Result<rt::SettingLifetime, String> {
        Ok(if self.flag("local")? { rt::SettingLifetime::Transaction } else { rt::SettingLifetime::Session })
    }

    fn decode<T>(&self, k: &str, decode: impl FnOnce(&Value) -> Result<T, rt::Error>) -> Result<T, String> {
        decode(self.get(k).unwrap_or(&Value::Null)).map_err(|e| format!("demesne runtime: {}: {e}", self.op))
    }
}

fn arg(a: &SqlArg) -> Value {
    a.as_ref().map_or(Value::Null, |s| Value::Str(s.clone()))
}

fn stmt((sql, args): (String, Vec<SqlArg>)) -> Value {
    Value::Struct(vec![("sql".into(), Value::Str(sql)), ("args".into(), Value::Array(args.iter().map(arg).collect()))])
}

fn point(governed: bool, allow: bool) -> Decision {
    match (governed, allow) {
        (false, _) => Decision::NotGoverned,
        (true, true) => Decision::Allow,
        (true, false) => Decision::Deny,
    }
}
fn unknown(op: &str) -> String {
    format!("demesne runtime: no operation {}", demesne_gocompat::quote(op))
}

fn envelope(result: R) -> String {
    json::marshal(&match result {
        Ok(v) => Value::Struct(vec![("ok".into(), v)]),
        Err(e) => Value::Struct(vec![("error".into(), Value::Str(e))]),
    })
}

/// Runs the runtime operation `op` on `args`, a JSON object, and returns `{"ok": value}` or `{"error": message}` as JSON.
#[must_use]
pub fn call(op: &str, args: &str) -> String {
    envelope(json::parse(args).map_err(|e| format!("demesne runtime: {op}: {e}")).and_then(|v| {
        let members = v.as_object().ok_or_else(|| format!("demesne runtime: {op}: the arguments must be an object"))?;
        dispatch(&Args { op, members })
    }))
}

/// Returns the envelope `{"error": message}`, for a host that refuses a call before it reaches the runtime.
#[must_use]
pub fn refusal(message: &str) -> String {
    envelope(Err(message.to_string()))
}

/// Returns the PDP's decision for `procedure` under `pdp`, a JSON projection, asking `holds` whether the caller holds the
/// permission that governs it. The result is the same envelope as [`call`].
#[must_use]
pub fn authorize(pdp: &str, procedure: &str, holds: impl Fn(&str) -> bool) -> String {
    envelope(
        json::parse(pdp)
            .map_err(|e| format!("demesne runtime: authorize: {e}"))
            .and_then(|v| projection::pdp(&v).map_err(|e| format!("demesne runtime: authorize: {e}")))
            .map(|p| Value::Str(p.authorize(procedure, holds).to_string())),
    )
}

fn dispatch(a: &Args) -> R {
    match a.op.split_once('.').map_or(a.op, |(group, _)| group) {
        "claims" => claims(a),
        "pdp" => Ok(Value::Str(rt::compose_can(point(a.flag("pointGoverned")?, a.flag("pointAllow")?), a.decision("pdp")?).to_string())),
        "app" => app(a),
        "vocab" => vocab(a),
        "holds" => holds(a),
        "roles" => roles(a),
        "grants" => Ok(Value::Str(rt::touch_on_conflict(&a.list("bareKey")?, &a.list("nullableKey")?, &a.list("sets")?))),
        "roleAssignment" => role_assignment(a),
        "levelGrant" => level_grant(a),
        "resourceAccess" => resource_access(a),
        _ => Err(unknown(a.op)),
    }
}

fn mint(contract: &[String], values: &BTreeMap<String, String>, extra: Option<&BTreeMap<String, String>>) -> R {
    rt::mint_claims_values_with_extra(contract, values, extra).map(Value::Str).map_err(|e| e.message().to_string())
}

fn built(a: &Args) -> Result<BTreeMap<String, String>, String> {
    let (subjects, levels) = (a.decode("claims", projection::subjects)?, a.decode("claims", projection::levels)?);
    rt::build_claims(&subjects, &levels, &a.decode("principal", projection::principal)?).map_err(|e| e.message().to_string())
}

fn claims(a: &Args) -> R {
    let contract = || a.decode("claims", projection::contract);
    let session = || a.decode("claims", projection::session);
    match a.op {
        "claims.mint" => mint(&contract()?, &a.str_map("values")?, None),
        "claims.mintWithExtra" => mint(&a.list("contract")?, &a.str_map("values")?, Some(&a.str_map("extra")?)),
        "claims.build" => built(a).map(|m| Value::Struct(m.into_iter().map(|(k, v)| (k, Value::Str(v))).collect())),
        "claims.mintFor" => built(a).and_then(|m| mint(&contract()?, &m, None)),
        "claims.setRoleSQL" => Ok(Value::Str(session()?.set_role_sql(a.lifetime()?))),
        "claims.claimsSetSQL" => Ok(Value::Str(session()?.claims_set_sql(a.lifetime()?))),
        "claims.sessionSetupSQL" => Ok(Value::strings(&session()?.session_setup_sql(a.lifetime()?))),
        _ => Err(unknown(a.op)),
    }
}

fn app(a: &Args) -> R {
    let o = a.decode("object", projection::app_object)?;
    match a.op {
        "app.checkSQL" => Ok(Value::Str(o.check_sql())),
        "app.checkManySQL" => Ok(Value::Str(o.check_many_sql())),
        "app.listResourcesSQL" => Ok(Value::Str(o.list_resources_sql())),
        "app.checkEditSQL" => Ok(Value::str(o.check_edit_sql())),
        "app.listResourcesFastSQL" => Ok(Value::Str(o.list_resources_fast_sql())),
        _ => Err(unknown(a.op)),
    }
}

fn vocab(a: &Args) -> R {
    let v = a.decode("vocab", projection::vocabulary)?;
    let perms = |r: Result<Vec<String>, rt::Error>| r.map(|p| Value::strings(&p)).map_err(|e| e.message().to_string());
    match a.op {
        "vocab.impliedPermissions" => perms(v.implied_permissions(&a.text("perm")?)),
        "vocab.expandImplications" => perms(v.expand_implications(&a.list("perms")?)),
        "vocab.presetPermissions" => perms(v.preset_permissions(&a.text("name")?)),
        "vocab.rankOf" => {
            let rank = v.rank_of(&a.text("preset")?);
            let index = rank.map_or(0, |i| i64::try_from(i).expect("a vocabulary ranks fewer presets than i64 counts"));
            Ok(Value::Struct(vec![("index".into(), Value::Int(index)), ("ok".into(), Value::Bool(rank.is_some()))]))
        }
        "vocab.presetsAtOrAbove" => Ok(Value::strings(&v.presets_at_or_above(&a.text("threshold")?))),
        "vocab.capGrant" => {
            let cap = v.cap_grant(&a.list("held")?, &a.list("requested")?);
            Ok(Value::Struct(vec![
                ("allowed".into(), Value::Bool(cap.allowed)),
                ("unknown".into(), Value::strings(&cap.unknown)),
                ("excess".into(), Value::strings(&cap.excess)),
            ]))
        }
        _ => Err(unknown(a.op)),
    }
}

fn holds(a: &Args) -> R {
    let resolver = || a.decode("resolver", projection::holds_resolver);
    match a.op {
        "holds.planeDepth" => Ok(Value::Int(i64::try_from(resolver()?.plane_depth()).expect("a resolver has fewer scope columns than i64 counts"))),
        "holds.selectedScopeCols" => Ok(Value::strings(resolver()?.selected_scope_cols())),
        "holds.assignmentsSQL" => Ok(Value::Str(resolver()?.assignments_sql())),
        "holds.scopeContains" => Ok(Value::Bool(rt::scope_contains(&a.list("assignment")?, &a.list("query")?))),
        "holds.withinPlane" => Ok(Value::Bool(rt::within_plane(&a.list("scope")?, a.count("depth")?))),
        "holds.resolve" => resolver()?
            .resolve(&a.decode("assignments", projection::role_assignments)?, &a.list("scope")?)
            .map(|e| Value::strings(&e.permissions()))
            .map_err(|e| e.message().to_string()),
        _ => Err(unknown(a.op)),
    }
}

fn roles(a: &Args) -> R {
    match a.op {
        "roles.resolve" => Ok(Value::strings(&rt::resolve_roles(&a.decode("assignments", projection::role_assignments)?, &a.list("scope")?).roles())),
        "roles.new" => Ok(Value::strings(&rt::EffectiveRoles::new(&a.list("keys")?).roles())),
        _ => Err(unknown(a.op)),
    }
}

fn role_assignment(a: &Args) -> R {
    let s = a.decode("surface", projection::role_assignment)?;
    let insert = |touch: bool| -> R {
        let (id, subject, role, by) = (a.text("assignmentID")?, a.text("subjectID")?, a.text("roleID")?, a.text("grantedBy")?);
        let (extra, scope) = (a.str_map("extra")?, a.list("scope")?);
        Ok(stmt(if touch {
            s.assign_touch_insert(&id, &subject, &role, &scope, &by, &extra)
        } else {
            s.assign_insert(&id, &subject, &role, &scope, &by, &extra)
        }))
    };
    match a.op {
        "roleAssignment.assignInsert" => insert(false),
        "roleAssignment.assignTouchInsert" => insert(true),
        "roleAssignment.revokeSQL" => Ok(Value::Str(s.revoke_sql())),
        "roleAssignment.listForRoleSQL" => Ok(Value::Str(s.list_for_role_sql())),
        "roleAssignment.listForPrincipalSQL" => Ok(Value::Str(s.list_for_principal_sql())),
        _ => Err(unknown(a.op)),
    }
}

fn level_grant(a: &Args) -> R {
    let g = a.decode("surface", projection::grant)?;
    match a.op {
        "levelGrant.activePredicate" => Ok(Value::Str(g.active_predicate(&a.text("prefix")?))),
        "levelGrant.grantInsert" => {
            let (id, grantee, level, by) = (a.text("grantID")?, a.text("granteeID")?, a.text("levelID")?, a.text("grantedBy")?);
            Ok(stmt(g.grant_insert(&id, &grantee, &level, &by, a.optional_text("expiresAt")?, &a.str_map("extra")?)))
        }
        "levelGrant.revokeSQL" => Ok(Value::Str(g.revoke_sql())),
        "levelGrant.listSQL" => Ok(Value::Str(g.list_sql())),
        _ => Err(unknown(a.op)),
    }
}

fn resource_access(a: &Args) -> R {
    let r = a.decode("surface", projection::resource_access)?;
    let who = || -> Result<_, String> { Ok((a.text("resourceID")?, a.text("kind")?, a.text("principalID")?, a.text("access")?)) };
    match a.op {
        "resourceAccess.isReadMode" => Ok(Value::Bool(r.is_read_mode(&a.text("mode")?))),
        "resourceAccess.grantKindAllowed" => Ok(Value::Bool(r.grant_kind_allowed(&a.text("kind")?))),
        "resourceAccess.modeSQL" => Ok(Value::Str(r.mode_sql())),
        "resourceAccess.setVisibilitySQL" => Ok(Value::Str(r.set_visibility_sql())),
        "resourceAccess.grantInsert" => {
            let (id, kind, principal, access) = who()?;
            Ok(stmt(r.grant_insert(&a.list("scope")?, &id, &kind, &principal, &access)))
        }
        "resourceAccess.revokeDelete" => {
            let (id, kind, principal, access) = who()?;
            Ok(stmt(r.revoke_delete(&id, &kind, &principal, &access)))
        }
        "resourceAccess.listGrantsSQL" => Ok(Value::Str(r.list_grants_sql())),
        "resourceAccess.listGrantsArgs" => Ok(Value::Array(r.list_grants_args(&a.text("resourceID")?).iter().map(arg).collect())),
        "resourceAccess.accessorsSQL" => Ok(Value::Str(r.accessors_sql())),
        "resourceAccess.admitsSQL" => Ok(Value::Str(r.admits_sql().map_err(|e| e.to_string())?)),
        _ => Err(unknown(a.op)),
    }
}
