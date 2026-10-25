#![doc = "demesne's runtime as WebAssembly, for `@foir/demesne`. `call` runs one runtime operation: its projection and inputs arrive as a JSON object, and the result returns as `{\"ok\": value}` or `{\"error\": message}`. `authorize` runs the PDP against a JavaScript `holds` callback."]

use demesne_gocompat::json::{self, Value};
use demesne_runtime::{self as rt, Decision, SqlArg, projection};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

type R = Result<Value, String>;

static NULL: Value = Value::Null;

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&NULL)
}

fn text(v: &Value, k: &str) -> String {
    field(v, k).as_str().unwrap_or_default().to_string()
}

fn list(v: &Value, k: &str) -> Vec<String> {
    field(v, k).string_list()
}

fn flag(v: &Value, k: &str) -> bool {
    field(v, k).as_bool().unwrap_or(false)
}

fn str_map(v: &Value, k: &str) -> BTreeMap<String, String> {
    field(v, k).entries().iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()
}

fn arg(a: &SqlArg) -> Value {
    a.as_ref().map_or(Value::Null, |s| Value::Str(s.clone()))
}

fn stmt((sql, args): (String, Vec<SqlArg>)) -> Value {
    Value::Struct(vec![("sql".into(), Value::Str(sql)), ("args".into(), Value::Array(args.iter().map(arg).collect()))])
}

fn decision(s: &str) -> Decision {
    match s {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => Decision::NotGoverned,
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
#[wasm_bindgen]
#[must_use]
pub fn call(op: &str, args: &str) -> String {
    envelope(json::parse(args).map_err(|e| format!("demesne runtime: {op}: {e}")).and_then(|a| dispatch(op, &a)))
}

#[wasm_bindgen]
extern "C" {
    pub type HoldsFn;

    #[wasm_bindgen(method, js_name = call)]
    fn invoke(this: &HoldsFn, ctx: &JsValue, perm: &str) -> JsValue;
}

/// Returns the PDP's decision for `procedure` under `pdp`, a JSON projection, asking `holds` whether the caller holds the permission that governs it; the result is the same envelope as [`call`].
#[wasm_bindgen]
#[must_use]
pub fn authorize(pdp: &str, procedure: &str, holds: &HoldsFn) -> String {
    envelope(
        json::parse(pdp)
            .map_err(|e| format!("demesne runtime: authorize: {e}"))
            .map(|v| Value::Str(projection::pdp(&v).authorize(procedure, |perm| holds.invoke(&JsValue::UNDEFINED, perm).is_truthy()).to_string())),
    )
}

fn dispatch(op: &str, a: &Value) -> R {
    match op.split_once('.').map_or(op, |(group, _)| group) {
        "claims" => claims(op, a),
        "pdp" => Ok(Value::Str(rt::compose_can(flag(a, "pointGoverned"), flag(a, "pointAllow"), decision(&text(a, "pdp"))).to_string())),
        "app" => app(op, a),
        "vocab" => vocab(op, a),
        "holds" => holds(op, a),
        "roles" => roles(op, a),
        "grants" => Ok(Value::Str(rt::touch_on_conflict(&list(a, "bareKey"), &list(a, "nullableKey"), &list(a, "sets")))),
        "roleAssignment" => role_assignment(op, a),
        "levelGrant" => level_grant(op, a),
        "resourceAccess" => resource_access(op, a),
        _ => Err(unknown(op)),
    }
}

fn mint(contract: &[String], values: &BTreeMap<String, String>, extra: Option<&BTreeMap<String, String>>) -> R {
    rt::mint_claims_values_with_extra(contract, values, extra).map(Value::Str).map_err(|e| e.message().to_string())
}

fn built(claims: &Value, a: &Value) -> Result<BTreeMap<String, String>, String> {
    rt::build_claims(&projection::subjects(claims), &projection::levels(claims), &projection::principal(field(a, "principal")))
        .map_err(|e| e.message().to_string())
}

fn claims(op: &str, a: &Value) -> R {
    let c = field(a, "claims");
    let session = projection::session(c);
    let local = flag(a, "local");
    match op {
        "claims.mint" => mint(&projection::contract(c), &str_map(a, "values"), None),
        "claims.mintWithExtra" => mint(&list(a, "contract"), &str_map(a, "values"), Some(&str_map(a, "extra"))),
        "claims.build" => built(c, a).map(|m| Value::Struct(m.into_iter().map(|(k, v)| (k, Value::Str(v))).collect())),
        "claims.mintFor" => built(c, a).and_then(|m| mint(&projection::contract(c), &m, None)),
        "claims.setRoleSQL" => Ok(Value::Str(session.set_role_sql(local))),
        "claims.claimsSetSQL" => Ok(Value::Str(session.claims_set_sql(local))),
        "claims.sessionSetupSQL" => Ok(Value::strings(&session.session_setup_sql(local))),
        _ => Err(unknown(op)),
    }
}

fn app(op: &str, a: &Value) -> R {
    let o = projection::app_object(field(a, "object"));
    match op {
        "app.checkSQL" => Ok(Value::Str(o.check_sql())),
        "app.checkManySQL" => Ok(Value::Str(o.check_many_sql())),
        "app.listResourcesSQL" => Ok(Value::Str(o.list_resources_sql())),
        "app.checkEditSQL" => Ok(Value::str(o.check_edit_sql())),
        "app.listResourcesFastSQL" => Ok(Value::Str(o.list_resources_fast_sql())),
        _ => Err(unknown(op)),
    }
}

fn vocab(op: &str, a: &Value) -> R {
    let v = projection::vocabulary(field(a, "vocab"));
    let perms = |r: Result<Vec<String>, rt::Error>| r.map(|p| Value::strings(&p)).map_err(|e| e.message().to_string());
    match op {
        "vocab.impliedPermissions" => perms(v.implied_permissions(&text(a, "perm"))),
        "vocab.expandImplications" => perms(v.expand_implications(&list(a, "perms"))),
        "vocab.presetPermissions" => perms(v.preset_permissions(&text(a, "name"))),
        "vocab.rankOf" => {
            let rank = v.rank_of(&text(a, "preset"));
            let index = rank.map_or(0, |i| i64::try_from(i).expect("a vocabulary ranks fewer presets than i64 counts"));
            Ok(Value::Struct(vec![("index".into(), Value::Int(index)), ("ok".into(), Value::Bool(rank.is_some()))]))
        }
        "vocab.presetsAtOrAbove" => Ok(Value::strings(&v.presets_at_or_above(&text(a, "threshold")))),
        "vocab.capGrant" => {
            let cap = v.cap_grant(&list(a, "held"), &list(a, "requested"));
            Ok(Value::Struct(vec![
                ("allowed".into(), Value::Bool(cap.allowed)),
                ("unknown".into(), Value::strings(&cap.unknown)),
                ("excess".into(), Value::strings(&cap.excess)),
            ]))
        }
        _ => Err(unknown(op)),
    }
}

fn holds(op: &str, a: &Value) -> R {
    let r = projection::holds_resolver(field(a, "resolver"));
    match op {
        "holds.planeDepth" => Ok(Value::Int(i64::try_from(r.plane_depth()).expect("a resolver has fewer scope columns than i64 counts"))),
        "holds.selectedScopeCols" => Ok(Value::strings(r.selected_scope_cols())),
        "holds.assignmentsSQL" => Ok(Value::Str(r.assignments_sql())),
        "holds.scopeContains" => Ok(Value::Bool(rt::scope_contains(&list(a, "assignment"), &list(a, "query")))),
        "holds.withinPlane" => {
            let depth = field(a, "depth").as_i64().map_or(0, |d| usize::try_from(d).unwrap_or(0));
            Ok(Value::Bool(rt::within_plane(&list(a, "scope"), depth)))
        }
        "holds.resolve" => r
            .resolve(&projection::role_assignments(field(a, "assignments")), &list(a, "scope"))
            .map(|e| Value::strings(&e.permissions()))
            .map_err(|e| e.message().to_string()),
        _ => Err(unknown(op)),
    }
}

fn roles(op: &str, a: &Value) -> R {
    match op {
        "roles.resolve" => Ok(Value::strings(&rt::resolve_roles(&projection::role_assignments(field(a, "assignments")), &list(a, "scope")).roles())),
        "roles.new" => Ok(Value::strings(&rt::EffectiveRoles::new(&list(a, "keys")).roles())),
        _ => Err(unknown(op)),
    }
}

fn role_assignment(op: &str, a: &Value) -> R {
    let s = projection::role_assignment(field(a, "surface"));
    let insert = |touch: bool| {
        let (id, subject, role, by) = (text(a, "assignmentID"), text(a, "subjectID"), text(a, "roleID"), text(a, "grantedBy"));
        let extra = str_map(a, "extra");
        let scope = list(a, "scope");
        stmt(if touch { s.assign_touch_insert(&id, &subject, &role, &scope, &by, &extra) } else { s.assign_insert(&id, &subject, &role, &scope, &by, &extra) })
    };
    match op {
        "roleAssignment.assignInsert" => Ok(insert(false)),
        "roleAssignment.assignTouchInsert" => Ok(insert(true)),
        "roleAssignment.revokeSQL" => Ok(Value::Str(s.revoke_sql())),
        "roleAssignment.listForRoleSQL" => Ok(Value::Str(s.list_for_role_sql())),
        "roleAssignment.listForPrincipalSQL" => Ok(Value::Str(s.list_for_principal_sql())),
        _ => Err(unknown(op)),
    }
}

fn level_grant(op: &str, a: &Value) -> R {
    let g = projection::grant(field(a, "surface"));
    match op {
        "levelGrant.activePredicate" => Ok(Value::Str(g.active_predicate(&text(a, "prefix")))),
        "levelGrant.grantInsert" => {
            let expires = field(a, "expiresAt").as_str().map(String::from);
            Ok(stmt(g.grant_insert(&text(a, "grantID"), &text(a, "granteeID"), &text(a, "levelID"), &text(a, "grantedBy"), expires, &str_map(a, "extra"))))
        }
        "levelGrant.revokeSQL" => Ok(Value::Str(g.revoke_sql())),
        "levelGrant.listSQL" => Ok(Value::Str(g.list_sql())),
        _ => Err(unknown(op)),
    }
}

fn resource_access(op: &str, a: &Value) -> R {
    let r = projection::resource_access(field(a, "surface"));
    let who = || (text(a, "resourceID"), text(a, "kind"), text(a, "principalID"), text(a, "access"));
    match op {
        "resourceAccess.isReadMode" => Ok(Value::Bool(r.is_read_mode(&text(a, "mode")))),
        "resourceAccess.grantKindAllowed" => Ok(Value::Bool(r.grant_kind_allowed(&text(a, "kind")))),
        "resourceAccess.modeSQL" => Ok(Value::Str(r.mode_sql())),
        "resourceAccess.setVisibilitySQL" => Ok(Value::Str(r.set_visibility_sql())),
        "resourceAccess.grantInsert" => {
            let (id, kind, principal, access) = who();
            Ok(stmt(r.grant_insert(&list(a, "scope"), &id, &kind, &principal, &access)))
        }
        "resourceAccess.revokeDelete" => {
            let (id, kind, principal, access) = who();
            Ok(stmt(r.revoke_delete(&id, &kind, &principal, &access)))
        }
        "resourceAccess.listGrantsSQL" => Ok(Value::Str(r.list_grants_sql())),
        "resourceAccess.listGrantsArgs" => Ok(Value::Array(r.list_grants_args(&text(a, "resourceID")).iter().map(arg).collect())),
        "resourceAccess.accessorsSQL" => Ok(Value::Str(r.accessors_sql())),
        _ => Err(unknown(op)),
    }
}
