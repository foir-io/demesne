use demesne_gocompat::json::{self, Value};
use demesne_runtime::{self as rt, RoleAssignment, SqlArg, projection};
use std::collections::BTreeMap;

fn s(x: &str) -> Value {
    Value::str(x)
}

fn args(a: &[SqlArg]) -> Value {
    Value::Array(a.iter().map(|x| x.as_ref().map_or(Value::Null, Value::str)).collect())
}

fn stmt((sql, a): (String, Vec<SqlArg>)) -> Value {
    Value::Map(vec![("sql".into(), Value::Str(sql)), ("args".into(), args(&a))])
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.map(|v| v.as_string_map().unwrap_or_else(|| panic!("not an object of strings: {v:?}")).into_iter().collect()).unwrap_or_default()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_strings().unwrap_or_else(|| panic!("not an array of strings: {v:?}"))
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or_else(|| panic!("missing {k}"))
}

fn text(v: &Value, k: &str) -> String {
    field(v, k).as_str().unwrap_or("").to_string()
}

fn run_case(proj: &Value, c: &Value) -> Value {
    let kind = text(c, "kind");
    let empty = Value::Map(Vec::new());
    let i = c.get("input").unwrap_or(&empty);
    let session = || projection::session(field(proj, "claims")).expect("the oracle projection decodes");
    let lifetime = || if i.get("local").and_then(Value::as_bool).unwrap_or(false) { rt::SettingLifetime::Transaction } else { rt::SettingLifetime::Session };
    let app = || {
        let name = text(i, "object");
        let objs = field(proj, "appSurface").as_array().expect("appSurface is an array");
        projection::app_object(objs.iter().find(|o| text(o, "object") == name).expect("the case names an object on the app surface"))
            .expect("the oracle projection decodes")
    };
    let holds = || match i.get("resolver").and_then(Value::as_str) {
        Some(r) => projection::holds_resolver(field(field(proj, "holdsResolvers"), r)).expect("the oracle projection decodes"),
        None => projection::holds_resolver(field(proj, "holdsResolver")).expect("the oracle projection decodes"),
    };
    if let Some(v) = writer_case(proj, &kind, i) {
        return v;
    }
    match kind.as_str() {
        "claims.claimsSetSQL" => Value::Str(session().claims_set_sql(lifetime())),
        "claims.setRoleSQL" => Value::Str(session().set_role_sql(lifetime())),
        "claims.sessionSetupSQL" => Value::strings(&session().session_setup_sql(lifetime())),
        "claims.mintWithExtra" => {
            let contract = projection::contract(field(proj, "claims")).expect("the oracle projection decodes");
            let extra = str_map(i.get("extra"));
            Value::Str(rt::mint_claims_values_with_extra(&contract, &str_map(i.get("values")), Some(&extra)).expect("the oracle mints only valid claims"))
        }
        "appSurface.checkSQL" => Value::Str(app().check_sql()),
        "appSurface.checkManySQL" => Value::Str(app().check_many_sql()),
        "appSurface.listResourcesSQL" => Value::Str(app().list_resources_sql()),
        "appSurface.checkEditSQL" => s(app().check_edit_sql()),
        "appSurface.listResourcesFastSQL" => Value::Str(app().list_resources_fast_sql()),
        "holds.assignmentsSQL" => Value::Str(holds().assignments_sql()),
        "holds.scopeContains" => Value::Bool(rt::scope_contains(&strings(field(i, "assignment")), &strings(field(i, "query")))),
        "holds.resolve" => {
            let asg: Vec<RoleAssignment> = field(i, "assignments")
                .as_array()
                .expect("assignments is an array")
                .iter()
                .map(|a| RoleAssignment { scope: strings(field(a, "scope")), role_key: text(a, "roleKey"), permissions: strings(field(a, "permissions")) })
                .collect();
            Value::strings(&holds().resolve(&asg, &strings(field(i, "scope"))).expect("the oracle resolves only valid scopes").permissions())
        }
        other => panic!("oracle: unknown case kind {other:?}"),
    }
}

fn writer_case(proj: &Value, kind: &str, i: &Value) -> Option<Value> {
    let ra = || projection::role_assignment(field(proj, "roleAssignment")).expect("the oracle projection decodes");
    let grant = || projection::grant(field(field(proj, "grants"), &text(i, "grant"))).expect("the oracle projection decodes");
    let acc = || projection::resource_access(field(field(proj, "resourceAccess"), &text(i, "object"))).expect("the oracle projection decodes");
    Some(match kind {
        "roleAssignment.revokeSQL" => Value::Str(ra().revoke_sql()),
        "roleAssignment.listForRoleSQL" => Value::Str(ra().list_for_role_sql()),
        "roleAssignment.listForPrincipalSQL" => Value::Str(ra().list_for_principal_sql()),
        "roleAssignment.assignInsert" | "roleAssignment.assignTouchInsert" => {
            let r = ra();
            let scope = strings(field(i, "scope"));
            let extra = str_map(i.get("extra"));
            let call = if kind.ends_with("TouchInsert") {
                r.assign_touch_insert(&text(i, "assignmentID"), &text(i, "subjectID"), &text(i, "roleID"), &scope, &text(i, "grantedBy"), &extra)
            } else {
                r.assign_insert(&text(i, "assignmentID"), &text(i, "subjectID"), &text(i, "roleID"), &scope, &text(i, "grantedBy"), &extra)
            };
            stmt(call)
        }
        "levelGrant.revokeSQL" => Value::Str(grant().revoke_sql()),
        "levelGrant.listSQL" => Value::Str(grant().list_sql()),
        "levelGrant.grantInsert" => stmt(grant().grant_insert(
            &text(i, "grantID"),
            &text(i, "granteeID"),
            &text(i, "levelID"),
            &text(i, "grantedBy"),
            Some(text(i, "expiresAt")),
            &str_map(i.get("extra")),
        )),
        "resourceAccess.modeSQL" => Value::Str(acc().mode_sql()),
        "resourceAccess.setVisibilitySQL" => Value::Str(acc().set_visibility_sql()),
        "resourceAccess.listGrantsSQL" => Value::Str(acc().list_grants_sql()),
        "resourceAccess.accessorsSQL" => Value::Str(acc().accessors_sql()),
        "resourceAccess.admitsSQL" => Value::Str(acc().admits_sql().expect("the oracle's resource-access objects read through a select policy")),
        "resourceAccess.listGrantsArgs" => args(&acc().list_grants_args("rec1")),
        "resourceAccess.grantInsert" => {
            stmt(acc().grant_insert(&strings(field(i, "scope")), &text(i, "resourceID"), &text(i, "kind"), &text(i, "principalID"), &text(i, "access")))
        }
        "resourceAccess.revokeDelete" => stmt(acc().revoke_delete(&text(i, "resourceID"), &text(i, "kind"), &text(i, "principalID"), &text(i, "access"))),
        _ => return None,
    })
}

#[test]
fn rust_runtime_passes_the_committed_oracle() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../ts/packages/runtime/test/generated/oracle.json")).unwrap();
    let oracle = json::parse(&raw).unwrap();
    let mut total = 0;
    let mut failures = Vec::new();
    for (spec, entry) in oracle.as_object().expect("the oracle is an object") {
        let proj = field(entry, "projections");
        for (idx, c) in field(entry, "cases").as_array().unwrap().iter().enumerate() {
            total += 1;
            let got = json::marshal(&run_case(proj, c));
            let want = json::marshal(field(c, "expect"));
            if got != want {
                failures.push(format!("{spec} {} #{idx}: got {got} want {want}", text(c, "kind")));
            }
        }
    }
    assert!(failures.is_empty(), "{} of {total} oracle cases differ:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(total, 537, "the committed oracle carries 537 cases");
}
