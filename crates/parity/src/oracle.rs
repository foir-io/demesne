use demesne_emit_sql::Sql;
use demesne_emit_ts::projections;
use demesne_gocompat::json::Value;
use demesne_model::analysis::object_grant_edge;
use demesne_model::{SpecExt, SurfaceExt};
use demesne_runtime::{self as rt, HoldsResolver, RoleAssignment, SqlArg};
use demesne_syntax::Spec;
use std::collections::BTreeMap;

fn s(v: &str) -> Value {
    Value::str(v)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn case(kind: &str, input: Option<Value>, expect: Value) -> Value {
    let mut e = vec![("kind", s(kind)), ("expect", expect)];
    if let Some(i) = input {
        e.push(("input", i));
    }
    map(e)
}

fn args(a: &[SqlArg]) -> Value {
    Value::Array(a.iter().map(|x| x.as_ref().map(|v| Value::str(v)).unwrap_or(Value::Null)).collect())
}

fn stmt(sql: String, a: &[SqlArg]) -> Value {
    map(vec![("sql", Value::Str(sql)), ("args", args(a))])
}

fn canonical_scope(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("s{}", char::from_u32('1' as u32 + i as u32).unwrap())).collect()
}

fn canonical_extra(cols: &[String]) -> BTreeMap<String, String> {
    cols.iter().map(|c| (c.clone(), format!("x_{c}"))).collect()
}

fn str_map(m: &BTreeMap<String, String>) -> Value {
    Value::Map(m.iter().map(|(k, v)| (k.clone(), Value::str(v))).collect())
}

fn matrix_scopes(n: usize) -> Result<(Vec<Vec<String>>, Vec<Vec<String>>), String> {
    let ids = ["T1", "P1", "S1"];
    let alt = ["T2", "P2", "S2"];
    if n > 3 {
        return Err("panic".into());
    }
    let mut assign = Vec::new();
    for k in 0..=n {
        let mut a = vec![String::new(); n];
        for i in 0..k {
            a[i] = ids[i].to_string();
        }
        assign.push(a);
    }
    let mut query = vec![vec![String::new(); n]];
    for k in 1..=n {
        let mut q = vec![String::new(); n];
        for i in 0..k {
            q[i] = ids[i].to_string();
        }
        query.push(q);
    }
    for k in 1..=n {
        let mut q: Vec<String> = ids[..n].iter().map(|x| x.to_string()).collect();
        q[k - 1] = alt[k - 1].to_string();
        query.push(q);
    }
    Ok((assign, query))
}

fn matrix_perm_sets(v: &rt::Vocabulary) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |set: Vec<String>| {
        if seen.insert(set.join("|")) {
            out.push(set);
        }
    };
    for im in &v.implications {
        add(vec![im.perm.clone()]);
    }
    if let (Some(first), Some(last)) = (v.permissions.first(), v.permissions.last()) {
        add(vec![first.clone()]);
        add(vec![first.clone(), last.clone()]);
    }
    add(vec!["totally:madeup".into()]);
    out
}

fn holds_matrix_cases(hr: &HoldsResolver, resolver: &str) -> Result<Vec<Value>, String> {
    if hr.perms_col.is_empty() {
        return Ok(Vec::new());
    }
    let (assign, query) = matrix_scopes(hr.scope_cols.len())?;
    let mut out = Vec::new();
    if resolver.is_empty() {
        for a in &assign {
            for q in &query {
                out.push(case(
                    "holds.scopeContains",
                    Some(map(vec![("assignment", Value::strings(a)), ("query", Value::strings(q))])),
                    Value::Bool(rt::scope_contains(a, q)),
                ));
            }
        }
    }
    for perms in matrix_perm_sets(hr.vocabulary()) {
        for a in &assign {
            for q in &query {
                let asg = [RoleAssignment { scope: a.clone(), role_key: String::new(), permissions: perms.clone() }];
                let eff = hr.resolve(&asg, q).map_err(|e| e.to_string())?;
                let mut input = vec![
                    (
                        "assignments",
                        Value::Array(vec![map(vec![
                            ("scope", Value::strings(a)),
                            ("roleKey", s("")),
                            ("permissions", Value::strings(&perms)),
                        ])]),
                    ),
                    ("scope", Value::strings(q)),
                ];
                if !resolver.is_empty() {
                    input.push(("resolver", s(resolver)));
                }
                out.push(case("holds.resolve", Some(map(input)), Value::strings(&eff.permissions())));
            }
        }
    }
    Ok(out)
}

pub fn build_oracle_entry(sp: &Spec) -> Result<Value, String> {
    let mut proj: Vec<(String, Value)> = Vec::new();
    let mut cases: Vec<Value> = Vec::new();
    proj.push(("claims".into(), projections::claims(sp)?));
    let session = sp.session();
    for local in [true, false] {
        let input = || Some(map(vec![("local", Value::Bool(local))]));
        cases.push(case("claims.claimsSetSQL", input(), Value::Str(session.claims_set_sql(local))));
        cases.push(case("claims.setRoleSQL", input(), Value::Str(session.set_role_sql(local))));
        cases.push(case("claims.sessionSetupSQL", input(), Value::strings(&session.session_setup_sql(local))));
    }
    let contract = sp.claims_contract()?;
    let vals: BTreeMap<String, String> = contract.iter().map(|k| (k.clone(), format!("v_{k}"))).collect();
    let extra: BTreeMap<String, String> = [("role".to_string(), "authenticated".to_string())].into();
    let minted = rt::mint_claims_values_with_extra(&contract, &vals, Some(&extra)).map_err(|e| e.to_string())?;
    cases.push(case(
        "claims.mintWithExtra",
        Some(map(vec![("values", str_map(&vals)), ("extra", str_map(&extra))])),
        Value::Str(minted),
    ));
    if let Ok(surf) = Sql::new(sp).emit_app_surface() {
        let mut objs = Vec::new();
        for o in &surf.objects {
            objs.push(projections::app_object(o));
            let input = || Some(map(vec![("object", s(&o.object))]));
            cases.push(case("appSurface.checkSQL", input(), Value::Str(o.check_sql())));
            cases.push(case("appSurface.checkManySQL", input(), Value::Str(o.check_many_sql())));
            cases.push(case("appSurface.listResourcesSQL", input(), Value::Str(o.list_resources_sql())));
            cases.push(case("appSurface.checkEditSQL", input(), s(o.check_edit_sql())));
            cases.push(case("appSurface.listResourcesFastSQL", input(), Value::Str(o.list_resources_fast_sql())));
        }
        proj.push(("appSurface".into(), Value::Array(objs)));
    }
    if !sp.role_stores.is_empty() {
        let hr = sp.holds_resolver("")?;
        proj.push(("holdsResolver".into(), projections::holds(&hr)));
        cases.push(case("holds.assignmentsSQL", None, Value::Str(hr.assignments_sql())));
        cases.extend(holds_matrix_cases(&hr, "")?);
        if sp.role_stores.len() >= 2 {
            let mut by_name: Vec<(String, Value)> = Vec::new();
            for (i, rs) in sp.role_stores.iter().enumerate() {
                let r = sp.holds_resolver(&rs.name)?;
                by_name.retain(|(k, _)| k != &rs.name);
                by_name.push((rs.name.clone(), projections::holds(&r)));
                if i == 0 {
                    continue;
                }
                cases.push(case("holds.assignmentsSQL", Some(map(vec![("resolver", s(&rs.name))])), Value::Str(r.assignments_sql())));
                cases.extend(holds_matrix_cases(&r, &rs.name)?);
            }
            proj.push(("holdsResolvers".into(), Value::Map(by_name)));
        }
        let ra = sp.role_assignment_surface("")?;
        proj.push(("roleAssignment".into(), projections::role_assign(&ra)));
        let scope = canonical_scope(ra.scope_cols.len());
        let extra = canonical_extra(&ra.extra_cols);
        let assign_in = map(vec![
            ("assignmentID", s("a1")),
            ("subjectID", s("u1")),
            ("roleID", s("r1")),
            ("scope", Value::strings(&scope)),
            ("grantedBy", s("g1")),
            ("extra", str_map(&extra)),
        ]);
        let (isql, iargs) = ra.assign_insert("a1", "u1", "r1", &scope, "g1", &extra);
        let (tsql, targs) = ra.assign_touch_insert("a1", "u1", "r1", &scope, "g1", &extra);
        cases.push(case("roleAssignment.revokeSQL", None, Value::Str(ra.revoke_sql())));
        cases.push(case("roleAssignment.listForRoleSQL", None, Value::Str(ra.list_for_role_sql())));
        cases.push(case("roleAssignment.listForPrincipalSQL", None, Value::Str(ra.list_for_principal_sql())));
        cases.push(case("roleAssignment.assignInsert", Some(assign_in.clone()), stmt(isql, &iargs)));
        cases.push(case("roleAssignment.assignTouchInsert", Some(assign_in), stmt(tsql, &targs)));
    }
    if !sp.grants.is_empty() {
        let mut gm: Vec<(String, Value)> = Vec::new();
        for gd in &sp.grants {
            let g = sp.grant_surface(&gd.name)?;
            gm.retain(|(k, _)| k != &gd.name);
            gm.push((gd.name.clone(), projections::grant(&g)));
            let extra = canonical_extra(&g.extra_cols);
            let grant_in = map(vec![
                ("grant", s(&gd.name)),
                ("grantID", s("g1")),
                ("granteeID", s("u1")),
                ("levelID", s("l1")),
                ("grantedBy", s("gb1")),
                ("expiresAt", s("2030-01-01T00:00:00Z")),
                ("extra", str_map(&extra)),
            ]);
            let (gsql, gargs) = g.grant_insert("g1", "u1", "l1", "gb1", Some("2030-01-01T00:00:00Z".into()), &extra);
            let gin = || Some(map(vec![("grant", s(&gd.name))]));
            cases.push(case("levelGrant.revokeSQL", gin(), Value::Str(g.revoke_sql())));
            cases.push(case("levelGrant.listSQL", gin(), Value::Str(g.list_sql())));
            cases.push(case("levelGrant.grantInsert", Some(grant_in), stmt(gsql, &gargs)));
        }
        proj.push(("grants".into(), Value::Map(gm)));
    }
    let mut ram: Vec<(String, Value)> = Vec::new();
    for o in &sp.objects {
        if object_grant_edge(o).is_none() {
            continue;
        }
        let r = sp.conditional_resource_access_surface(&o.name)?;
        ram.retain(|(k, _)| k != &o.name);
        ram.push((o.name.clone(), projections::res_access(&r)));
        let obj_in = || Some(map(vec![("object", s(&o.name))]));
        let scope = canonical_scope(r.scope_cols.len());
        let (gsql, gargs) = r.grant_insert(&scope, "rec1", "k1", "p1", "read");
        let (dsql, dargs) = r.revoke_delete("rec1", "k1", "p1", "read");
        cases.push(case("resourceAccess.modeSQL", obj_in(), Value::Str(r.mode_sql())));
        cases.push(case("resourceAccess.setVisibilitySQL", obj_in(), Value::Str(r.set_visibility_sql())));
        cases.push(case("resourceAccess.listGrantsSQL", obj_in(), Value::Str(r.list_grants_sql())));
        cases.push(case("resourceAccess.accessorsSQL", obj_in(), Value::Str(r.accessors_sql())));
        cases.push(case("resourceAccess.listGrantsArgs", obj_in(), args(&r.list_grants_args("rec1"))));
        cases.push(case(
            "resourceAccess.grantInsert",
            Some(map(vec![
                ("object", s(&o.name)),
                ("scope", Value::strings(&scope)),
                ("resourceID", s("rec1")),
                ("kind", s("k1")),
                ("principalID", s("p1")),
                ("access", s("read")),
            ])),
            stmt(gsql, &gargs),
        ));
        cases.push(case(
            "resourceAccess.revokeDelete",
            Some(map(vec![
                ("object", s(&o.name)),
                ("resourceID", s("rec1")),
                ("kind", s("k1")),
                ("principalID", s("p1")),
                ("access", s("read")),
            ])),
            stmt(dsql, &dargs),
        ));
    }
    if !ram.is_empty() {
        proj.push(("resourceAccess".into(), Value::Map(ram)));
    }
    Ok(Value::Map(vec![("projections".into(), Value::Map(proj)), ("cases".into(), Value::Array(cases))]))
}
