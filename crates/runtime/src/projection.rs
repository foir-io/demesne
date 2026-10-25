use crate::{
    AppObjectSurface, GrantSurface, HoldsResolver, Implication, LevelClaim, Pdp, Preset, Principal, ResourceAccessSurface, RoleAssignment,
    RoleAssignmentSurface, Session, Str, Strs, SubjectIdentity, Vocabulary, owned, owned_list,
};
use demesne_gocompat::json::Value;

fn st(v: &Value, k: &str) -> Str {
    owned(v.get(k).and_then(Value::as_str).unwrap_or(""))
}

fn list(v: &Value, k: &str) -> Strs {
    owned_list(v.get(k).map(Value::string_list).unwrap_or_default())
}

#[must_use]
pub fn session(claims: &Value) -> Session {
    Session { setting: st(claims, "setting"), cast: st(claims, "cast"), role: st(claims, "role") }
}

pub fn contract(claims: &Value) -> Vec<String> {
    claims.get("contract").map(Value::string_list).unwrap_or_default()
}

#[must_use]
pub fn subjects(claims: &Value) -> Vec<SubjectIdentity> {
    claims
        .get("subjects")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|s| SubjectIdentity { name: st(s, "name"), identifies: st(s, "identifies") })
        .collect()
}

#[must_use]
pub fn levels(claims: &Value) -> Vec<LevelClaim> {
    claims
        .get("levels")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|l| LevelClaim { name: st(l, "name"), claim_key: st(l, "claimKey"), is_virtual: l.get("virtual").and_then(Value::as_bool).unwrap_or(false) })
        .collect()
}

#[must_use]
pub fn principal(v: &Value) -> Principal {
    let scopes = v.get("scopes").map_or(&[][..], Value::entries).iter().filter_map(|(k, s)| s.as_str().map(|s| (k.clone(), s.to_string()))).collect();
    Principal { subject: st(v, "subject").into_owned(), id: st(v, "id").into_owned(), scopes }
}

#[must_use]
pub fn pdp(v: &Value) -> Pdp {
    let entries = |k: &str| {
        let mut e: Vec<(Str, Str)> =
            v.get(k).map_or(&[][..], Value::entries).iter().filter_map(|(p, perm)| perm.as_str().map(|perm| (owned(p.as_str()), owned(perm)))).collect();
        e.sort();
        e
    };
    Pdp { emit_site: st(v, "emitSite"), policy: entries("policy").into(), ungoverned: entries("ungoverned").into() }
}

#[must_use]
pub fn role_assignments(v: &Value) -> Vec<RoleAssignment> {
    v.as_array()
        .unwrap_or(&[])
        .iter()
        .map(|a| RoleAssignment {
            scope: a.get("scope").map(Value::string_list).unwrap_or_default(),
            role_key: st(a, "roleKey").into_owned(),
            permissions: a.get("permissions").map(Value::string_list).unwrap_or_default(),
        })
        .collect()
}

#[must_use]
pub fn app_object(v: &Value) -> AppObjectSurface {
    AppObjectSurface {
        object: st(v, "object"),
        table: st(v, "table"),
        pk: st(v, "pk"),
        flat_list_fn: st(v, "flatListFn"),
        async_check_sql: st(v, "asyncCheckSQL"),
        edit_check_sql: st(v, "editCheckSQL"),
        checks: std::borrow::Cow::Borrowed(&[]),
    }
}

#[must_use]
pub fn vocabulary(v: &Value) -> Vocabulary {
    let entries = |k: &str| v.get(k).and_then(Value::as_array).unwrap_or(&[]).to_vec();
    Vocabulary {
        name: st(v, "name"),
        permissions: list(v, "permissions"),
        implications: entries("implications")
            .iter()
            .map(|im| Implication { perm: st(im, "perm"), set: list(im, "set"), star: im.get("star").and_then(Value::as_bool).unwrap_or(false) })
            .collect::<Vec<_>>()
            .into(),
        presets: entries("presets")
            .iter()
            .map(|p| Preset { name: st(p, "name"), level: st(p, "level"), set: list(p, "set"), star: p.get("star").and_then(Value::as_bool).unwrap_or(false) })
            .collect::<Vec<_>>()
            .into(),
        rank: list(v, "rank"),
    }
}

pub fn holds_resolver(v: &Value) -> HoldsResolver {
    HoldsResolver {
        assignments: st(v, "assignments"),
        kind_col: st(v, "kindCol"),
        kind_val: st(v, "kindVal"),
        subject_col: st(v, "subjectCol"),
        scope_cols: list(v, "scopeCols"),
        revoked_col: st(v, "revokedCol"),
        plane: st(v, "plane"),
        plane_depth: v.get("planeDepth").and_then(Value::as_i64).unwrap_or(0),
        role_col: st(v, "roleCol"),
        roles_table: st(v, "rolesTable"),
        roles_id: st(v, "rolesId"),
        key_col: st(v, "keyCol"),
        perms_col: st(v, "permsCol"),
        vocab: v.get("vocab").map(vocabulary).unwrap_or_default(),
    }
}

#[must_use]
pub fn role_assignment(v: &Value) -> RoleAssignmentSurface {
    RoleAssignmentSurface {
        assignments: st(v, "assignments"),
        pk: st(v, "pk"),
        kind_col: st(v, "kindCol"),
        kind_val: st(v, "kindVal"),
        subject_col: st(v, "subjectCol"),
        role_col: st(v, "roleCol"),
        scope_cols: list(v, "scopeCols"),
        revoked_col: st(v, "revokedCol"),
        granted_at_col: st(v, "grantedAtCol"),
        granted_by_col: st(v, "grantedByCol"),
        revoked_by_col: st(v, "revokedByCol"),
        extra_cols: list(v, "extraCols"),
        roles_table: st(v, "rolesTable"),
        roles_id: st(v, "rolesId"),
        key_col: st(v, "keyCol"),
        perms_col: st(v, "permsCol"),
    }
}

#[must_use]
pub fn grant(v: &Value) -> GrantSurface {
    GrantSurface {
        name: st(v, "name"),
        level: st(v, "level"),
        table: st(v, "table"),
        grantee_col: st(v, "granteeCol"),
        level_col: st(v, "levelCol"),
        active_col: st(v, "activeCol"),
        expires_col: st(v, "expiresCol"),
        pk: st(v, "pk"),
        granted_by_col: st(v, "grantedByCol"),
        revoked_by_col: st(v, "revokedByCol"),
        created_at_col: st(v, "createdAtCol"),
        extra_cols: list(v, "extraCols"),
    }
}

pub fn resource_access(v: &Value) -> ResourceAccessSurface {
    ResourceAccessSurface {
        table: st(v, "table"),
        scope_cols: list(v, "scopeCols"),
        scope_nullable: std::borrow::Cow::Borrowed(&[]),
        mode_col: st(v, "modeCol"),
        pk: st(v, "pk"),
        read_modes: list(v, "readModes"),
        grant_kinds: list(v, "grantKinds"),
        acl_table: st(v, "aclTable"),
        record_col: st(v, "recordCol"),
        kind_col: st(v, "kindCol"),
        principal_col: st(v, "principalCol"),
        access_col: st(v, "accessCol"),
        discrim_col: st(v, "discrimCol"),
        discrim_val: st(v, "discrimVal"),
        accessor_fn: st(v, "accessorFn"),
        conditional: v.get("accessorsConditional").and_then(Value::as_bool).unwrap_or(false),
        conditional_by: Str::Borrowed(""),
    }
}
