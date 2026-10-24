use crate::*;
use demesne_gocompat::json::Value;

fn st(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn list(v: &Value, k: &str) -> Vec<String> {
    v.get(k).map(Value::string_list).unwrap_or_default()
}

pub fn session(claims: &Value) -> Session {
    Session { setting: st(claims, "setting"), cast: st(claims, "cast"), role: st(claims, "role") }
}

pub fn contract(claims: &Value) -> Vec<String> {
    list(claims, "contract")
}

pub fn app_object(v: &Value) -> AppObjectSurface {
    AppObjectSurface {
        object: st(v, "object"),
        table: st(v, "table"),
        pk: st(v, "pk"),
        flat_list_fn: st(v, "flatListFn"),
        async_check_sql: st(v, "asyncCheckSQL"),
        edit_check_sql: st(v, "editCheckSQL"),
        checks: Vec::new(),
    }
}

pub fn vocabulary(v: &Value) -> Vocabulary {
    let entries = |k: &str| v.get(k).and_then(Value::as_array).unwrap_or(&[]).to_vec();
    Vocabulary {
        name: st(v, "name"),
        permissions: list(v, "permissions"),
        implications: entries("implications")
            .iter()
            .map(|im| Implication { perm: st(im, "perm"), set: list(im, "set"), star: im.get("star").and_then(Value::as_bool).unwrap_or(false) })
            .collect(),
        presets: entries("presets")
            .iter()
            .map(|p| Preset { name: st(p, "name"), level: st(p, "level"), set: list(p, "set"), star: p.get("star").and_then(Value::as_bool).unwrap_or(false) })
            .collect(),
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
        scope_nullable: Vec::new(),
        mode_col: st(v, "modeCol"),
        pk: st(v, "pk"),
        read_modes: list(v, "readModes").into_iter().collect(),
        grant_kinds: list(v, "grantKinds").into_iter().collect(),
        acl_table: st(v, "aclTable"),
        record_col: st(v, "recordCol"),
        kind_col: st(v, "kindCol"),
        principal_col: st(v, "principalCol"),
        access_col: st(v, "accessCol"),
        discrim_col: st(v, "discrimCol"),
        discrim_val: st(v, "discrimVal"),
        accessor_fn: st(v, "accessorFn"),
        conditional: v.get("accessorsConditional").and_then(Value::as_bool).unwrap_or(false),
        conditional_by: String::new(),
    }
}
