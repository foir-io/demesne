use crate::error::Error;
use demesne_gocompat::json::Value;
use demesne_model::SpecExt;
use demesne_runtime as rt;
use demesne_syntax::Spec;

fn s(v: &str) -> Value {
    Value::str(v)
}

fn strs<S: AsRef<str>>(v: &[S]) -> Value {
    Value::strings(v)
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Struct(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Projects the spec's session and claims contract into the shape `@foir/demesne` reads.
///
/// # Errors
///
/// The topology has no single root, or a level is unreachable from it.
pub fn claims(sp: &Spec) -> Result<Value, Error> {
    let session = sp.session();
    let contract = sp.claims_contract()?;
    let entries = sp.claims_contract_entries()?;
    let te: Vec<Value> = entries.iter().map(|e| obj(vec![("key", s(&e.key)), ("level", s(&e.level)), ("subjects", strs(&e.subjects))])).collect();
    let subs: Vec<Value> = sp.subjects.iter().map(|sub| obj(vec![("name", s(&sub.name)), ("identifies", s(sub.identifies()))])).collect();
    let levels: Vec<Value> =
        sp.levels().iter().map(|l| obj(vec![("name", s(&l.name)), ("claimKey", s(&l.claim_key())), ("virtual", Value::Bool(l.is_virtual))])).collect();
    Ok(obj(vec![
        ("setting", s(&session.setting)),
        ("cast", s(&session.cast)),
        ("role", s(&session.role)),
        ("contract", strs(&contract)),
        ("entries", Value::Array(te)),
        ("subjects", Value::Array(subs)),
        ("levels", Value::Array(levels)),
    ]))
}

#[must_use]
pub fn app_object(o: &rt::AppObjectSurface) -> Value {
    obj(vec![
        ("object", s(&o.object)),
        ("table", s(&o.table)),
        ("pk", s(&o.pk)),
        ("flatListFn", s(&o.flat_list_fn)),
        ("asyncCheckSQL", s(&o.async_check_sql)),
        ("editCheckSQL", s(&o.edit_check_sql)),
    ])
}

#[must_use]
pub fn pdp(p: &rt::Pdp) -> Value {
    let map = |m: &[(rt::Str, rt::Str)]| Value::Map(m.iter().map(|(k, v)| (k.to_string(), Value::str(v.as_ref()))).collect());
    obj(vec![("emitSite", s(&p.emit_site)), ("policy", map(&p.policy)), ("ungoverned", map(&p.ungoverned))])
}

#[must_use]
pub fn vocab(v: &rt::Vocabulary) -> Value {
    let presets: Vec<Value> = v.presets.iter().map(|p| obj(vec![("name", s(&p.name)), ("star", Value::Bool(p.star)), ("set", strs(&p.set))])).collect();
    let mut fields = vec![("name", s(&v.name)), ("permissions", strs(&v.permissions))];
    if !v.implications.is_empty() {
        let ims: Vec<Value> =
            v.implications.iter().map(|im| obj(vec![("perm", s(&im.perm)), ("star", Value::Bool(im.star)), ("set", strs(&im.set))])).collect();
        fields.push(("implications", Value::Array(ims)));
    }
    fields.push(("presets", Value::Array(presets)));
    fields.push(("rank", strs(&v.rank)));
    obj(fields)
}

#[must_use]
pub fn holds(r: &rt::HoldsResolver) -> Value {
    let mut fields = vec![
        ("assignments", s(&r.assignments)),
        ("kindCol", s(&r.kind_col)),
        ("kindVal", s(&r.kind_val)),
        ("subjectCol", s(&r.subject_col)),
        ("scopeCols", strs(&r.scope_cols)),
        ("revokedCol", s(&r.revoked_col)),
    ];
    if !r.plane.is_empty() {
        fields.push(("plane", s(&r.plane)));
        fields.push(("planeDepth", Value::Int(r.plane_depth)));
    }
    fields.extend([
        ("roleCol", s(&r.role_col)),
        ("rolesTable", s(&r.roles_table)),
        ("rolesId", s(&r.roles_id)),
        ("keyCol", s(&r.key_col)),
        ("permsCol", s(&r.perms_col)),
        ("vocab", vocab(&r.vocab)),
    ]);
    obj(fields)
}

#[must_use]
pub fn role_assign(r: &rt::RoleAssignmentSurface) -> Value {
    obj(vec![
        ("assignments", s(&r.assignments)),
        ("pk", s(&r.pk)),
        ("kindCol", s(&r.kind_col)),
        ("kindVal", s(&r.kind_val)),
        ("subjectCol", s(&r.subject_col)),
        ("roleCol", s(&r.role_col)),
        ("scopeCols", strs(&r.scope_cols)),
        ("revokedCol", s(&r.revoked_col)),
        ("grantedAtCol", s(&r.granted_at_col)),
        ("grantedByCol", s(&r.granted_by_col)),
        ("revokedByCol", s(&r.revoked_by_col)),
        ("extraCols", strs(&r.extra_cols)),
        ("rolesTable", s(&r.roles_table)),
        ("rolesId", s(&r.roles_id)),
        ("keyCol", s(&r.key_col)),
        ("permsCol", s(&r.perms_col)),
    ])
}

#[must_use]
pub fn grant(g: &rt::GrantSurface) -> Value {
    obj(vec![
        ("name", s(&g.name)),
        ("level", s(&g.level)),
        ("table", s(&g.table)),
        ("granteeCol", s(&g.grantee_col)),
        ("levelCol", s(&g.level_col)),
        ("activeCol", s(&g.active_col)),
        ("expiresCol", s(&g.expires_col)),
        ("pk", s(&g.pk)),
        ("grantedByCol", s(&g.granted_by_col)),
        ("revokedByCol", s(&g.revoked_by_col)),
        ("createdAtCol", s(&g.created_at_col)),
        ("extraCols", strs(&g.extra_cols)),
    ])
}

#[must_use]
pub fn res_access(r: &rt::ResourceAccessSurface) -> Value {
    let set = |xs: &[rt::Str]| Value::strings(xs);
    obj(vec![
        ("table", s(&r.table)),
        ("scopeCols", strs(&r.scope_cols)),
        ("modeCol", s(&r.mode_col)),
        ("pk", s(&r.pk)),
        ("readModes", set(&r.read_modes)),
        ("grantKinds", set(&r.grant_kinds)),
        ("aclTable", s(&r.acl_table)),
        ("recordCol", s(&r.record_col)),
        ("kindCol", s(&r.kind_col)),
        ("principalCol", s(&r.principal_col)),
        ("accessCol", s(&r.access_col)),
        ("discrimCol", s(&r.discrim_col)),
        ("discrimVal", s(&r.discrim_val)),
        ("accessorFn", s(&r.accessor_fn)),
        ("admitsFn", s(&r.admits_fn)),
        ("accessorsConditional", Value::Bool(r.conditional)),
    ])
}
