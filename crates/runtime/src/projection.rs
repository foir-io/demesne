use crate::{
    AppObjectSurface, Error, GrantSurface, HoldsResolver, Implication, LevelClaim, Pdp, Preset, Principal, ResourceAccessSurface, RoleAssignment,
    RoleAssignmentSurface, Session, Str, Strs, SubjectIdentity, Vocabulary, owned, owned_list,
};
use demesne_gocompat::json::Value;

struct Fields<'a> {
    members: &'a [(String, Value)],
    what: String,
}

impl<'a> Fields<'a> {
    fn of(v: &'a Value, what: impl Into<String>) -> Result<Self, Error> {
        let what = what.into();
        match v.as_object() {
            Some(members) => Ok(Fields { members, what }),
            None => Err(Error::input(format!("{what} must be an object"))),
        }
    }

    fn get(&self, k: &str) -> Option<&'a Value> {
        self.members.iter().find(|(key, _)| key == k).map(|(_, v)| v).filter(|v| !matches!(v, Value::Null))
    }

    fn wrong(&self, k: &str, want: &str) -> Error {
        Error::input(format!("{}.{k} must be {want}", self.what))
    }

    fn string(&self, k: &str) -> Result<String, Error> {
        self.get(k).and_then(Value::as_str).map(String::from).ok_or_else(|| self.wrong(k, "a string"))
    }

    fn str(&self, k: &str) -> Result<Str, Error> {
        self.string(k).map(owned)
    }

    fn optional_str(&self, k: &str) -> Result<Str, Error> {
        if self.get(k).is_none() {
            return Ok(Str::Borrowed(""));
        }
        self.str(k)
    }

    fn strings(&self, k: &str) -> Result<Vec<String>, Error> {
        self.get(k).and_then(Value::as_strings).ok_or_else(|| self.wrong(k, "an array of strings"))
    }

    fn strs(&self, k: &str) -> Result<Strs, Error> {
        self.strings(k).map(owned_list)
    }

    fn flag(&self, k: &str) -> Result<bool, Error> {
        self.get(k).and_then(Value::as_bool).ok_or_else(|| self.wrong(k, "a boolean"))
    }

    fn int(&self, k: &str) -> Result<i64, Error> {
        self.get(k).and_then(Value::as_i64).ok_or_else(|| self.wrong(k, "an integer"))
    }

    fn string_map(&self, k: &str) -> Result<Vec<(String, String)>, Error> {
        self.get(k).and_then(Value::as_string_map).ok_or_else(|| self.wrong(k, "an object of strings"))
    }

    fn objects<T>(&self, k: &str, decode: impl Fn(Fields<'a>) -> Result<T, Error>) -> Result<Vec<T>, Error> {
        let items = self.get(k).and_then(Value::as_array).ok_or_else(|| self.wrong(k, "an array"))?;
        items.iter().enumerate().map(|(i, v)| Fields::of(v, format!("{}.{k}[{i}]", self.what)).and_then(&decode)).collect()
    }

    fn optional_objects<T>(&self, k: &str, decode: impl Fn(Fields<'a>) -> Result<T, Error>) -> Result<Vec<T>, Error> {
        if self.get(k).is_none() {
            return Ok(Vec::new());
        }
        self.objects(k, decode)
    }

    fn object(&self, k: &str) -> Result<Fields<'a>, Error> {
        Fields::of(self.get(k).unwrap_or(&Value::Null), format!("{}.{k}", self.what))
    }
}

/// Decodes the session settings from a claims projection.
///
/// # Errors
///
/// A claims projection with `setting`, `cast` or `role` missing or not a string.
pub fn session(claims: &Value) -> Result<Session, Error> {
    let c = Fields::of(claims, "claims")?;
    Ok(Session { setting: c.str("setting")?, cast: c.str("cast")?, role: c.str("role")? })
}

/// Decodes the claims contract, the claim keys a minted token carries, from a claims projection.
///
/// # Errors
///
/// A claims projection whose `contract` is missing or not an array of strings.
pub fn contract(claims: &Value) -> Result<Vec<String>, Error> {
    Fields::of(claims, "claims")?.strings("contract")
}

/// Decodes the subjects and the claim each identifies from a claims projection.
///
/// # Errors
///
/// A claims projection whose `subjects` is missing, or holds an entry with a field missing or of the wrong type.
pub fn subjects(claims: &Value) -> Result<Vec<SubjectIdentity>, Error> {
    Fields::of(claims, "claims")?.objects("subjects", |s| Ok(SubjectIdentity { name: s.str("name")?, identifies: s.str("identifies")? }))
}

/// Decodes the topology levels and their scope claims from a claims projection.
///
/// # Errors
///
/// A claims projection whose `levels` is missing, or holds an entry with a field missing or of the wrong type.
pub fn levels(claims: &Value) -> Result<Vec<LevelClaim>, Error> {
    Fields::of(claims, "claims")?.objects("levels", |l| Ok(LevelClaim { name: l.str("name")?, claim_key: l.str("claimKey")?, is_virtual: l.flag("virtual")? }))
}

/// Decodes a principal: its subject, its identity and its scope at each level.
///
/// # Errors
///
/// A principal with `subject` or `id` missing or not a string, or `scopes` not an object of strings.
pub fn principal(v: &Value) -> Result<Principal, Error> {
    let p = Fields::of(v, "principal")?;
    Ok(Principal { subject: p.string("subject")?, id: p.string("id")?, scopes: p.string_map("scopes")?.into_iter().collect() })
}

/// Decodes a PDP projection: the permission that governs each procedure, and the procedures left ungoverned.
///
/// # Errors
///
/// A PDP projection with `emitSite` missing or not a string, or `policy` or `ungoverned` not an object of strings.
pub fn pdp(v: &Value) -> Result<Pdp, Error> {
    let p = Fields::of(v, "pdp")?;
    let entries = |k: &str| -> Result<Vec<(Str, Str)>, Error> {
        let mut e: Vec<(Str, Str)> = p.string_map(k)?.into_iter().map(|(proc, perm)| (owned(proc), owned(perm))).collect();
        e.sort();
        Ok(e)
    };
    Ok(Pdp { emit_site: p.str("emitSite")?, policy: entries("policy")?.into(), ungoverned: entries("ungoverned")?.into() })
}

/// Decodes a list of role assignments: each one's scope, role key and the permissions the role grants.
///
/// # Errors
///
/// Anything but an array, or an assignment with a field missing or of the wrong type.
pub fn role_assignments(v: &Value) -> Result<Vec<RoleAssignment>, Error> {
    let items = v.as_array().ok_or_else(|| Error::input("assignments must be an array"))?;
    items
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let a = Fields::of(a, format!("assignments[{i}]"))?;
            Ok(RoleAssignment { scope: a.strings("scope")?, role_key: a.string("roleKey")?, permissions: a.strings("permissions")? })
        })
        .collect()
}

/// Decodes one object's app surface.
///
/// # Errors
///
/// An app surface with a field missing or of the wrong type.
pub fn app_object(v: &Value) -> Result<AppObjectSurface, Error> {
    let o = Fields::of(v, "appObject")?;
    Ok(AppObjectSurface {
        object: o.str("object")?,
        table: o.str("table")?,
        pk: o.str("pk")?,
        flat_list_fn: o.str("flatListFn")?,
        async_check_sql: o.str("asyncCheckSQL")?,
        edit_check_sql: o.str("editCheckSQL")?,
        checks: std::borrow::Cow::Borrowed(&[]),
    })
}

/// Decodes a vocabulary: its permissions, implications, presets and rank.
///
/// # Errors
///
/// A vocabulary with a field missing or of the wrong type.
pub fn vocabulary(v: &Value) -> Result<Vocabulary, Error> {
    vocabulary_fields(&Fields::of(v, "vocabulary")?)
}

fn vocabulary_fields(v: &Fields<'_>) -> Result<Vocabulary, Error> {
    Ok(Vocabulary {
        name: v.str("name")?,
        permissions: v.strs("permissions")?,
        implications: v.optional_objects("implications", |im| Ok(Implication { perm: im.str("perm")?, set: im.strs("set")?, star: im.flag("star")? }))?.into(),
        presets: v
            .objects("presets", |p| Ok(Preset { name: p.str("name")?, level: p.optional_str("level")?, set: p.strs("set")?, star: p.flag("star")? }))?
            .into(),
        rank: v.strs("rank")?,
    })
}

/// Decodes the resolver that reads a rolestore's assignments and the permissions their roles grant.
///
/// # Errors
///
/// A resolver with a field missing or of the wrong type, including a `plane` without its `planeDepth`.
pub fn holds_resolver(v: &Value) -> Result<HoldsResolver, Error> {
    let r = Fields::of(v, "holdsResolver")?;
    let plane = r.optional_str("plane")?;
    let plane_depth = if plane.is_empty() { 0 } else { r.int("planeDepth")? };
    Ok(HoldsResolver {
        assignments: r.str("assignments")?,
        kind_col: r.str("kindCol")?,
        kind_val: r.str("kindVal")?,
        subject_col: r.str("subjectCol")?,
        scope_cols: r.strs("scopeCols")?,
        revoked_col: r.str("revokedCol")?,
        plane,
        plane_depth,
        role_col: r.str("roleCol")?,
        roles_table: r.str("rolesTable")?,
        roles_id: r.str("rolesId")?,
        key_col: r.str("keyCol")?,
        perms_col: r.str("permsCol")?,
        vocab: vocabulary_fields(&r.object("vocab")?)?,
    })
}

/// Decodes the surface that writes and lists a rolestore's role assignments.
///
/// # Errors
///
/// A surface with a field missing or of the wrong type.
pub fn role_assignment(v: &Value) -> Result<RoleAssignmentSurface, Error> {
    let s = Fields::of(v, "roleAssignmentSurface")?;
    Ok(RoleAssignmentSurface {
        assignments: s.str("assignments")?,
        pk: s.str("pk")?,
        kind_col: s.str("kindCol")?,
        kind_val: s.str("kindVal")?,
        subject_col: s.str("subjectCol")?,
        role_col: s.str("roleCol")?,
        scope_cols: s.strs("scopeCols")?,
        revoked_col: s.str("revokedCol")?,
        granted_at_col: s.str("grantedAtCol")?,
        granted_by_col: s.str("grantedByCol")?,
        revoked_by_col: s.str("revokedByCol")?,
        extra_cols: s.strs("extraCols")?,
        roles_table: s.str("rolesTable")?,
        roles_id: s.str("rolesId")?,
        key_col: s.str("keyCol")?,
        perms_col: s.str("permsCol")?,
    })
}

/// Decodes the surface that writes and lists one level grant.
///
/// # Errors
///
/// A surface with a field missing or of the wrong type.
pub fn grant(v: &Value) -> Result<GrantSurface, Error> {
    let g = Fields::of(v, "grantSurface")?;
    Ok(GrantSurface {
        name: g.str("name")?,
        level: g.str("level")?,
        table: g.str("table")?,
        grantee_col: g.str("granteeCol")?,
        level_col: g.str("levelCol")?,
        active_col: g.str("activeCol")?,
        expires_col: g.str("expiresCol")?,
        pk: g.str("pk")?,
        granted_by_col: g.str("grantedByCol")?,
        revoked_by_col: g.str("revokedByCol")?,
        created_at_col: g.str("createdAtCol")?,
        extra_cols: g.strs("extraCols")?,
    })
}

/// Decodes the surface that shares one object's rows and lists who can read them.
///
/// # Errors
///
/// A surface with a field missing or of the wrong type.
pub fn resource_access(v: &Value) -> Result<ResourceAccessSurface, Error> {
    let r = Fields::of(v, "resourceAccessSurface")?;
    Ok(ResourceAccessSurface {
        table: r.str("table")?,
        scope_cols: r.strs("scopeCols")?,
        scope_nullable: std::borrow::Cow::Borrowed(&[]),
        mode_col: r.str("modeCol")?,
        pk: r.str("pk")?,
        read_modes: r.strs("readModes")?,
        grant_kinds: r.strs("grantKinds")?,
        acl_table: r.str("aclTable")?,
        record_col: r.str("recordCol")?,
        kind_col: r.str("kindCol")?,
        principal_col: r.str("principalCol")?,
        access_col: r.str("accessCol")?,
        discrim_col: r.str("discrimCol")?,
        discrim_val: r.str("discrimVal")?,
        accessor_fn: r.str("accessorFn")?,
        admits_fn: r.str("admitsFn")?,
        conditional: r.flag("accessorsConditional")?,
        conditional_by: Str::Borrowed(""),
    })
}
