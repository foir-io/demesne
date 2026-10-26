use crate::ConditionalExt;
use crate::SpecExt;
use crate::analysis::{grant_relation, object_grant_edge};
use crate::conditional::admission_names;
use crate::error::Error;
use crate::vocab::to_runtime;
use demesne_gocompat::quote;
use demesne_runtime as rt;
use demesne_syntax::{RoleStore, Spec};
use std::collections::BTreeMap;

fn s(o: Option<&str>) -> rt::Str {
    rt::owned(o.unwrap_or_default())
}

fn o(v: impl Into<String>) -> rt::Str {
    rt::owned(v)
}

fn l(v: &[String]) -> rt::Strs {
    rt::owned_list(v.iter().cloned())
}

fn pick_role_store<'a>(spec: &'a Spec, rolestore: &str) -> Option<&'a RoleStore> {
    if rolestore.is_empty() { spec.role_stores.first() } else { spec.role_stores.iter().find(|r| r.name == rolestore) }
}

fn no_store(ctx: &str, rolestore: &str) -> Error {
    Error::unplaced(if rolestore.is_empty() {
        format!("{ctx}: the spec declares no rolestore")
    } else {
        format!("{ctx}: no rolestore {} in the spec", quote(rolestore))
    })
}

pub trait SurfaceExt: SpecExt {
    /// Returns the runtime resolver for `holds` checks against `rolestore` (empty picks the only one).
    ///
    /// # Errors
    ///
    /// No such rolestore, or none backed by a vocabulary.
    fn holds_resolver(&self, rolestore: &str) -> Result<rt::HoldsResolver, Error> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("HoldsResolver", rolestore));
        };
        let vocab = self.rolestore_vocab(rs)?;
        Ok(rt::HoldsResolver {
            assignments: s(rs.assignments.as_deref()),
            kind_col: s(rs.kind_col.as_deref()),
            kind_val: s(rs.kind_val.as_deref()),
            subject_col: s(rs.subject_col.as_deref()),
            scope_cols: l(&rs.scope_cols),
            revoked_col: s(rs.revoked_col.as_deref()),
            plane: s(rs.plane.as_deref()),
            plane_depth: i64::try_from(self.rolestore_plane_depth(rs)).expect("a plane depth counts topology levels"),
            role_col: s(rs.role_col.as_deref()),
            roles_table: s(rs.roles_table.as_deref()),
            roles_id: s(rs.roles_id.as_deref()),
            key_col: s(rs.key_col.as_deref()),
            perms_col: s(rs.perms_col.as_deref()),
            vocab: to_runtime(vocab),
        })
    }

    /// Returns the runtime surface that writes and lists assignments in `rolestore` (empty picks the only one).
    ///
    /// # Errors
    ///
    /// No such rolestore.
    fn role_assignment_surface(&self, rolestore: &str) -> Result<rt::RoleAssignmentSurface, Error> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("RoleAssignmentSurface", rolestore));
        };
        Ok(rt::RoleAssignmentSurface {
            assignments: s(rs.assignments.as_deref()),
            pk: o(rs.assignment_pk()),
            kind_col: s(rs.kind_col.as_deref()),
            kind_val: s(rs.kind_val.as_deref()),
            subject_col: s(rs.subject_col.as_deref()),
            role_col: s(rs.role_col.as_deref()),
            scope_cols: l(&rs.scope_cols),
            revoked_col: s(rs.revoked_col.as_deref()),
            granted_at_col: s(rs.granted_at_col.as_deref()),
            granted_by_col: s(rs.granted_by_col.as_deref()),
            revoked_by_col: s(rs.revoked_by_col.as_deref()),
            extra_cols: l(&rs.extra_cols),
            roles_table: s(rs.roles_table.as_deref()),
            roles_id: s(rs.roles_id.as_deref()),
            key_col: s(rs.key_col.as_deref()),
            perms_col: s(rs.perms_col.as_deref()),
        })
    }

    /// Returns the runtime surface that writes and revokes grant `name`.
    ///
    /// # Errors
    ///
    /// No such grant, or a claim grant, which has no edge table to write.
    fn grant_surface(&self, name: &str) -> Result<rt::GrantSurface, Error> {
        let Some(g) = self.grant_by_name(name) else {
            return Err(Error::unplaced(format!("GrantSurface: no grant {} in the spec", quote(name))));
        };
        if g.claim_key.is_some() {
            return Err(Error::unplaced(format!("GrantSurface: claim grant {} has no writable edge", quote(name))));
        }
        Ok(rt::GrantSurface {
            name: o(g.name.clone()),
            level: o(g.level.clone()),
            table: s(g.table.as_deref()),
            grantee_col: s(g.grantee_col.as_deref()),
            level_col: s(g.level_col.as_deref()),
            active_col: s(g.active_col.as_deref()),
            expires_col: s(g.expires_col.as_deref()),
            pk: o(g.grant_pk()),
            granted_by_col: s(g.granted_by_col.as_deref()),
            revoked_by_col: s(g.revoked_by_col.as_deref()),
            created_at_col: s(g.created_at_col.as_deref()),
            extra_cols: l(&g.extra_cols),
        })
    }

    /// Returns the surface that lists who can reach rows of `object`, including readers it can only name conditionally.
    ///
    /// # Errors
    ///
    /// No such object, or the object has no grant store.
    fn conditional_resource_access_surface(&self, object: &str) -> Result<rt::ResourceAccessSurface, Error> {
        let Some(obj) = self.object_by_name(object) else {
            return Err(Error::unplaced(format!("ResourceAccessSurface: no object {} in the spec", quote(object))));
        };
        let Some(edge) = object_grant_edge(obj) else {
            return Err(Error::unplaced(format!(
                "ResourceAccessSurface: object {} has no grant store (descriptor grants or a `via grant` relation)",
                quote(object)
            )));
        };
        let schema = self.spec().definer_schema();
        let mut r = rt::ResourceAccessSurface {
            table: o(obj.table.clone()),
            pk: o(obj.pk()),
            acl_table: o(edge.table.clone()),
            record_col: o(edge.record_col.clone()),
            kind_col: o(edge.kind_col.clone()),
            principal_col: o(edge.principal_col.clone()),
            access_col: o(edge.access_col.clone()),
            discrim_col: s(edge.discrim_col.as_deref()),
            discrim_val: s(edge.discrim_val.as_deref()),
            accessor_fn: o(format!("{schema}.{}_accessors", obj.table)),
            ..Default::default()
        };
        let cond = self.conditional_accessors(obj);
        if !cond.is_empty() {
            r.conditional = true;
            r.conditional_by = o(admission_names(&cond));
            r.accessor_fn = o(format!("{schema}.{}_accessors_conditional", obj.table));
        }
        let scope_cols: Vec<String> = obj.scoped.iter().map(|lvl| self.scope_col(obj, lvl)).collect();
        r.scope_cols = l(&scope_cols);
        r.scope_nullable = obj.scoped.iter().map(|lvl| obj.scope_is_wildcard(lvl)).collect::<Vec<_>>().into();
        let mut read_modes = std::collections::BTreeSet::new();
        for (_, t) in obj.perm_terms() {
            if let Some(col) = t.mode_col() {
                r.mode_col = o(col);
                read_modes.insert(t.mode_val().to_string());
            }
        }
        r.read_modes = rt::owned_list(read_modes);
        if let Some((rel, _)) = grant_relation(obj) {
            let kinds: std::collections::BTreeSet<String> = rel.types.iter().cloned().collect();
            r.grant_kinds = rt::owned_list(kinds);
        }
        Ok(r)
    }

    /// Returns the surface that lists who can reach rows of `object`, when it can name every reader.
    ///
    /// # Errors
    ///
    /// Any error from [`SurfaceExt::conditional_resource_access_surface`], or an object with readers it cannot name.
    fn resource_access_surface(&self, object: &str) -> Result<rt::ResourceAccessSurface, Error> {
        self.conditional_resource_access_surface(object)?.require_unconditional(object).map_err(|e| Error::unplaced(e.to_string()))
    }

    /// Returns each preset of `rolestore`'s vocabulary with its permissions fully expanded.
    ///
    /// # Errors
    ///
    /// No such rolestore, no backing vocabulary, or a preset that is cyclic or names an unknown entry.
    fn expanded_presets(&self, rolestore: &str) -> Result<BTreeMap<String, Vec<String>>, Error> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("ExpandedPresets", rolestore));
        };
        let v = self.rolestore_vocab(rs).map_err(|e| Error::unplaced(format!("ExpandedPresets: {e}")))?;
        let rv = to_runtime(v);
        let mut out = BTreeMap::new();
        for p in &v.presets {
            let perms = rv.preset_permissions(&p.name).map_err(|e| Error::unplaced(format!("ExpandedPresets: {e}")))?;
            out.insert(p.name.clone(), perms);
        }
        Ok(out)
    }
}

impl<T: SpecExt + ?Sized> SurfaceExt for T {}
