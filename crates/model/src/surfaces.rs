use crate::analysis::{SpecExt, grant_relation, object_grant_edge};
use crate::conditional::{ConditionalExt, admission_names};
use crate::vocab::to_runtime;
use demesne_gocompat::quote;
use demesne_runtime as rt;
use demesne_syntax::*;
use std::collections::BTreeMap;

fn s(o: &Option<String>) -> String {
    o.clone().unwrap_or_default()
}

fn pick_role_store<'a>(spec: &'a Spec, rolestore: &str) -> Option<&'a RoleStore> {
    if rolestore.is_empty() {
        spec.role_stores.first()
    } else {
        spec.role_stores.iter().find(|r| r.name == rolestore)
    }
}

fn no_store(ctx: &str, rolestore: &str) -> String {
    if rolestore.is_empty() {
        format!("{ctx}: the spec declares no rolestore")
    } else {
        format!("{ctx}: no rolestore {} in the spec", quote(rolestore))
    }
}

pub trait SurfaceExt: SpecExt {
    fn holds_resolver(&self, rolestore: &str) -> Result<rt::HoldsResolver, String> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("HoldsResolver", rolestore));
        };
        let vocab = self.rolestore_vocab(rs)?;
        Ok(rt::HoldsResolver {
            assignments: s(&rs.assignments),
            kind_col: s(&rs.kind_col),
            kind_val: s(&rs.kind_val),
            subject_col: s(&rs.subject_col),
            scope_cols: rs.scope_cols.clone(),
            revoked_col: s(&rs.revoked_col),
            plane: s(&rs.plane),
            plane_depth: self.rolestore_plane_depth(rs) as i64,
            role_col: s(&rs.role_col),
            roles_table: s(&rs.roles_table),
            roles_id: s(&rs.roles_id),
            key_col: s(&rs.key_col),
            perms_col: s(&rs.perms_col),
            vocab: to_runtime(vocab),
        })
    }

    fn role_assignment_surface(&self, rolestore: &str) -> Result<rt::RoleAssignmentSurface, String> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("RoleAssignmentSurface", rolestore));
        };
        Ok(rt::RoleAssignmentSurface {
            assignments: s(&rs.assignments),
            pk: rs.assignment_pk().to_string(),
            kind_col: s(&rs.kind_col),
            kind_val: s(&rs.kind_val),
            subject_col: s(&rs.subject_col),
            role_col: s(&rs.role_col),
            scope_cols: rs.scope_cols.clone(),
            revoked_col: s(&rs.revoked_col),
            granted_at_col: s(&rs.granted_at_col),
            granted_by_col: s(&rs.granted_by_col),
            revoked_by_col: s(&rs.revoked_by_col),
            extra_cols: rs.extra_cols.clone(),
            roles_table: s(&rs.roles_table),
            roles_id: s(&rs.roles_id),
            key_col: s(&rs.key_col),
            perms_col: s(&rs.perms_col),
        })
    }

    fn grant_surface(&self, name: &str) -> Result<rt::GrantSurface, String> {
        let Some(g) = self.grant_by_name(name) else {
            return Err(format!("GrantSurface: no grant {} in the spec", quote(name)));
        };
        if g.claim_key.is_some() {
            return Err(format!("GrantSurface: claim grant {} has no writable edge", quote(name)));
        }
        Ok(rt::GrantSurface {
            name: g.name.clone(),
            level: g.level.clone(),
            table: s(&g.table),
            grantee_col: s(&g.grantee_col),
            level_col: s(&g.level_col),
            active_col: s(&g.active_col),
            expires_col: s(&g.expires_col),
            pk: g.grant_pk().to_string(),
            granted_by_col: s(&g.granted_by_col),
            revoked_by_col: s(&g.revoked_by_col),
            created_at_col: s(&g.created_at_col),
            extra_cols: g.extra_cols.clone(),
        })
    }

    fn conditional_resource_access_surface(&self, object: &str) -> Result<rt::ResourceAccessSurface, String> {
        let Some(obj) = self.object_by_name(object) else {
            return Err(format!("ResourceAccessSurface: no object {} in the spec", quote(object)));
        };
        let Some(edge) = object_grant_edge(obj) else {
            return Err(format!(
                "ResourceAccessSurface: object {} has no grant store (descriptor grants or a `via grant` relation)",
                quote(object)
            ));
        };
        let schema = self.spec().definer_schema();
        let mut r = rt::ResourceAccessSurface {
            table: obj.table.clone(),
            pk: obj.pk().to_string(),
            acl_table: edge.table.clone(),
            record_col: edge.record_col.clone(),
            kind_col: edge.kind_col.clone(),
            principal_col: edge.principal_col.clone(),
            access_col: edge.access_col.clone(),
            discrim_col: s(&edge.discrim_col),
            discrim_val: s(&edge.discrim_val),
            accessor_fn: format!("{schema}.{}_accessors", obj.table),
            ..Default::default()
        };
        let cond = self.conditional_accessors(obj);
        if !cond.is_empty() {
            r.conditional = true;
            r.conditional_by = admission_names(&cond);
            r.accessor_fn = format!("{schema}.{}_accessors_conditional", obj.table);
        }
        for lvl in &obj.scoped {
            r.scope_cols.push(self.scope_col(obj, lvl));
            r.scope_nullable.push(obj.scope_is_wildcard(lvl));
        }
        for pm in &obj.perms {
            for t in pm.tree.leaves() {
                if let Some(col) = t.mode_col() {
                    r.mode_col = col.to_string();
                    r.read_modes.insert(t.mode_val().to_string());
                }
            }
        }
        if let Some((rel, _)) = grant_relation(obj) {
            r.grant_kinds.extend(rel.types.iter().cloned());
        }
        Ok(r)
    }

    fn resource_access_surface(&self, object: &str) -> Result<rt::ResourceAccessSurface, String> {
        self.conditional_resource_access_surface(object)?.require_unconditional(object).map_err(|e| e.to_string())
    }

    fn expanded_presets(&self, rolestore: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
        let Some(rs) = pick_role_store(self.spec(), rolestore) else {
            return Err(no_store("ExpandedPresets", rolestore));
        };
        let v = self.rolestore_vocab(rs).map_err(|e| format!("ExpandedPresets: {e}"))?;
        let rv = to_runtime(v);
        let mut out = BTreeMap::new();
        for p in &v.presets {
            let perms = rv.preset_permissions(&p.name).map_err(|e| format!("ExpandedPresets: {e}"))?;
            out.insert(p.name.clone(), perms);
        }
        Ok(out)
    }
}

impl<T: SpecExt + ?Sized> SurfaceExt for T {}
