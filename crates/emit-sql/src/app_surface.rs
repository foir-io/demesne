use crate::Sql;
use crate::error::Error;
use demesne_model::SpecExt;
use demesne_model::analysis::relation_is_async;
use demesne_model::conditional::accessor_tree_op;
use demesne_runtime::{AppCheck, AppCheckSurface, AppObjectSurface, owned, quote_literal};
use demesne_syntax::{Object, Repr};

impl Sql<'_> {
    fn app_checks(&self, o: &Object) -> Result<Vec<AppCheck>, String> {
        let mut checks = Vec::new();
        for pm in o.perms.iter().filter(|pm| pm.has_layer("check")) {
            let sql = self.perm_point_check_sql(o, pm).map_err(|e| format!("EmitAppSurface: {}.{} @check point-check: {e}", o.name, pm.verb))?;
            if !sql.is_empty() {
                checks.push(AppCheck { verb: owned(pm.verb.clone()), check_sql: owned(sql) });
            }
        }
        Ok(checks)
    }

    /// Builds the application check surface: each point-checkable object's check, list and edit SQL.
    ///
    /// # Errors
    ///
    /// The spec declares no objects, or an object's predicates cannot be compiled.
    pub fn emit_app_surface(&self) -> Result<AppCheckSurface, Error> {
        self.app_surface().map_err(Error::unplaced)
    }

    fn app_surface(&self) -> Result<AppCheckSurface, String> {
        if self.s.objects.is_empty() {
            return Err("EmitAppSurface: the spec declares no objects".into());
        }
        let mut objects: Vec<AppObjectSurface> = Vec::new();
        for o in &self.s.objects {
            if !o.point_checkable() {
                continue;
            }
            let edit_sql = self.edit_point_check_sql(o).map_err(|e| format!("EmitAppSurface: {} edit point-check: {e}", o.name))?;
            let checks = self.app_checks(o)?;
            objects.push(AppObjectSurface {
                object: owned(o.name.clone()),
                table: owned(o.table.clone()),
                pk: owned(o.pk()),
                flat_list_fn: owned(self.flat_list_fn(o)),
                async_check_sql: owned(self.async_check_sql(o)),
                edit_check_sql: owned(edit_sql),
                checks: checks.into(),
            });
        }
        Ok(AppCheckSurface { objects: objects.into() })
    }

    fn flat_list_fn(&self, o: &Object) -> String {
        let Some(sel) = o.perms.iter().find(|pm| pm.maps() == "select") else { return String::new() };
        let leaves = sel.tree.leaves();
        if leaves.len() != 1 || !accessor_tree_op(&sel.tree).is_empty() {
            return String::new();
        }
        let Some(rel) = o.relations.iter().find(|r| r.name == leaves[0].ident()) else { return String::new() };
        let Repr::Group(g) = &rel.repr else { return String::new() };
        if !g.materialized {
            return String::new();
        }
        if o.scoped.last().and_then(|l| self.s.owner_subject(l)).is_none() {
            return String::new();
        }
        format!("{}.{}_{}_flat_resources", self.s.definer_schema(), o.table, rel.name)
    }

    fn async_check_sql(&self, o: &Object) -> String {
        let Some(rel) = o.relations.iter().find(|r| relation_is_async(r)) else { return String::new() };
        let Some(cust) = o.scoped.last().and_then(|l| self.s.owner_subject(l)) else { return String::new() };
        let kind = rel.types.first().map_or("", String::as_str);
        format!(
            "SELECT allowed, as_of::text FROM {}_affordance($1, {}, {})",
            self.s.async_index_base(&o.table, &rel.name),
            quote_literal(kind),
            self.id_claim(cust.identifies())
        )
    }
}
