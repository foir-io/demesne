use crate::{Error, SqlArg, Str, Strs};
use std::borrow::Cow;
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceAccessSurface {
    pub table: Str,
    pub scope_cols: Strs,
    pub scope_nullable: Cow<'static, [bool]>,
    pub mode_col: Str,
    pub pk: Str,
    pub read_modes: Strs,
    pub grant_kinds: Strs,
    pub acl_table: Str,
    pub record_col: Str,
    pub kind_col: Str,
    pub principal_col: Str,
    pub access_col: Str,
    pub discrim_col: Str,
    pub discrim_val: Str,
    pub accessor_fn: Str,
    pub conditional: bool,
    pub conditional_by: Str,
}

impl ResourceAccessSurface {
    /// Returns the surface when its enumeration names every reader of `object`.
    ///
    /// # Errors
    ///
    /// The object admits readers its accessor function cannot list. Use the conditional resource-access surface for such an object instead.
    pub fn require_unconditional(self, object: &str) -> Result<Self, Error> {
        if self.conditional {
            return Err(Error::access(format!(
                "ResourceAccessSurface: object {} admits readers its enumeration cannot name ({}), so {} lists only the accessors it can name and never the rest; call ConditionalResourceAccessSurface and decide what those rows mean for this caller",
                demesne_gocompat::quote(object),
                self.conditional_by,
                self.accessor_fn
            )));
        }
        Ok(self)
    }

    #[must_use]
    pub fn is_read_mode(&self, mode: &str) -> bool {
        self.read_modes.iter().any(|m| m == mode)
    }

    #[must_use]
    pub fn grant_kind_allowed(&self, kind: &str) -> bool {
        self.grant_kinds.iter().any(|k| k == kind)
    }

    #[must_use]
    pub fn mode_sql(&self) -> String {
        format!("SELECT {} FROM {} WHERE {} = $1", self.mode_col, self.table, self.pk)
    }

    #[must_use]
    pub fn set_visibility_sql(&self) -> String {
        format!("UPDATE {} SET {} = $1 WHERE {} = $2", self.table, self.mode_col, self.pk)
    }

    fn scope_arg(&self, i: usize, v: &str) -> SqlArg {
        if v.is_empty() && self.scope_nullable.get(i).copied().unwrap_or(false) {
            return None;
        }
        Some(v.to_string())
    }

    #[must_use]
    pub fn grant_insert(&self, scope: &[String], resource_id: &str, kind: &str, principal_id: &str, access: &str) -> (String, Vec<SqlArg>) {
        let mut cols: Vec<&str> = self.scope_cols.iter().map(std::convert::AsRef::as_ref).collect();
        let mut args: Vec<SqlArg> = scope.iter().enumerate().map(|(i, v)| self.scope_arg(i, v)).collect();
        if !self.discrim_col.is_empty() {
            cols.push(&self.discrim_col);
            args.push(Some(self.discrim_val.to_string()));
        }
        cols.extend([&*self.record_col, &*self.kind_col, &*self.principal_col, &*self.access_col]);
        args.extend([resource_id, kind, principal_id, access].map(|s| Some(s.to_string())));
        let ph: Vec<String> = (1..=cols.len()).map(|i| format!("${i}")).collect();
        let mut conflict: Vec<&str> = Vec::new();
        if !self.discrim_col.is_empty() {
            conflict.push(&self.discrim_col);
        }
        conflict.extend([&*self.record_col, &*self.kind_col, &*self.principal_col, &*self.access_col]);
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT ({}) DO NOTHING RETURNING created_at",
            self.acl_table,
            cols.join(", "),
            ph.join(", "),
            conflict.join(", ")
        );
        (sql, args)
    }

    #[must_use]
    pub fn revoke_delete(&self, resource_id: &str, kind: &str, principal_id: &str, access: &str) -> (String, Vec<SqlArg>) {
        let mut conds = Vec::new();
        let mut args: Vec<SqlArg> = Vec::new();
        let mut add = |col: &str, val: &str| {
            args.push(Some(val.to_string()));
            conds.push(format!("{col} = ${}", args.len()));
        };
        add(&self.record_col, resource_id);
        if !self.discrim_col.is_empty() {
            add(&self.discrim_col, &self.discrim_val);
        }
        add(&self.kind_col, kind);
        add(&self.principal_col, principal_id);
        if !access.is_empty() {
            add(&self.access_col, access);
        }
        (format!("DELETE FROM {} WHERE {}", self.acl_table, conds.join(" AND ")), args)
    }

    #[must_use]
    pub fn list_grants_sql(&self) -> String {
        let mut sql =
            format!("SELECT {}, {}, {}, created_at FROM {} WHERE {} = $1", self.kind_col, self.principal_col, self.access_col, self.acl_table, self.record_col);
        if !self.discrim_col.is_empty() {
            write!(sql, " AND {} = $2", self.discrim_col).expect("fmt::Write for String never fails");
        }
        sql + " ORDER BY created_at"
    }

    #[must_use]
    pub fn list_grants_args(&self, resource_id: &str) -> Vec<SqlArg> {
        if !self.discrim_col.is_empty() {
            return vec![Some(resource_id.to_string()), Some(self.discrim_val.to_string())];
        }
        vec![Some(resource_id.to_string())]
    }

    #[must_use]
    pub fn is_conditional(&self) -> bool {
        self.conditional
    }

    #[must_use]
    pub fn conditional_by(&self) -> &str {
        &self.conditional_by
    }

    #[must_use]
    pub fn accessors_sql(&self) -> String {
        if self.conditional {
            return format!("SELECT source, principal_kind, principal_id, access, via_claim_key, via_claim_value FROM {}($1)", self.accessor_fn);
        }
        format!("SELECT source, principal_kind, principal_id, access FROM {}($1)", self.accessor_fn)
    }
}
