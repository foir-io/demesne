use crate::{SqlArg, Str, Strs};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantSurface {
    pub name: Str,
    pub level: Str,
    pub table: Str,
    pub grantee_col: Str,
    pub level_col: Str,
    pub active_col: Str,
    pub expires_col: Str,
    pub pk: Str,
    pub granted_by_col: Str,
    pub revoked_by_col: Str,
    pub created_at_col: Str,
    pub extra_cols: Strs,
}

impl GrantSurface {
    /// Returns the condition that a grant row is active: not revoked and not expired, with each column prefixed; `TRUE` when the store has neither column.
    #[must_use]
    pub fn active_predicate(&self, prefix: &str) -> String {
        let mut conj = Vec::new();
        if !self.active_col.is_empty() {
            conj.push(format!("{prefix}{} IS NULL", self.active_col));
        }
        if !self.expires_col.is_empty() {
            conj.push(format!("{prefix}{} > now()", self.expires_col));
        }
        if conj.is_empty() {
            return "TRUE".into();
        }
        conj.join(" AND ")
    }

    fn grant_cols(&self) -> Vec<&str> {
        let mut cols: Vec<&str> = vec![&self.pk, &self.grantee_col, &self.level_col];
        for c in [&self.granted_by_col, &self.expires_col, &self.created_at_col, &self.active_col, &self.revoked_by_col] {
            if !c.is_empty() {
                cols.push(c);
            }
        }
        cols.extend(self.extra_cols.iter().map(std::convert::AsRef::as_ref));
        cols
    }

    #[must_use]
    pub fn grant_insert(
        &self,
        grant_id: &str,
        grantee_id: &str,
        level_id: &str,
        granted_by: &str,
        expires_at: SqlArg,
        extra: &BTreeMap<String, String>,
    ) -> (String, Vec<SqlArg>) {
        let mut cols: Vec<&str> = vec![&self.pk, &self.grantee_col, &self.level_col];
        let mut args: Vec<SqlArg> = vec![Some(grant_id.into()), Some(grantee_id.into()), Some(level_id.into())];
        if !self.granted_by_col.is_empty() {
            cols.push(&self.granted_by_col);
            args.push(Some(granted_by.into()));
        }
        if !self.expires_col.is_empty() {
            cols.push(&self.expires_col);
            args.push(expires_at);
        }
        for c in self.extra_cols.iter() {
            cols.push(c);
            args.push(extra.get(c.as_ref()).cloned());
        }
        let ph: Vec<String> = (1..=cols.len()).map(|i| format!("${i}")).collect();
        let sql = format!("INSERT INTO {} ({}) VALUES ({}) RETURNING {}", self.table, cols.join(", "), ph.join(", "), self.grant_cols().join(", "));
        (sql, args)
    }

    #[must_use]
    pub fn revoke_sql(&self) -> String {
        if self.active_col.is_empty() {
            return format!("DELETE FROM {} WHERE {} = $1", self.table, self.pk);
        }
        let mut set = format!("{} = now()", self.active_col);
        if !self.revoked_by_col.is_empty() {
            write!(set, ", {} = $2", self.revoked_by_col).expect("fmt::Write for String never fails");
        }
        format!("UPDATE {} SET {} WHERE {} = $1 AND {} IS NULL RETURNING {}", self.table, set, self.pk, self.active_col, self.grant_cols().join(", "))
    }

    #[must_use]
    pub fn list_sql(&self) -> String {
        let mut sql = format!(
            "SELECT {} FROM {} WHERE ($1::text IS NULL OR {} = $1) AND ($2::text IS NULL OR {} = $2) AND (NOT $3::boolean OR ({}))",
            self.grant_cols().join(", "),
            self.table,
            self.grantee_col,
            self.level_col,
            self.active_predicate("")
        );
        if !self.created_at_col.is_empty() {
            write!(sql, " ORDER BY {} DESC", self.created_at_col).expect("fmt::Write for String never fails");
        }
        sql
    }
}
