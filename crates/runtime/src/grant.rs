use crate::SqlArg;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantSurface {
    pub name: String,
    pub level: String,
    pub table: String,
    pub grantee_col: String,
    pub level_col: String,
    pub active_col: String,
    pub expires_col: String,
    pub pk: String,
    pub granted_by_col: String,
    pub revoked_by_col: String,
    pub created_at_col: String,
    pub extra_cols: Vec<String>,
}

impl GrantSurface {
    fn active_predicate(&self, prefix: &str) -> String {
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

    fn grant_cols(&self) -> Vec<String> {
        let mut cols = vec![self.pk.clone(), self.grantee_col.clone(), self.level_col.clone()];
        for c in [&self.granted_by_col, &self.expires_col, &self.created_at_col, &self.active_col, &self.revoked_by_col] {
            if !c.is_empty() {
                cols.push(c.clone());
            }
        }
        cols.extend(self.extra_cols.iter().cloned());
        cols
    }

    pub fn grant_insert(
        &self,
        grant_id: &str,
        grantee_id: &str,
        level_id: &str,
        granted_by: &str,
        expires_at: SqlArg,
        extra: &BTreeMap<String, String>,
    ) -> (String, Vec<SqlArg>) {
        let mut cols = vec![self.pk.clone(), self.grantee_col.clone(), self.level_col.clone()];
        let mut args: Vec<SqlArg> = vec![Some(grant_id.into()), Some(grantee_id.into()), Some(level_id.into())];
        if !self.granted_by_col.is_empty() {
            cols.push(self.granted_by_col.clone());
            args.push(Some(granted_by.into()));
        }
        if !self.expires_col.is_empty() {
            cols.push(self.expires_col.clone());
            args.push(expires_at);
        }
        for c in &self.extra_cols {
            cols.push(c.clone());
            args.push(extra.get(c).cloned());
        }
        let ph: Vec<String> = (1..=cols.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
            self.table,
            cols.join(", "),
            ph.join(", "),
            self.grant_cols().join(", ")
        );
        (sql, args)
    }

    pub fn revoke_sql(&self) -> String {
        if self.active_col.is_empty() {
            return format!("DELETE FROM {} WHERE {} = $1", self.table, self.pk);
        }
        let mut set = format!("{} = now()", self.active_col);
        if !self.revoked_by_col.is_empty() {
            set.push_str(&format!(", {} = $2", self.revoked_by_col));
        }
        format!(
            "UPDATE {} SET {} WHERE {} = $1 AND {} IS NULL RETURNING {}",
            self.table,
            set,
            self.pk,
            self.active_col,
            self.grant_cols().join(", ")
        )
    }

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
            sql.push_str(&format!(" ORDER BY {} DESC", self.created_at_col));
        }
        sql
    }
}
