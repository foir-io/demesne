use crate::SqlArg;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleAssignmentSurface {
    pub assignments: String,
    pub pk: String,
    pub kind_col: String,
    pub kind_val: String,
    pub subject_col: String,
    pub role_col: String,
    pub scope_cols: Vec<String>,
    pub revoked_col: String,
    pub granted_at_col: String,
    pub granted_by_col: String,
    pub revoked_by_col: String,
    pub extra_cols: Vec<String>,
    pub roles_table: String,
    pub roles_id: String,
    pub key_col: String,
    pub perms_col: String,
}

pub fn touch_on_conflict(bare_key: &[String], nullable_key: &[String], sets: &[String]) -> String {
    let mut key: Vec<String> = bare_key.to_vec();
    key.extend(nullable_key.iter().map(|c| format!("COALESCE({c}, '')")));
    format!("ON CONFLICT ({}) DO UPDATE SET {}", key.join(", "), sets.join(", "))
}

impl RoleAssignmentSurface {
    fn assignment_cols(&self) -> Vec<String> {
        let mut cols = vec![self.pk.clone(), self.kind_col.clone(), self.subject_col.clone(), self.role_col.clone()];
        cols.extend(self.scope_cols.iter().cloned());
        for c in [&self.granted_at_col, &self.granted_by_col, &self.revoked_col, &self.revoked_by_col] {
            if !c.is_empty() {
                cols.push(c.clone());
            }
        }
        cols.extend(self.extra_cols.iter().cloned());
        cols
    }

    pub fn assign_insert(
        &self,
        assignment_id: &str,
        subject_id: &str,
        role_id: &str,
        scope: &[String],
        granted_by: &str,
        extra: &BTreeMap<String, String>,
    ) -> (String, Vec<SqlArg>) {
        self.assign_sql(false, assignment_id, subject_id, role_id, scope, granted_by, extra)
    }

    pub fn assign_touch_insert(
        &self,
        assignment_id: &str,
        subject_id: &str,
        role_id: &str,
        scope: &[String],
        granted_by: &str,
        extra: &BTreeMap<String, String>,
    ) -> (String, Vec<SqlArg>) {
        self.assign_sql(true, assignment_id, subject_id, role_id, scope, granted_by, extra)
    }

    fn assign_sql(
        &self,
        touch: bool,
        assignment_id: &str,
        subject_id: &str,
        role_id: &str,
        scope: &[String],
        granted_by: &str,
        extra: &BTreeMap<String, String>,
    ) -> (String, Vec<SqlArg>) {
        let mut cols = vec![self.pk.clone(), self.kind_col.clone(), self.subject_col.clone(), self.role_col.clone()];
        let mut args: Vec<SqlArg> =
            vec![Some(assignment_id.into()), Some(self.kind_val.clone()), Some(subject_id.into()), Some(role_id.into())];
        for (i, c) in self.scope_cols.iter().enumerate() {
            cols.push(c.clone());
            args.push(scope.get(i).cloned());
        }
        if !self.granted_by_col.is_empty() {
            cols.push(self.granted_by_col.clone());
            args.push(Some(granted_by.into()));
        }
        for c in &self.extra_cols {
            cols.push(c.clone());
            args.push(extra.get(c).cloned());
        }
        let ph: Vec<String> = (1..=cols.len()).map(|i| format!("${i}")).collect();
        let conflict = if touch { format!(" {}", self.touch_clause()) } else { String::new() };
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({}){} RETURNING {}",
            self.assignments,
            cols.join(", "),
            ph.join(", "),
            conflict,
            self.assignment_cols().join(", ")
        );
        (sql, args)
    }

    fn touch_clause(&self) -> String {
        let bare = vec![self.kind_col.clone(), self.subject_col.clone(), self.role_col.clone()];
        let mut nullable = self.scope_cols.clone();
        nullable.extend(self.extra_cols.iter().cloned());
        let mut sets = Vec::new();
        if !self.revoked_col.is_empty() {
            sets.push(format!("{} = NULL", self.revoked_col));
        }
        if !self.revoked_by_col.is_empty() {
            sets.push(format!("{} = NULL", self.revoked_by_col));
        }
        if !self.granted_at_col.is_empty() {
            sets.push(format!("{} = now()", self.granted_at_col));
        }
        if !self.granted_by_col.is_empty() {
            sets.push(format!("{c} = EXCLUDED.{c}", c = self.granted_by_col));
        }
        touch_on_conflict(&bare, &nullable, &sets)
    }

    pub fn revoke_sql(&self) -> String {
        let mut set = format!("{} = now()", self.revoked_col);
        if !self.revoked_by_col.is_empty() {
            set.push_str(&format!(", {} = $2", self.revoked_by_col));
        }
        format!("UPDATE {} SET {} WHERE {} = $1 AND {} IS NULL", self.assignments, set, self.pk, self.revoked_col)
    }

    pub fn list_for_role_sql(&self) -> String {
        let mut sql = format!("SELECT {} FROM {} WHERE {} = $1", self.assignment_cols().join(", "), self.assignments, self.role_col);
        if !self.granted_at_col.is_empty() {
            sql.push_str(&format!(" ORDER BY {} DESC", self.granted_at_col));
        }
        sql
    }

    pub fn list_for_principal_sql(&self) -> String {
        let mut cols = vec![format!("a.{}", self.pk), format!("a.{}", self.subject_col), format!("a.{}", self.role_col)];
        for c in [&self.granted_at_col, &self.granted_by_col] {
            if !c.is_empty() {
                cols.push(format!("a.{c}"));
            }
        }
        cols.push(format!("r.{}", self.key_col));
        if !self.perms_col.is_empty() {
            cols.push(format!("r.{}", self.perms_col));
        }
        format!(
            "SELECT {} FROM {} a JOIN {} r ON r.{} = a.{} WHERE a.{} = '{}' AND a.{} = $1 AND a.{} IS NULL",
            cols.join(", "),
            self.assignments,
            self.roles_table,
            self.roles_id,
            self.role_col,
            self.kind_col,
            self.kind_val,
            self.subject_col,
            self.revoked_col
        )
    }
}
