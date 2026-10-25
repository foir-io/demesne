use crate::{Error, Str, Strs, Vocabulary};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HoldsResolver {
    pub assignments: Str,
    pub kind_col: Str,
    pub kind_val: Str,
    pub subject_col: Str,
    pub scope_cols: Strs,
    pub revoked_col: Str,
    pub plane: Str,
    pub plane_depth: i64,
    pub role_col: Str,
    pub roles_table: Str,
    pub roles_id: Str,
    pub key_col: Str,
    pub perms_col: Str,
    pub vocab: Vocabulary,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleAssignment {
    pub scope: Vec<String>,
    pub role_key: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectivePerms {
    perms: BTreeSet<String>,
}

impl EffectivePerms {
    #[must_use]
    pub fn holds(&self, perm: &str) -> bool {
        self.perms.contains(perm)
    }

    #[must_use]
    pub fn permissions(&self) -> Vec<String> {
        self.perms.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveRoles {
    roles: BTreeSet<String>,
}

impl EffectiveRoles {
    pub fn new<S: AsRef<str>>(keys: &[S]) -> Self {
        EffectiveRoles { roles: keys.iter().map(std::convert::AsRef::as_ref).filter(|k| !k.is_empty()).map(String::from).collect() }
    }

    #[must_use]
    pub fn holds(&self, role_key: &str) -> bool {
        self.roles.contains(role_key)
    }

    #[must_use]
    pub fn roles(&self) -> Vec<String> {
        self.roles.iter().cloned().collect()
    }
}

impl HoldsResolver {
    #[must_use]
    pub fn vocabulary(&self) -> &Vocabulary {
        &self.vocab
    }

    /// Returns how many leading scope columns the plane selects: all of them unless a plane is declared, else its depth clamped to the columns.
    #[must_use]
    pub fn plane_depth(&self) -> usize {
        let n = self.scope_cols.len();
        if self.plane.is_empty() {
            return n;
        }
        usize::try_from(self.plane_depth).map_or(0, |d| d.min(n))
    }

    #[must_use]
    pub fn selected_scope_cols(&self) -> &[Str] {
        &self.scope_cols[..self.plane_depth()]
    }

    #[must_use]
    pub fn assignments_sql(&self) -> String {
        let mut cols: Vec<String> = self.selected_scope_cols().iter().map(|c| format!("ra.{c}")).collect();
        cols.push(format!("r.{}", self.key_col));
        if !self.perms_col.is_empty() {
            cols.push(format!("r.{}", self.perms_col));
        }
        let mut conds = Vec::new();
        if !self.kind_col.is_empty() {
            conds.push(format!("ra.{} = '{}'", self.kind_col, self.kind_val));
        }
        conds.push(format!("ra.{} = $1", self.subject_col));
        if !self.revoked_col.is_empty() {
            conds.push(format!("ra.{} IS NULL", self.revoked_col));
        }
        for c in &self.scope_cols[self.plane_depth()..] {
            conds.push(format!("ra.{c} IS NULL"));
        }
        format!(
            "SELECT {} FROM {} ra JOIN {} r ON r.{} = ra.{} WHERE {}",
            cols.join(", "),
            self.assignments,
            self.roles_table,
            self.roles_id,
            self.role_col,
            conds.join(" AND ")
        )
    }

    #[must_use]
    pub fn global_assignments_sql(&self) -> String {
        if self.scope_cols.is_empty() {
            return String::new();
        }
        let mut cols = vec![format!("ra.{}", self.subject_col), format!("r.{}", self.key_col)];
        cols.extend(self.scope_cols.iter().map(|c| format!("ra.{c}")));
        let mut conds = Vec::new();
        if !self.kind_col.is_empty() {
            conds.push(format!("ra.{} = '{}'", self.kind_col, self.kind_val));
        }
        if !self.revoked_col.is_empty() {
            conds.push(format!("ra.{} IS NULL", self.revoked_col));
        }
        conds.push(format!("ra.{} IS NULL", self.scope_cols[0]));
        format!(
            "SELECT {} FROM {} ra JOIN {} r ON r.{} = ra.{} WHERE {} ORDER BY 1, 2",
            cols.join(", "),
            self.assignments,
            self.roles_table,
            self.roles_id,
            self.role_col,
            conds.join(" AND ")
        )
    }

    /// Resolves the permissions the `assignments` confer at `scope`, with implications expanded.
    ///
    /// # Errors
    ///
    /// An assignment whose role key names no preset in the vocabulary, or a vocabulary whose presets or implications are cyclic or name unknown permissions.
    pub fn resolve(&self, assignments: &[RoleAssignment], scope: &[String]) -> Result<EffectivePerms, Error> {
        let depth = self.plane_depth();
        let mut eff = EffectivePerms::default();
        for a in assignments {
            if !within_plane(&a.scope, depth) {
                continue;
            }
            if !scope_contains(clamp_scope(&a.scope, depth), scope) {
                continue;
            }
            let perms: Vec<String> = if self.perms_col.is_empty() {
                self.vocab
                    .preset_permissions(&a.role_key)
                    .map_err(|e| Error::vocabulary(format!("Resolve: assignment role {}: {e}", demesne_gocompat::quote(&a.role_key))))?
            } else {
                a.permissions.clone()
            };
            let conferred = self.vocab.expand_implications(&perms).map_err(|e| Error::vocabulary(format!("Resolve: {e}")))?;
            eff.perms.extend(conferred);
        }
        Ok(eff)
    }
}

/// Returns whether every scope id past the first `depth` is empty, so an assignment at that scope sits on the plane.
#[must_use]
pub fn within_plane(scope: &[String], depth: usize) -> bool {
    scope.iter().skip(depth).all(std::string::String::is_empty)
}

fn clamp_scope(scope: &[String], depth: usize) -> &[String] {
    if depth < scope.len() { &scope[..depth] } else { scope }
}

#[must_use]
pub fn scope_contains(assignment: &[String], query: &[String]) -> bool {
    assignment.iter().enumerate().all(|(i, a)| a.is_empty() || query.get(i) == Some(a))
}

#[must_use]
pub fn scope_all_empty(scope: &[String]) -> bool {
    scope.iter().all(std::string::String::is_empty)
}

#[must_use]
pub fn resolve_roles(assignments: &[RoleAssignment], scope: &[String]) -> EffectiveRoles {
    let mut e = EffectiveRoles::default();
    for a in assignments {
        if a.role_key.is_empty() {
            continue;
        }
        if scope_all_empty(&a.scope) || scope_contains(&a.scope, scope) {
            e.roles.insert(a.role_key.clone());
        }
    }
    e
}
