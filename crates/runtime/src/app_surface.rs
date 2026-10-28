use crate::Str;
use std::borrow::Cow;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppCheck {
    pub verb: Str,
    pub check_sql: Str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppObjectSurface {
    pub object: Str,
    pub table: Str,
    pub pk: Str,
    pub flat_list_fn: Str,
    pub async_check_sql: Str,
    pub edit_check_sql: Str,
    pub checks: Cow<'static, [AppCheck]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppCheckSurface {
    pub objects: Cow<'static, [AppObjectSurface]>,
}

impl AppCheckSurface {
    #[must_use]
    pub fn object(&self, name: &str) -> Option<&AppObjectSurface> {
        self.objects.iter().find(|o| o.object == name)
    }
}

impl AppObjectSurface {
    #[must_use]
    pub fn check_sql(&self) -> String {
        format!("SELECT EXISTS (SELECT 1 FROM {} WHERE {} = $1)", self.table, self.pk)
    }

    #[must_use]
    pub fn check_edit_sql(&self) -> &str {
        &self.edit_check_sql
    }

    #[must_use]
    pub fn check_verb_sql(&self, verb: &str) -> &str {
        self.checks.iter().find(|c| c.verb == verb).map_or("", |c| c.check_sql.as_ref())
    }

    #[must_use]
    pub fn check_many_sql(&self) -> String {
        format!("SELECT {} FROM {} WHERE {} = ANY($1)", self.pk, self.table, self.pk)
    }

    #[must_use]
    pub fn list_resources_sql(&self) -> String {
        format!("SELECT {pk} FROM {t} WHERE ($1::text IS NULL OR {pk}::text > $1::text) ORDER BY {pk}::text LIMIT $2", pk = self.pk, t = self.table)
    }

    #[must_use]
    pub fn list_resources_fast_sql(&self) -> String {
        if self.flat_list_fn.is_empty() {
            return String::new();
        }
        format!(
            "SELECT {pk} FROM {t} WHERE {pk} IN (SELECT {f}()) AND ($1::text IS NULL OR {pk}::text > $1::text) ORDER BY {pk}::text LIMIT $2",
            pk = self.pk,
            t = self.table,
            f = self.flat_list_fn
        )
    }
}
