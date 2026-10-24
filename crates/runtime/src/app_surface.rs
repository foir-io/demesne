#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppCheck {
    pub verb: String,
    pub check_sql: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppObjectSurface {
    pub object: String,
    pub table: String,
    pub pk: String,
    pub flat_list_fn: String,
    pub async_check_sql: String,
    pub edit_check_sql: String,
    pub checks: Vec<AppCheck>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppCheckSurface {
    pub objects: Vec<AppObjectSurface>,
}

impl AppCheckSurface {
    pub fn object(&self, name: &str) -> Option<&AppObjectSurface> {
        self.objects.iter().find(|o| o.object == name)
    }
}

impl AppObjectSurface {
    pub fn check_sql(&self) -> String {
        format!("SELECT EXISTS (SELECT 1 FROM {} WHERE {} = $1)", self.table, self.pk)
    }

    pub fn check_edit_sql(&self) -> &str {
        &self.edit_check_sql
    }

    pub fn check_verb_sql(&self, verb: &str) -> &str {
        self.checks.iter().find(|c| c.verb == verb).map(|c| c.check_sql.as_str()).unwrap_or("")
    }

    pub fn check_many_sql(&self) -> String {
        format!("SELECT {} FROM {} WHERE {} = ANY($1)", self.pk, self.table, self.pk)
    }

    pub fn list_resources_sql(&self) -> String {
        format!(
            "SELECT {pk} FROM {t} WHERE ($1::text IS NULL OR {pk}::text > $1::text) ORDER BY {pk}::text LIMIT $2",
            pk = self.pk,
            t = self.table
        )
    }

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
