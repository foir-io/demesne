use crate::Sql;
use demesne_runtime::quote_literal;

pub(crate) struct Remembered {
    seen: String,
    own: String,
    claims: String,
}

fn plain(part: &str) -> bool {
    part.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_') && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl Sql<'_> {
    pub(crate) fn remembered(&self, name: &str) -> Option<Remembered> {
        let schema = self.s.definer_schema();
        if !plain(schema) || !plain(name) {
            return None;
        }
        let setting = |what: &str| quote_literal(&format!("demesne.{schema}.{name}.{what}"));
        Some(Remembered { seen: setting("seen"), own: setting("own"), claims: format!("current_setting({}, true)", quote_literal(self.claims_setting().0)) })
    }
}

impl Remembered {
    pub(crate) fn holds_for(&self, argument: &str) -> String {
        format!("current_setting({}, true) = {} AND current_setting({}, true) = {argument}", self.seen, self.claims, self.own)
    }

    pub(crate) fn keep(&self, argument: &str) -> String {
        format!("PERFORM set_config({}, {argument}, true), set_config({}, coalesce({}, ''), true);", self.own, self.seen, self.claims)
    }
}
