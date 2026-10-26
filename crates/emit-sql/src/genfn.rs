use demesne_runtime::quote_literal;
use std::fmt::Write as _;
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefinerArm {
    pub value: String,
    pub body: String,
}

/// The language a definer's body is written in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Language {
    /// A SQL function.
    #[default]
    Sql,
    /// A PL/pgSQL function.
    Plpgsql,
}

/// Which roles may execute a definer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Execute {
    /// Every role: Postgres grants execute on a new function to PUBLIC.
    #[default]
    Public,
    /// Only the roles the adopter grants it to: execute is revoked from PUBLIC.
    Granted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenFn {
    pub name: String,
    pub schema: String,
    pub table_schema: String,
    pub sig: String,
    pub body: String,
    pub returns: String,
    pub raw_body: bool,
    pub strict: bool,
    pub arm_param: String,
    pub arms: Vec<DefinerArm>,
    pub language: Language,
    pub execute: Execute,
}

impl GenFn {
    #[must_use]
    pub fn schema(&self) -> &str {
        if self.schema.is_empty() { "auth" } else { &self.schema }
    }

    #[must_use]
    pub fn table_schema(&self) -> &str {
        if self.table_schema.is_empty() { "public" } else { &self.table_schema }
    }

    #[must_use]
    pub fn create_sql(&self) -> String {
        let returns = if self.returns.is_empty() { "boolean" } else { &self.returns };
        let mut lang = match self.language {
            Language::Sql => "sql",
            Language::Plpgsql => "plpgsql",
        };
        let mut body = format!("  SELECT {};", self.body);
        if self.raw_body {
            body.clone_from(&self.body);
        }
        if !self.arms.is_empty() {
            lang = "plpgsql";
            body = self.arms_body();
        }
        let strict = if self.strict { "STRICT\n" } else { "" };
        let mut sql = format!(
            "CREATE OR REPLACE FUNCTION {}.{}({})\nRETURNS {}\nLANGUAGE {}\nSTABLE\n{}SECURITY DEFINER\nSET search_path = {}\nAS $$\n{}\n$$;",
            self.schema(),
            self.name,
            self.sig,
            returns,
            lang,
            strict,
            self.table_schema(),
            body
        );
        match self.execute {
            Execute::Public => {}
            Execute::Granted => {
                write!(sql, "\nREVOKE EXECUTE ON FUNCTION {}.{}({}) FROM PUBLIC;", self.schema(), self.name, sig_types(&self.sig))
                    .expect("fmt::Write for String never fails");
            }
        }
        sql
    }

    fn arms_body(&self) -> String {
        let mut b = String::from("#variable_conflict use_column\nBEGIN\n");
        for a in &self.arms {
            write!(b, "  IF {} = {} THEN\n    RETURN {};\n  END IF;\n", self.arm_param, quote_literal(&a.value), a.body)
                .expect("fmt::Write for String never fails");
        }
        b.push_str("  RETURN false;\nEND");
        b
    }

    #[must_use]
    pub fn text(&self) -> String {
        if self.arms.is_empty() {
            return self.body.clone();
        }
        self.arms.iter().map(|a| a.body.as_str()).collect::<Vec<_>>().join("\n")
    }
}

fn sig_types(sig: &str) -> String {
    sig.split(',').map(|p| p.split_whitespace().skip(1).collect::<Vec<_>>().join(" ")).filter(|t| !t.is_empty()).collect::<Vec<_>>().join(", ")
}

pub(crate) fn sig_args(sig: &str) -> Vec<&str> {
    sig.split(',').filter_map(|p| p.split_whitespace().next()).collect()
}

pub(crate) fn binds_every(sig: &str, conjuncts: &[&[String]]) -> bool {
    sig_args(sig).iter().all(|arg| conjuncts.iter().all(|conj| binds_arg(conj, arg)))
}

fn binds_arg(conj: &[String], arg: &str) -> bool {
    let suffix = format!(" = {arg}");
    conj.iter().any(|c| c.ends_with(&suffix))
}

#[must_use]
pub fn definers_sql(defs: &[GenFn]) -> String {
    let mut b = String::new();
    for d in defs {
        b.push_str(&d.create_sql());
        b.push_str("\n\n");
    }
    b
}

pub(crate) fn grant_edge_exists(edge: &str, conjuncts: &[String]) -> String {
    format!("EXISTS (SELECT 1 FROM {} WHERE {})", edge, conjuncts.join(" AND "))
}
