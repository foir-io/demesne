#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefinerArm {
    pub value: String,
    pub body: String,
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
}

impl GenFn {
    pub fn schema(&self) -> &str {
        if self.schema.is_empty() { "auth" } else { &self.schema }
    }

    pub fn table_schema(&self) -> &str {
        if self.table_schema.is_empty() { "public" } else { &self.table_schema }
    }

    pub fn arg_types(&self) -> String {
        if self.sig.trim().is_empty() {
            return String::new();
        }
        self.sig
            .split(',')
            .map(|p| p.split_whitespace().last().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn create_sql(&self) -> String {
        let returns = if self.returns.is_empty() { "boolean" } else { &self.returns };
        let (mut lang, mut body) = ("sql", format!("  SELECT {};", self.body));
        if self.raw_body {
            body = self.body.clone();
        }
        if !self.arms.is_empty() {
            lang = "plpgsql";
            body = self.arms_body();
        }
        let strict = if self.strict { "STRICT\n" } else { "" };
        format!(
            "CREATE OR REPLACE FUNCTION {}.{}({})\nRETURNS {}\nLANGUAGE {}\nSTABLE\n{}SECURITY DEFINER\nSET search_path = {}\nAS $$\n{}\n$$;",
            self.schema(),
            self.name,
            self.sig,
            returns,
            lang,
            strict,
            self.table_schema(),
            body
        )
    }

    fn arms_body(&self) -> String {
        let mut b = String::from("#variable_conflict use_column\nBEGIN\n");
        for a in &self.arms {
            b.push_str(&format!("  IF {} = '{}' THEN\n    RETURN {};\n  END IF;\n", self.arm_param, a.value, a.body));
        }
        b.push_str("  RETURN false;\nEND");
        b
    }

    pub fn text(&self) -> String {
        if self.arms.is_empty() {
            return self.body.clone();
        }
        self.arms.iter().map(|a| a.body.as_str()).collect::<Vec<_>>().join("\n")
    }
}

pub fn sig_args(sig: &str) -> Vec<&str> {
    sig.split(',').filter_map(|p| p.split_whitespace().next()).collect()
}

pub fn binds_every(sig: &str, conjuncts: &[&[String]]) -> bool {
    sig_args(sig).iter().all(|arg| conjuncts.iter().all(|conj| binds_arg(conj, arg)))
}

fn binds_arg(conj: &[String], arg: &str) -> bool {
    let suffix = format!(" = {arg}");
    conj.iter().any(|c| c.ends_with(&suffix))
}

pub fn definers_sql(defs: &[GenFn]) -> String {
    let mut b = String::new();
    for d in defs {
        b.push_str(&d.create_sql());
        b.push_str("\n\n");
    }
    b
}

pub fn grant_edge_exists(edge: &str, conjuncts: &[String]) -> String {
    format!("EXISTS (SELECT 1 FROM {} WHERE {})", edge, conjuncts.join(" AND "))
}
