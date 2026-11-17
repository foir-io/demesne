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
    /// Every role: the SQL grants execute to PUBLIC, so applying it again restores what a revoke took away.
    #[default]
    Public,
    /// No role but the definer's owner: execute is revoked from PUBLIC, and only generated functions call it.
    Revoked,
    /// The roles the adopter grants it to: execute is revoked from PUBLIC, and the function is an interface for such a role.
    Grantable,
}

impl Execute {
    pub(crate) fn statement(self, function: &str, arg_types: &str) -> String {
        match self {
            Execute::Public => format!("GRANT EXECUTE ON FUNCTION {function}({arg_types}) TO PUBLIC;"),
            Execute::Revoked | Execute::Grantable => format!("REVOKE EXECUTE ON FUNCTION {function}({arg_types}) FROM PUBLIC;"),
        }
    }
}

pub(crate) enum Arg {
    Fixed(String),
    Row(String),
}

pub(crate) fn definer_call(function: &str, args: &[Arg]) -> String {
    let list = args.iter().map(|a| match a {
        Arg::Fixed(s) | Arg::Row(s) => s.as_str(),
    });
    let call = format!("{function}({})", list.collect::<Vec<_>>().join(", "));
    if args.iter().all(|a| matches!(a, Arg::Fixed(_))) { format!("(SELECT {call})") } else { call }
}

/// A parameter of a generated function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Param {
    /// The parameter's name, such as `p_doc_id`.
    pub name: String,
    /// What the parameter holds, which decides its type.
    pub kind: ParamKind,
}

/// What a generated function's parameter holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParamKind {
    /// The id of a subject, an object or a level's node, typed as the spec's identifiers.
    Id,
    /// An array of such ids.
    Ids,
    /// A value of the named SQL type, such as `text` for an access or `jsonb` for claims.
    Typed(String),
}

impl Param {
    /// A parameter that holds an id, typed as the spec's identifiers.
    #[must_use]
    pub fn id(name: impl Into<String>) -> Self {
        Self { name: name.into(), kind: ParamKind::Id }
    }

    /// A parameter that holds an array of ids.
    #[must_use]
    pub fn ids(name: impl Into<String>) -> Self {
        Self { name: name.into(), kind: ParamKind::Ids }
    }

    /// A parameter of the named SQL type.
    #[must_use]
    pub fn typed(name: impl Into<String>, sql_type: impl Into<String>) -> Self {
        Self { name: name.into(), kind: ParamKind::Typed(sql_type.into()) }
    }
}

/// Returns `params` as a signature, each id typed as `id_type`, such as `p_doc_id text, p_access text`.
#[must_use]
pub fn render(params: &[Param], id_type: &str) -> String {
    let typed = |p: &Param| match &p.kind {
        ParamKind::Id => format!("{} {id_type}", p.name),
        ParamKind::Ids => format!("{} {id_type}[]", p.name),
        ParamKind::Typed(t) => format!("{} {t}", p.name),
    };
    params.iter().map(typed).collect::<Vec<_>>().join(", ")
}

/// What the SQL does before it creates a definer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Before {
    /// Nothing.
    #[default]
    Nothing,
    /// Drops a function of the same name and argument types whose parameters are named otherwise, since
    /// `CREATE OR REPLACE` cannot rename a parameter. Only a function no policy calls is marked so, since a policy that
    /// calls a function keeps it from being dropped.
    DropRenamed,
}

/// How a function PUBLIC may run is bound to the caller's own claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bound {
    /// The position of the argument that must be the caller's own.
    pub argument: usize,
    /// The expressions that read the claims the argument may equal.
    pub claims: Vec<String>,
    /// The PL/pgSQL body of the copy PUBLIC cannot run, which another generated function calls with one of `claims`.
    pub inside: String,
    /// The PL/pgSQL body that remembers a verified argument for as long as the claims setting keeps its text.
    pub remembered: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenFn {
    pub name: String,
    pub schema: String,
    pub table_schema: String,
    pub params: Vec<Param>,
    /// The spec's identifier type, which every [`ParamKind::Id`] parameter takes; `text` when empty.
    pub id_type: String,
    pub body: String,
    pub returns: String,
    pub raw_body: bool,
    pub strict: bool,
    pub arm_param: String,
    pub arms: Vec<DefinerArm>,
    pub language: Language,
    pub execute: Execute,
    pub bound: Option<Bound>,
    /// The parameter the generator filled from a principal. A function PUBLIC may run answers only when it is one of the caller's own claims.
    pub principal: Option<String>,
    /// The identity claims of the subjects whose principal [`GenFn::principal`] holds. A function PUBLIC may run is
    /// bound to these alone, so a caller of one subject is never taken for a principal of another that shares its id.
    pub principal_claims: Vec<String>,
    /// What the SQL does before it creates the function.
    pub before: Before,
}

impl GenFn {
    #[must_use]
    pub fn schema(&self) -> &str {
        if self.schema.is_empty() { "auth" } else { &self.schema }
    }

    /// Returns the parameter list as the SQL declares it.
    #[must_use]
    pub fn sig(&self) -> String {
        render(&self.params, if self.id_type.is_empty() { "text" } else { &self.id_type })
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
        let mut sql = self.before_sql();
        write!(
            sql,
            "CREATE OR REPLACE FUNCTION {}.{}({})\nRETURNS {}\nLANGUAGE {}\nSTABLE\n{}SECURITY DEFINER\nSET search_path = {}, pg_temp\nAS $$\n{}\n$$;",
            self.schema(),
            self.name,
            self.sig(),
            returns,
            lang,
            strict,
            self.table_schema(),
            body
        )
        .expect("fmt::Write for String never fails");
        sql.push('\n');
        sql.push_str(&self.execute.statement(&format!("{}.{}", self.schema(), self.name), &sig_types(&self.sig())));
        sql
    }

    fn before_sql(&self) -> String {
        match self.before {
            Before::Nothing => String::new(),
            Before::DropRenamed => {
                let identity = format!("{}.{}({})", self.schema(), self.name, sig_types(&self.sig()));
                let names: Vec<String> = self.params.iter().map(|p| quote_literal(&p.name)).collect();
                format!(
                    "DO $demesne$ BEGIN\n  IF EXISTS (SELECT 1 FROM pg_proc WHERE oid = to_regprocedure({}) AND proargnames IS DISTINCT FROM ARRAY[{}]::text[]) THEN\n    DROP FUNCTION {identity};\n  END IF;\nEND $demesne$;\n",
                    quote_literal(&identity),
                    names.join(", ")
                )
            }
        }
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

pub(crate) fn sig_types(sig: &str) -> String {
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

pub(crate) fn order_by_calls(fns: Vec<GenFn>) -> Vec<GenFn> {
    let texts: Vec<String> = fns.iter().map(GenFn::create_sql).collect();
    let call_of: Vec<String> = fns.iter().map(|f| format!("{}.{}(", f.schema(), f.name)).collect();
    let deps: Vec<Vec<usize>> = texts.iter().enumerate().map(|(i, t)| (0..fns.len()).filter(|&j| j != i && t.contains(&call_of[j])).collect()).collect();
    let mut placed = vec![false; fns.len()];
    let mut order = Vec::with_capacity(fns.len());
    while order.len() < fns.len() {
        let next = (0..fns.len())
            .find(|&i| !placed[i] && deps[i].iter().all(|&j| placed[j]))
            .or_else(|| (0..fns.len()).find(|&i| !placed[i]))
            .expect("a function is still unplaced while the order is shorter than the list");
        placed[next] = true;
        order.push(next);
    }
    let mut slots: Vec<Option<GenFn>> = fns.into_iter().map(Some).collect();
    order.into_iter().map(|i| slots[i].take().expect("each function is placed once")).collect()
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
