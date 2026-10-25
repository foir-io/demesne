use crate::query_error;
use postgres::{Client, Transaction};
use std::collections::{BTreeMap, BTreeSet};

/// How serious a schema trap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Rows reach readers that the policies would refuse.
    Danger,
    /// Tenancy or performance is weakened, though no policy is bypassed.
    Warning,
}

/// One trap in the live schema around the tables a spec governs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trap {
    /// How serious it is.
    pub severity: Severity,
    /// What the trap is and how to remove it.
    pub message: String,
}

/// Finds the schema traps that bypass or weaken the policies on the `governed` tables.
///
/// They are: a view or materialized view that reads a governed table as its owner rather than its caller; a unique index over a nullable column in `scope_columns`, as `(table, column)`, that lets rows where the column is NULL repeat; and a policy comparison whose row column is wrapped in an expression, so the comparison cannot use an index on the column.
///
/// # Errors
///
/// A catalog query fails.
pub fn schema_traps(client: &mut Client, governed: &[String], scope_columns: &[(String, String)]) -> Result<Vec<Trap>, String> {
    let mut tx = client.transaction().map_err(|e| query_error(&e))?;
    tx.batch_execute("SET LOCAL search_path = ''").map_err(|e| query_error(&e))?;
    let mut oids = Vec::new();
    for t in governed {
        let oid: Option<u32> = tx.query_one("SELECT to_regclass($1)::oid", &[t]).map_err(|e| query_error(&e))?.get(0);
        oids.extend(oid);
    }
    let mut traps = owner_views(&mut tx, &oids)?;
    traps.extend(nullable_unique(&mut tx, scope_columns)?);
    traps.extend(wrapped_columns(&mut tx, &oids)?);
    tx.rollback().map_err(|e| query_error(&e))?;
    Ok(traps)
}

fn owner_views(tx: &mut Transaction<'_>, governed: &[u32]) -> Result<Vec<Trap>, String> {
    let rows = tx
        .query(
            "WITH RECURSIVE deps AS (
               SELECT DISTINCT r.ev_class AS view, d.refobjid AS rel
                 FROM pg_rewrite r JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid AND d.refclassid = 'pg_class'::regclass
                WHERE d.refobjid <> r.ev_class
             ), over AS (
               SELECT view, rel AS base FROM deps WHERE rel = ANY($1)
               UNION
               SELECT d.view, o.base FROM deps d JOIN over o ON d.rel = o.view
             )
             SELECT c.oid::regclass::text, c.relkind = 'm', pg_get_userbyid(c.relowner)::text, ro.rolsuper OR ro.rolbypassrls,
                    string_agg(DISTINCT o.base::regclass::text, ', ' ORDER BY o.base::regclass::text)
               FROM over o JOIN pg_class c ON c.oid = o.view JOIN pg_roles ro ON ro.oid = c.relowner
              WHERE NOT coalesce((SELECT option_value::boolean FROM pg_options_to_table(c.reloptions) WHERE option_name = 'security_invoker'), false)
              GROUP BY c.oid, c.relkind, c.relowner, ro.rolsuper, ro.rolbypassrls
              ORDER BY 1",
            &[&governed],
        )
        .map_err(|e| query_error(&e))?;
    Ok(rows
        .iter()
        .map(|r| {
            let (view, materialized, owner, bypasses, bases): (String, bool, String, bool, String) = (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4));
            let severity = if bypasses { Severity::Danger } else { Severity::Warning };
            let who = if bypasses { format!("its owner {owner}, who bypasses row level security, so every reader sees every row") } else { format!("its owner {owner}, so the policies judge {owner}, not the reader") };
            let message = if materialized {
                format!("materialized view {view} over governed {bases} holds the rows read at refresh by {who}: revoke access to it, or replace it with a view WITH (security_invoker = true)")
            } else {
                format!("view {view} over governed {bases} reads as {who}: ALTER VIEW {view} SET (security_invoker = true)")
            };
            Trap { severity, message }
        })
        .collect())
}

struct UniqueIndex {
    name: String,
    keys: Vec<i16>,
    exprs: String,
    pred: String,
    nulls_not_distinct: bool,
}

fn nullable_unique(tx: &mut Transaction<'_>, scope_columns: &[(String, String)]) -> Result<Vec<Trap>, String> {
    let mut by_table: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (t, c) in scope_columns {
        by_table.entry(t.as_str()).or_default().push(c.clone());
    }
    let version: i32 = tx.query_one("SELECT current_setting('server_version_num')::int", &[]).map_err(|e| query_error(&e))?.get(0);
    let nulls_not_distinct = if version >= 150_000 { "i.indnullsnotdistinct" } else { "false" };
    let mut traps = Vec::new();
    for (table, cols) in by_table {
        let indexes: Vec<UniqueIndex> = tx
            .query(
                &format!(
                    "SELECT i.indexrelid::regclass::text, i.indkey::int2[], coalesce(pg_get_expr(i.indexprs, i.indrelid), ''), coalesce(pg_get_expr(i.indpred, i.indrelid), ''), {nulls_not_distinct}
                       FROM pg_index i WHERE i.indisunique AND i.indrelid = to_regclass($1) ORDER BY 1"
                ),
                &[&table],
            )
            .map_err(|e| query_error(&e))?
            .iter()
            .map(|r| UniqueIndex { name: r.get(0), keys: r.get(1), exprs: r.get(2), pred: r.get(3), nulls_not_distinct: r.get(4) })
            .collect();
        let nullable: Vec<(i16, String)> = tx
            .query("SELECT attnum, attname::text FROM pg_attribute WHERE attrelid = to_regclass($1) AND attname = ANY($2) AND attnum > 0 AND NOT attnotnull ORDER BY attnum", &[&table, &cols])
            .map_err(|e| query_error(&e))?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        for u in indexes.iter().filter(|u| !u.nulls_not_distinct) {
            let open = nullable.iter().filter(|(n, c)| u.keys.contains(n) && !covers_null_tier(&indexes, u, *n, c));
            traps.extend(open.map(|(_, col)| Trap {
                severity: Severity::Warning,
                message: format!(
                    "unique index {} on {table} includes the nullable scope column {col} without NULLS NOT DISTINCT, so rows where {col} is NULL, the shared tier, never conflict: recreate it with NULLS NOT DISTINCT, or add a partial unique index on its other columns WHERE {col} IS NULL",
                    u.name
                ),
            }));
        }
    }
    Ok(traps)
}

fn covers_null_tier(indexes: &[UniqueIndex], u: &UniqueIndex, attnum: i16, col: &str) -> bool {
    let mut rest: Vec<i16> = u.keys.iter().copied().filter(|k| *k != attnum).collect();
    rest.sort_unstable();
    indexes.iter().any(|p| {
        let mut keys = p.keys.clone();
        keys.sort_unstable();
        keys == rest && p.exprs == u.exprs && p.pred.contains(&format!("({col} IS NULL)"))
    })
}

fn wrapped_columns(tx: &mut Transaction<'_>, governed: &[u32]) -> Result<Vec<Trap>, String> {
    let rows = tx
        .query(
            "SELECT pol.polname::text, pol.polrelid, pol.polrelid::regclass::text, coalesce(pol.polqual::text, ''), coalesce(pol.polwithcheck::text, '')
               FROM pg_policy pol WHERE pol.polrelid = ANY($1) ORDER BY 3, 1",
            &[&governed],
        )
        .map_err(|e| query_error(&e))?;
    let mut traps = Vec::new();
    for r in rows {
        let (policy, relid, table): (String, u32, String) = (r.get(0), r.get(1), r.get(2));
        let mut found = BTreeSet::new();
        for tree in [r.get::<_, String>(3), r.get::<_, String>(4)] {
            if let Some(node) = parse(&tree) {
                comparisons(&node, &mut found);
            }
        }
        for (attno, wrapper) in found {
            let (function, operator) = wrapper.oids();
            let row = tx
                .query_one(
                    "SELECT (SELECT attname::text FROM pg_attribute WHERE attrelid = $1 AND attnum = $2),
                            coalesce((SELECT proname::text FROM pg_proc WHERE oid = $3), (SELECT oprname::text FROM pg_operator WHERE oid = $4))",
                    &[&relid, &attno, &function, &operator],
                )
                .map_err(|e| query_error(&e))?;
            let (col, function): (Option<String>, Option<String>) = (row.get(0), row.get(1));
            let col = col.unwrap_or_else(|| format!("column {attno}"));
            traps.push(Trap {
                severity: Severity::Warning,
                message: format!(
                    "policy {policy} on {table} compares {col} through {}, so the comparison cannot use an index on {col} and is checked row by row: compare the bare column, or index the expression",
                    wrapper.describe(function.as_deref())
                ),
            });
        }
    }
    Ok(traps)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Wrapper {
    Coalesce,
    NullIf,
    Case,
    Cast,
    Function(u32),
    Operator(u32),
}

impl Wrapper {
    fn oids(&self) -> (u32, u32) {
        match self {
            Self::Function(oid) => (*oid, 0),
            Self::Operator(oid) => (0, *oid),
            _ => (0, 0),
        }
    }

    fn describe(&self, name: Option<&str>) -> String {
        let name = |oid: u32| name.map_or_else(|| oid.to_string(), String::from);
        match self {
            Self::Coalesce => "COALESCE".into(),
            Self::NullIf => "NULLIF".into(),
            Self::Case => "CASE".into(),
            Self::Cast => "a cast through text".into(),
            Self::Function(oid) => format!("{}()", name(*oid)),
            Self::Operator(oid) => format!("the operator {}", name(*oid)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Struct(String, Vec<(String, Node)>),
    List(Vec<Node>),
    Atom(String),
}

impl Node {
    fn kind(&self) -> &str {
        match self {
            Self::Struct(k, _) => k,
            _ => "",
        }
    }

    fn field(&self, name: &str) -> Option<&Node> {
        match self {
            Self::Struct(_, fields) => fields.iter().find(|(f, _)| f == name).map(|(_, v)| v),
            _ => None,
        }
    }

    fn atom(&self, name: &str) -> Option<&str> {
        match self.field(name) {
            Some(Self::Atom(a)) => Some(a),
            _ => None,
        }
    }

    fn args(&self) -> &[Node] {
        match self.field("args") {
            Some(Self::List(items)) => items,
            _ => &[],
        }
    }

    fn row_column(&self) -> Option<i16> {
        if self.kind() == "VAR" { self.atom("varattno")?.parse().ok() } else { None }
    }

    fn wrapped_column(&self) -> Option<i16> {
        if let Some(col) = self.row_column() {
            return Some(col);
        }
        match self {
            Self::Struct(kind, fields) if kind != "SUBLINK" => fields.iter().find_map(|(_, v)| v.wrapped_column()),
            Self::List(items) => items.iter().find_map(Node::wrapped_column),
            _ => None,
        }
    }

    fn wrapper(&self) -> Option<Wrapper> {
        match self.kind() {
            "COALESCEEXPR" => Some(Wrapper::Coalesce),
            "NULLIFEXPR" => Some(Wrapper::NullIf),
            "CASEEXPR" => Some(Wrapper::Case),
            "COERCEVIAIO" => Some(Wrapper::Cast),
            "FUNCEXPR" => self.atom("funcid")?.parse().ok().map(Wrapper::Function),
            "OPEXPR" => self.atom("opno")?.parse().ok().map(Wrapper::Operator),
            _ => None,
        }
    }
}

fn comparisons(node: &Node, found: &mut BTreeSet<(i16, Wrapper)>) {
    match node.kind() {
        "BOOLEXPR" => node.args().iter().for_each(|a| comparisons(a, found)),
        "OPEXPR" | "SCALARARRAYOPEXPR" | "DISTINCTEXPR" => {
            for arg in node.args() {
                if let (Some(w), Some(col)) = (arg.wrapper(), arg.wrapped_column()) {
                    found.insert((col, w));
                }
            }
        }
        _ => {}
    }
}

fn parse(src: &str) -> Option<Node> {
    let tokens = tokens(src);
    let mut i = 0;
    value(&tokens, &mut i)
}

fn tokens(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '{' | '}' | '(' | ')' => out.push(c.to_string()),
            '[' => {
                let _ = chars.by_ref().find(|d| *d == ']');
                out.push("[]".into());
            }
            _ => out.push(atom(c, &mut chars)),
        }
    }
    out
}

fn atom(first: char, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut s = String::new();
    let mut next = Some(first);
    while let Some(d) = next {
        if d == '\\' {
            s.extend(chars.next());
        } else {
            s.push(d);
        }
        next = chars.next_if(|d| !d.is_whitespace() && !"{}()".contains(*d));
    }
    s
}

fn value(tokens: &[String], i: &mut usize) -> Option<Node> {
    let t = tokens.get(*i)?.clone();
    *i += 1;
    match t.as_str() {
        "{" => {
            let kind = tokens.get(*i)?.clone();
            *i += 1;
            let mut fields = Vec::new();
            while let Some(t) = tokens.get(*i) {
                if t == "}" {
                    *i += 1;
                    break;
                }
                let name = t.strip_prefix(':').map(String::from);
                *i += 1;
                let Some(name) = name else { continue };
                if tokens.get(*i).is_some_and(|n| n == "}" || n.starts_with(':')) {
                    fields.push((name, Node::Atom(String::new())));
                    continue;
                }
                let v = value(tokens, i)?;
                fields.push((name, v));
            }
            Some(Node::Struct(kind, fields))
        }
        "(" => {
            let mut items = Vec::new();
            while tokens.get(*i).is_some_and(|t| t != ")") {
                items.push(value(tokens, i)?);
            }
            *i += 1;
            Some(Node::List(items))
        }
        _ => Some(Node::Atom(t)),
    }
}
