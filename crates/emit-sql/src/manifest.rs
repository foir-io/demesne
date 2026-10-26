use crate::Sql;
use crate::error::{Error, ManifestError};
use crate::genfn::definers_sql;
use demesne_gocompat::json::{self, Value};
use demesne_gocompat::quote;
use std::collections::BTreeSet;
use std::fmt::Write as _;

const FORMAT: i64 = 1;

/// Every database object a spec's SQL creates, recorded so that the next migration can drop what a later spec no longer emits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Functions by identity signature, such as `auth.notes_accessors(text)`.
    pub functions: BTreeSet<String>,
    /// Policies as `(table, name)`.
    pub policies: BTreeSet<(String, String)>,
    /// Triggers as `(table, name)`.
    pub triggers: BTreeSet<(String, String)>,
    /// Indexes as `(table, name)`.
    pub indexes: BTreeSet<(String, String)>,
    /// Tables the SQL creates.
    pub tables: BTreeSet<String>,
    /// Tables the SQL enables row level security on.
    pub rls: BTreeSet<String>,
}

impl Manifest {
    /// Reads the objects a script creates.
    ///
    /// # Errors
    ///
    /// A `CREATE` statement of a kind the manifest does not record, or one it cannot read the identity of.
    pub fn from_sql(sql: &str) -> Result<Self, ManifestError> {
        let mut m = Self::default();
        for (object, _) in objects(sql)? {
            match object {
                Object::Function(sig) => m.functions.insert(sig),
                Object::Policy { table, name } => m.policies.insert((table, name)),
                Object::Trigger { table, name } => m.triggers.insert((table, name)),
                Object::Index { table, name } => m.indexes.insert((table, name)),
                Object::Table(t) => m.tables.insert(t),
                Object::Rls(t) => m.rls.insert(t),
            };
        }
        Ok(m)
    }

    /// Reads a manifest written by [`Manifest::to_json`].
    ///
    /// # Errors
    ///
    /// Text that is not JSON, or JSON that is not a manifest of this format.
    pub fn from_json(src: &str) -> Result<Self, ManifestError> {
        Self::read_json(src).map_err(ManifestError::new)
    }

    fn read_json(src: &str) -> Result<Self, String> {
        let v = json::parse(src).map_err(|e| format!("manifest: {e}"))?;
        match v.get("manifest").and_then(Value::as_i64) {
            Some(FORMAT) => {}
            Some(n) => return Err(format!("manifest: format {n} is not one this demesne reads (it reads format {FORMAT})")),
            None => return Err("manifest: not a demesne manifest (no \"manifest\" format field)".into()),
        }
        let names = |key: &str| -> Result<BTreeSet<String>, String> {
            let Some(items) = v.get(key).and_then(Value::as_array) else { return Err(format!("manifest: {} is not a list", quote(key))) };
            items.iter().map(|i| i.as_str().map(String::from).ok_or_else(|| format!("manifest: an entry of {} is not a string", quote(key)))).collect()
        };
        let pairs = |key: &str| -> Result<BTreeSet<(String, String)>, String> {
            let Some(items) = v.get(key).and_then(Value::as_array) else { return Err(format!("manifest: {} is not a list", quote(key))) };
            items
                .iter()
                .map(|i| match (i.get("table").and_then(Value::as_str), i.get("name").and_then(Value::as_str)) {
                    (Some(t), Some(n)) => Ok((t.to_string(), n.to_string())),
                    _ => Err(format!("manifest: an entry of {} needs a table and a name", quote(key))),
                })
                .collect()
        };
        Ok(Self {
            functions: names("functions")?,
            policies: pairs("policies")?,
            triggers: pairs("triggers")?,
            indexes: pairs("indexes")?,
            tables: names("tables")?,
            rls: names("rls")?,
        })
    }

    /// Writes the manifest as indented JSON, each list sorted.
    #[must_use]
    pub fn to_json(&self) -> String {
        let names = |xs: &BTreeSet<String>| Value::Array(xs.iter().map(|x| Value::str(x.as_str())).collect());
        let pairs = |xs: &BTreeSet<(String, String)>| {
            Value::Array(
                xs.iter().map(|(t, n)| Value::Struct(vec![("table".into(), Value::str(t.as_str())), ("name".into(), Value::str(n.as_str()))])).collect(),
            )
        };
        let v = Value::Struct(vec![
            ("manifest".into(), Value::Int(FORMAT)),
            ("functions".into(), names(&self.functions)),
            ("policies".into(), pairs(&self.policies)),
            ("triggers".into(), pairs(&self.triggers)),
            ("indexes".into(), pairs(&self.indexes)),
            ("tables".into(), names(&self.tables)),
            ("rls".into(), names(&self.rls)),
        ]);
        let mut out = json::marshal_indent(&v, "", "  ");
        out.push('\n');
        out
    }

    /// Returns the SQL that removes what `previous` created and this manifest does not: exact drops, then a check that fails the migration if any of them survived.
    ///
    /// Tables are not dropped, as they hold data, and row level security stays enabled on a table no longer governed, so that it fails closed; both are named in comments.
    #[must_use]
    pub fn drops_since(&self, previous: &Self) -> String {
        let triggers: Vec<_> = previous.triggers.difference(&self.triggers).collect();
        let policies: Vec<_> = previous.policies.difference(&self.policies).collect();
        let indexes: Vec<_> = previous.indexes.difference(&self.indexes).collect();
        let functions: Vec<_> = previous.functions.difference(&self.functions).collect();
        let tables: Vec<_> = previous.tables.difference(&self.tables).collect();
        let ungoverned: Vec<_> = previous.rls.difference(&self.rls).collect();
        if triggers.is_empty() && policies.is_empty() && indexes.is_empty() && functions.is_empty() && tables.is_empty() && ungoverned.is_empty() {
            return String::new();
        }
        let mut b = String::from("\n-- ===== Dropped since the previous manifest =====\n");
        for (table, name) in &triggers {
            writeln!(b, "DROP TRIGGER IF EXISTS {name} ON {table};").expect("fmt::Write for String never fails");
        }
        for (table, name) in &policies {
            writeln!(b, "DROP POLICY IF EXISTS {name} ON {table};").expect("fmt::Write for String never fails");
        }
        for (table, name) in &indexes {
            writeln!(b, "DROP INDEX IF EXISTS {};", sibling(table, name)).expect("fmt::Write for String never fails");
        }
        for f in &functions {
            writeln!(b, "DROP FUNCTION IF EXISTS {f};").expect("fmt::Write for String never fails");
        }
        if !(triggers.is_empty() && policies.is_empty() && indexes.is_empty() && functions.is_empty()) {
            b.push_str(&self.survivor_check(&triggers, &policies, &indexes, &functions));
        }
        for t in &tables {
            writeln!(b, "-- table {t} is no longer emitted; it is not dropped, as it holds data: drop it once nothing reads it")
                .expect("fmt::Write for String never fails");
        }
        for t in &ungoverned {
            writeln!(b, "-- table {t} is no longer governed; row level security stays enabled and forced, so only roles that bypass it can read the table: disable it deliberately if that is intended")
                .expect("fmt::Write for String never fails");
        }
        b
    }

    fn survivor_check(&self, triggers: &[&(String, String)], policies: &[&(String, String)], indexes: &[&(String, String)], functions: &[&String]) -> String {
        let mut arms = Vec::new();
        if !functions.is_empty() {
            let names: BTreeSet<(String, String)> = functions.iter().map(|f| function_name(f)).collect();
            let kept: Vec<String> =
                self.functions.iter().filter(|f| names.contains(&function_name(f))).map(|f| format!("to_regprocedure({})::oid", literal(f))).collect();
            arms.push(format!(
                "SELECT 'function ' || p.oid::regprocedure::text AS what\n      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace\n      WHERE (n.nspname, p.proname) IN ({})\n        AND p.oid <> ALL (array_remove(ARRAY[{}]::oid[], NULL))",
                names.iter().map(|(s, n)| format!("({}::name, {}::name)", literal(s), literal(n))).collect::<Vec<_>>().join(", "),
                kept.join(", ")
            ));
        }
        let on_table = |xs: &[&(String, String)]| {
            xs.iter().map(|(t, n)| format!("(to_regclass({})::oid, {}::name)", literal(t), literal(&ident(n)))).collect::<Vec<_>>().join(", ")
        };
        if !policies.is_empty() {
            arms.push(format!(
                "SELECT 'policy ' || pol.polname || ' on ' || pol.polrelid::regclass::text\n      FROM pg_policy pol\n      WHERE (pol.polrelid, pol.polname) IN ({})",
                on_table(policies)
            ));
        }
        if !triggers.is_empty() {
            arms.push(format!(
                "SELECT 'trigger ' || t.tgname || ' on ' || t.tgrelid::regclass::text\n      FROM pg_trigger t\n      WHERE NOT t.tgisinternal AND (t.tgrelid, t.tgname) IN ({})",
                on_table(triggers)
            ));
        }
        if !indexes.is_empty() {
            arms.push(format!(
                "SELECT 'index ' || c.oid::regclass::text\n      FROM pg_class c\n      WHERE c.oid IN ({})",
                indexes.iter().map(|(t, n)| format!("to_regclass({})::oid", literal(&sibling(t, n)))).collect::<Vec<_>>().join(", ")
            ));
        }
        format!(
            "DO $demesne$\nDECLARE\n  survivors text;\nBEGIN\n  SELECT string_agg(what, ', ' ORDER BY what) INTO survivors FROM (\n    {}\n  ) s;\n  IF survivors IS NOT NULL THEN\n    RAISE EXCEPTION 'demesne: still present after the drops: %', survivors;\n  END IF;\nEND\n$demesne$;\n",
            arms.join("\n    UNION ALL\n    ")
        )
    }
}

/// One object a script creates, by the identity a [`Manifest`] records it under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Object {
    /// A function, by identity signature, such as `auth.notes_accessors(text)`.
    Function(String),
    /// A policy on a table.
    Policy {
        /// The table, as the script names it.
        table: String,
        /// The policy's name.
        name: String,
    },
    /// A trigger on a table.
    Trigger {
        /// The table, as the script names it.
        table: String,
        /// The trigger's name.
        name: String,
    },
    /// An index on a table.
    Index {
        /// The table, as the script names it.
        table: String,
        /// The index's name.
        name: String,
    },
    /// A table the script creates.
    Table(String),
    /// A table the script enables row level security on.
    Rls(String),
}

/// Returns each statement of `sql` that creates an object or enables row level security, with that object, in script order.
///
/// # Errors
///
/// A `CREATE` statement of a kind the manifest does not record, or one it cannot read the identity of.
pub fn objects(sql: &str) -> Result<Vec<(Object, String)>, ManifestError> {
    read_objects(sql).map_err(ManifestError::new)
}

fn read_objects(sql: &str) -> Result<Vec<(Object, String)>, String> {
    let mut out = Vec::new();
    for stmt in statements(sql) {
        let words: Vec<&str> = stmt.split_whitespace().collect();
        let object = match words.as_slice() {
            ["CREATE", "OR", "REPLACE", "FUNCTION", ..] | ["CREATE", "FUNCTION", ..] => Object::Function(function_signature(&stmt)?),
            ["CREATE", "POLICY", name, "ON", table, ..] => Object::Policy { table: (*table).to_string(), name: (*name).to_string() },
            ["CREATE", "OR", "REPLACE", "TRIGGER", name, rest @ ..] | ["CREATE", "TRIGGER", name, rest @ ..] => {
                Object::Trigger { table: target(rest, &stmt)?, name: (*name).to_string() }
            }
            ["CREATE", "UNIQUE", "INDEX", rest @ ..] | ["CREATE", "INDEX", rest @ ..] => {
                let (table, name) = index_entry(rest, &stmt)?;
                Object::Index { table, name }
            }
            ["CREATE", "TABLE", rest @ ..] => Object::Table(table_name(rest, &stmt)?),
            ["ALTER", "TABLE", table, "ENABLE", "ROW", "LEVEL", "SECURITY"] => Object::Rls((*table).to_string()),
            ["CREATE", ..] => return Err(format!("the manifest does not record this kind of object: {}", first_line(&stmt))),
            _ => continue,
        };
        out.push((object, stmt));
    }
    Ok(out)
}

impl Sql<'_> {
    /// Appends the spec's whole SQL surface to `b`, as `demesne emit <spec> all` prints it. On an error, `b` keeps what was written before it.
    ///
    /// # Errors
    ///
    /// The definers or the policies do not compile, or an `@rls` permission cannot.
    pub fn write_all_sql(&self, b: &mut String) -> Result<(), Error> {
        let flats = self.flats_sql();
        if !flats.is_empty() {
            b.push_str(&flats);
            b.push('\n');
        }
        b.push_str(&definers_sql(&self.emit_definers()?));
        b.push('\n');
        let res = self.emit_rls()?;
        b.push_str(&res.enablement_sql());
        b.push('\n');
        if !res.unsupported.is_empty() {
            return Err(Error::unplaced(format!("spec has uncompilable @rls permissions: {}", res.unsupported.join("; "))));
        }
        b.push_str(&res.policy_sql("authenticated"));
        for part in [self.triggers_sql(), self.changelog_sql(), self.async_sql()] {
            if !part.is_empty() {
                b.push('\n');
                b.push_str(&part);
            }
        }
        Ok(())
    }

    /// Returns the manifest of everything [`Sql::write_all_sql`] creates.
    ///
    /// # Errors
    ///
    /// The SQL does not compile, or it creates an object the manifest does not record.
    pub fn manifest(&self) -> Result<Manifest, Error> {
        let mut b = String::new();
        self.write_all_sql(&mut b)?;
        Manifest::from_sql(&b).map_err(|e| Error::unplaced(e.to_string()))
    }

    /// Returns a migration from the surface `previous` records to this spec's: the whole SQL, then [`Manifest::drops_since`].
    ///
    /// # Errors
    ///
    /// The SQL does not compile, or it creates an object the manifest does not record.
    pub fn migration(&self, previous: &Manifest) -> Result<String, Error> {
        let mut b = String::new();
        self.write_all_sql(&mut b)?;
        let drops = Manifest::from_sql(&b).map_err(|e| Error::unplaced(e.to_string()))?.drops_since(previous);
        b.push_str(&drops);
        Ok(b)
    }
}

fn statements(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '-' && chars.get(i + 1) == Some(&'-') {
            i += chars[i..].iter().take_while(|c| **c != '\n').count();
            cur.push(' ');
        } else if let Some(end) = quoted_end(&chars, i) {
            cur.extend(&chars[i..end]);
            i = end;
        } else if chars[i] == ';' {
            out.push(std::mem::take(&mut cur).trim().to_string());
            i += 1;
        } else {
            cur.push(chars[i]);
            i += 1;
        }
    }
    out.push(cur.trim().to_string());
    out.retain(|s| !s.is_empty());
    out
}

fn quoted_end(chars: &[char], start: usize) -> Option<usize> {
    let q = chars[start];
    if q == '\'' || q == '"' {
        return Some(chars[start + 1..].iter().position(|c| *c == q).map_or(chars.len(), |k| start + k + 2));
    }
    if q != '$' {
        return None;
    }
    let len = dollar_tag(&chars[start..])?;
    let tag = &chars[start..start + len];
    let close = (start + len..chars.len()).find(|&j| chars[j..].starts_with(tag)).unwrap_or(chars.len());
    Some((close + len).min(chars.len()))
}

fn dollar_tag(chars: &[char]) -> Option<usize> {
    let body = chars.iter().skip(1).take_while(|c| c.is_ascii_alphanumeric() || **c == '_').count();
    if chars.get(1).is_some_and(char::is_ascii_digit) {
        return None;
    }
    (chars.get(1 + body) == Some(&'$')).then_some(body + 2)
}

fn function_signature(stmt: &str) -> Result<String, String> {
    let after = stmt.split_once("FUNCTION").map(|(_, a)| a.trim_start()).ok_or_else(|| unreadable(stmt))?;
    let open = after.find('(').ok_or_else(|| unreadable(stmt))?;
    let name = after[..open].trim();
    if function_name(name).0.is_empty() {
        return Err(format!("the manifest needs a schema-qualified function name, so the drop is exact: {}", first_line(stmt)));
    }
    let mut depth = 0usize;
    let mut close = None;
    for (k, c) in after[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + k);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.ok_or_else(|| unreadable(stmt))?;
    let mut types = Vec::new();
    for arg in split_args(&after[open + 1..close]) {
        let words: Vec<&str> = arg.split_whitespace().collect();
        let modal = words.first().is_some_and(|w| ["IN", "OUT", "INOUT", "VARIADIC"].contains(&w.to_ascii_uppercase().as_str()));
        if modal || words.len() < 2 || arg.contains('=') || words.iter().any(|w| w.eq_ignore_ascii_case("DEFAULT")) {
            return Err(format!("the manifest reads only arguments written as `name type`: {} in {}", quote(&arg), first_line(stmt)));
        }
        types.push(words[1..].join(" "));
    }
    Ok(format!("{name}({})", types.join(", ")))
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur.trim().to_string());
    out.retain(|a| !a.is_empty());
    out
}

fn index_entry(rest: &[&str], stmt: &str) -> Result<(String, String), String> {
    let rest = rest.strip_prefix(&["IF", "NOT", "EXISTS"][..]).unwrap_or(rest);
    let [name, tail @ ..] = rest else { return Err(unreadable(stmt)) };
    Ok((target(tail, stmt)?, (*name).to_string()))
}

fn table_name(rest: &[&str], stmt: &str) -> Result<String, String> {
    let rest = rest.strip_prefix(&["IF", "NOT", "EXISTS"][..]).unwrap_or(rest);
    rest.first().map(|n| n.split('(').next().unwrap_or_default()).filter(|n| !n.is_empty()).map(String::from).ok_or_else(|| unreadable(stmt))
}

fn target(words: &[&str], stmt: &str) -> Result<String, String> {
    words
        .iter()
        .position(|w| *w == "ON")
        .and_then(|k| words.get(k + 1))
        .map(|t| t.split('(').next().unwrap_or_default())
        .filter(|t| !t.is_empty())
        .map(String::from)
        .ok_or_else(|| unreadable(stmt))
}

fn function_name(signature: &str) -> (String, String) {
    let name = signature.split('(').next().unwrap_or_default();
    let parts = qualified(name);
    match parts.as_slice() {
        [schema, name] => (schema.clone(), name.clone()),
        _ => (String::new(), parts.last().cloned().unwrap_or_default()),
    }
}

fn qualified(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in name.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            '.' if !quoted => parts.push(ident(&std::mem::take(&mut cur))),
            _ => cur.push(c),
        }
    }
    parts.push(ident(&cur));
    parts
}

fn ident(word: &str) -> String {
    match word.strip_prefix('"').and_then(|w| w.strip_suffix('"')) {
        Some(inner) => inner.replace("\"\"", "\""),
        None => word.to_ascii_lowercase(),
    }
}

fn sibling(table: &str, name: &str) -> String {
    let mut quoted = false;
    let mut dot = None;
    for (k, c) in table.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '.' if !quoted => dot = Some(k),
            _ => {}
        }
    }
    match dot {
        Some(k) => format!("{}.{name}", &table[..k]),
        None => name.to_string(),
    }
}

fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn first_line(stmt: &str) -> &str {
    stmt.lines().next().unwrap_or_default()
}

fn unreadable(stmt: &str) -> String {
    format!("the manifest cannot read the identity of: {}", first_line(stmt))
}
