use demesne_emit_sql::{Object, Sql, objects};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const KEYWORDS: [&str; 17] =
    ["select", "from", "as", "null", "true", "false", "and", "or", "not", "is", "in", "case", "when", "then", "else", "end", "distinct"];

fn specs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            specs(&path, out);
        } else if path.extension().is_some_and(|x| x == "demesne") {
            out.push(path);
        }
    }
}

fn corpus() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    specs(&root.join("examples"), &mut paths);
    specs(&root.join("testdata"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| {
            let s = demesne_syntax::parse(&std::fs::read_to_string(&p).ok()?).ok()?;
            demesne_emit_sql::validate(&s).ok()?;
            let mut b = String::new();
            Sql::new(&s).write_all_sql(&mut b).ok()?;
            Some((p.display().to_string(), b))
        })
        .collect()
}

fn body(stmt: &str) -> &str {
    stmt.find("AS $").map_or(stmt, |at| &stmt[at..])
}

fn stable(stmt: &str) -> bool {
    let head = &stmt[..stmt.find("AS $").unwrap_or(stmt.len())];
    head.lines().any(|l| l == "STABLE" || l == "IMMUTABLE")
}

fn without_strings(s: &str) -> String {
    let mut out = String::new();
    let mut quoted = false;
    for c in s.chars() {
        if c == '\'' {
            quoted = !quoted;
            out.push('\'');
        } else if !quoted {
            out.push(c);
        }
    }
    out
}

fn arguments(text: &str, open: usize) -> Option<(&str, usize)> {
    let mut depth = 0;
    let mut quoted = false;
    for (i, c) in text[open..].char_indices() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some((&text[open + 1..open + i], open + i));
                }
            }
            _ => {}
        }
    }
    None
}

fn parameters(stmt: &str) -> BTreeSet<&str> {
    let Some(open) = stmt.find('(') else { return BTreeSet::new() };
    let Some((list, _)) = arguments(stmt, open) else { return BTreeSet::new() };
    list.split(',').filter_map(|p| p.split_whitespace().next()).collect()
}

fn fixed(args: &str, params: &BTreeSet<&str>) -> bool {
    let a = without_strings(args);
    let bytes = a.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut aliases = BTreeSet::new();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let starts = (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') && (i == 0 || !(word(bytes[i - 1]) || bytes[i - 1] == b'$'));
        if !starts {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (word(bytes[i]) || bytes[i] == b'.') {
            i += 1;
        }
        let before = a[..start].trim_end();
        let after = a[i..].trim_start();
        tokens.push((&a[start..i], before.ends_with("::"), after.starts_with('('), before.ends_with(')')));
    }
    for (t, _, _, after_paren) in &tokens {
        if *after_paren && !KEYWORDS.contains(&t.to_ascii_lowercase().as_str()) {
            aliases.insert(*t);
        }
    }
    tokens.iter().all(|(t, cast, call, _)| *cast || *call || KEYWORDS.contains(&t.to_ascii_lowercase().as_str()) || params.contains(t) || aliases.contains(t))
}

struct Corpus {
    specs: usize,
    fixed_calls: usize,
    row_calls: usize,
    volatile_functions: usize,
    bare: Vec<String>,
    wrapped_volatile: Vec<String>,
}

impl Corpus {
    fn calls(&mut self, at: &str, text: &str, params: &BTreeSet<&str>, name: &str, stable: bool, reads_claims: bool) {
        for (start, _) in text.match_indices(&format!("{name}(")) {
            let Some((args, close)) = arguments(text, start + name.len()) else { continue };
            let wrapped = text[..start].trim_end().ends_with("(SELECT") && text[close + 1..].starts_with(')');
            let site = || format!("{at}: {}", &text[start.saturating_sub(60)..(close + 1).min(text.len())]);
            let fixed_claims = stable && reads_claims && fixed(args, params);
            self.fixed_calls += usize::from(fixed_claims);
            self.row_calls += usize::from(stable && reads_claims && !fixed_claims);
            if !stable && wrapped {
                self.wrapped_volatile.push(site());
            }
            if fixed_claims && !wrapped {
                self.bare.push(site());
            }
        }
    }
}

fn scan() -> Corpus {
    let mut c = Corpus { specs: 0, fixed_calls: 0, row_calls: 0, volatile_functions: 0, bare: Vec::new(), wrapped_volatile: Vec::new() };
    for (at, sql) in corpus() {
        c.specs += 1;
        let stmts = objects(&sql).unwrap_or_else(|e| panic!("{at}: {e}"));
        let functions: BTreeMap<String, &str> = stmts
            .iter()
            .filter_map(|(o, stmt)| match o {
                Object::Function(sig) => Some((sig.split('(').next().unwrap_or_default().to_string(), stmt.as_str())),
                _ => None,
            })
            .collect();
        c.volatile_functions += functions.values().filter(|s| !stable(s)).count();
        let mut reads: BTreeSet<&str> = functions.iter().filter(|(_, s)| body(s).contains("current_setting(")).map(|(n, _)| n.as_str()).collect();
        loop {
            let more: Vec<&str> = functions
                .iter()
                .filter(|(n, s)| !reads.contains(n.as_str()) && reads.iter().any(|r| body(s).contains(&format!("{r}("))))
                .map(|(n, _)| n.as_str())
                .collect();
            if more.is_empty() {
                break;
            }
            reads.extend(more);
        }
        for (o, stmt) in &stmts {
            let (text, params) = match o {
                Object::Function(_) => (body(stmt), parameters(stmt)),
                Object::Policy { .. } | Object::Trigger { .. } => (stmt.as_str(), BTreeSet::new()),
                _ => continue,
            };
            for (name, callee) in &functions {
                c.calls(&at, text, &params, name, stable(callee), reads.contains(name.as_str()));
            }
        }
    }
    c
}

#[test]
fn a_call_that_reads_claims_with_arguments_fixed_for_the_statement_is_made_once_per_statement() {
    let c = scan();
    assert!(c.specs > 100, "only {} specs emitted", c.specs);
    assert!(c.fixed_calls > 50 && c.row_calls > 50, "the corpus must call with fixed arguments and with row arguments: {} and {}", c.fixed_calls, c.row_calls);
    assert!(c.bare.is_empty(), "{} of {} calls with fixed arguments run once per row:\n{}", c.bare.len(), c.fixed_calls, c.bare.join("\n"));
}

#[test]
fn a_volatile_function_is_never_made_once_per_statement() {
    let c = scan();
    assert!(c.volatile_functions > 20, "only {} volatile functions in the corpus", c.volatile_functions);
    assert!(c.wrapped_volatile.is_empty(), "a volatile function called once per statement:\n{}", c.wrapped_volatile.join("\n"));
}

#[test]
fn an_argument_read_from_a_row_is_told_from_a_fixed_one() {
    let params = parameters("CREATE OR REPLACE FUNCTION auth.f(p_id text, user_id text, check_org_id uuid)\nRETURNS boolean");
    assert_eq!(params, BTreeSet::from(["p_id", "user_id", "check_org_id"]));
    for args in [
        "(SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')",
        "p_id",
        "user_id, check_org_id",
        "'doc', p_id",
        "ARRAY(SELECT e::uuid FROM jsonb_array_elements_text((SELECT current_setting('c', true)::json ->> 'k')::jsonb) e)",
        "NULL, 'x'",
    ] {
        assert!(fixed(args, &params), "{args}");
    }
    for args in ["resource_id", "docs.id", "p_id, tenant_id", "p_other", "(SELECT current_setting('c', true)::json ->> 'sub'), notes.id, 'write'"] {
        assert!(!fixed(args, &params), "{args}");
    }
}
