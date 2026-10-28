use demesne_cli::{Files, run_pure};
use demesne_parity::corpus::{self, Entry};
use std::collections::BTreeSet;
use std::path::Path;

const SPEC: &str = "spec.demesne";
const PAYLOADS: [&str; 3] = ["' OR {mark} OR '", "\\' OR {mark} OR '", " OR {mark}"];
const OUTPUTS: [&[&str]; 2] = [&["emit", SPEC, "all"], &["emit", SPEC, "--profile", "supabase"]];

struct OneSpec(Vec<u8>);

impl Files for OneSpec {
    fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        if path == SPEC { Ok(self.0.clone()) } else { Err(format!("open {path}: no such file or directory")) }
    }
}

fn entries() -> Vec<Entry> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut entries = corpus::collect(&root);
    corpus::add_dir(&mut entries, "gaps", &root.join("testdata/gaps"));
    corpus::add_dir(&mut entries, "oracle", &root.join("testdata/parity/oracle"));
    entries
}

fn strings(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = src;
    while let Some(start) = rest.find('"') {
        let body = &rest[start + 1..];
        let mut end = None;
        let mut escaped = false;
        for (i, c) in body.char_indices() {
            match c {
                '\n' => break,
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = Some(i);
                    break;
                }
                _ => escaped = false,
            }
        }
        let Some(end) = end else { break };
        out.insert(body[..end].to_string());
        rest = &body[end + 1..];
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
enum Backslash {
    LiteralOutsideEStrings,
    AlwaysEscapes,
}

fn literal_end(b: &[u8], open: usize, backslash: Backslash) -> usize {
    let q = b[open];
    let e_string =
        q == b'\'' && open > 0 && b[open - 1].eq_ignore_ascii_case(&b'e') && !(open > 1 && (b[open - 2] == b'_' || b[open - 2].is_ascii_alphanumeric()));
    let escapes = q == b'\'' && (e_string || backslash == Backslash::AlwaysEscapes);
    let mut i = open + 1;
    while i < b.len() && !(b[i] == q && b.get(i + 1) != Some(&q)) {
        i += if b[i] == q || (escapes && b[i] == b'\\') { 2 } else { 1 };
    }
    i + 1
}

fn outside_literals(sql: &str, backslash: Backslash) -> String {
    let b = sql.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' | b'"' => {
                i = literal_end(b, i, backslash);
                out.push(' ');
            }
            b'-' if b.get(i + 1) == Some(&b'-') => i = sql[i..].find('\n').map_or(b.len(), |n| i + n),
            b'/' if b.get(i + 1) == Some(&b'*') => i = sql[i + 2..].find("*/").map_or(b.len(), |n| i + n + 4),
            b'$' => {
                let tag = sql[i + 1..].find('$').filter(|&n| sql[i + 1..i + 1 + n].bytes().all(|c| c == b'_' || c.is_ascii_alphabetic()));
                i += tag.map_or(1, |n| n + 2);
                out.push(' ');
            }
            c => {
                out.push(char::from(c));
                i += 1;
            }
        }
    }
    out
}

struct Mutation<'a> {
    id: &'a str,
    original: &'a str,
    payload: &'a str,
    mark: String,
    spec: Vec<u8>,
}

impl Mutation<'_> {
    fn emitted_and_leaks(&self) -> Vec<(bool, Option<String>)> {
        OUTPUTS
            .iter()
            .map(|args| {
                let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
                let out = run_pure(&args, &OneSpec(self.spec.clone())).expect("emit runs without a database");
                if out.code != 0 {
                    return (false, None);
                }
                let sql = String::from_utf8(out.stdout).expect("the CLI writes UTF-8");
                let leaked = [Backslash::LiteralOutsideEStrings, Backslash::AlwaysEscapes].iter().any(|&b| outside_literals(&sql, b).contains(&self.mark));
                (true, leaked.then(|| format!("{} {:?} + {:?} ({})", self.id, self.original, self.payload, args.join(" "))))
            })
            .collect()
    }
}

#[test]
fn no_spec_string_reaches_the_sql_outside_a_literal() {
    let mut emitted = 0;
    let mut leaks = Vec::new();
    for e in entries() {
        let src = std::fs::read_to_string(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.path.display()));
        let originals = strings(&src);
        let mutations =
            originals.iter().enumerate().flat_map(|(n, s)| PAYLOADS.iter().enumerate().map(move |(p, payload)| (format!("mk{n}x{p}x"), s, *payload)));
        for (mark, s, payload) in mutations {
            let spec = src.replace(&format!("\"{s}\""), &format!("\"{s}{}\"", payload.replace("{mark}", &mark))).into_bytes();
            for (ran, leak) in (Mutation { id: &e.id, original: s, payload, mark, spec }).emitted_and_leaks() {
                emitted += usize::from(ran);
                leaks.extend(leak);
            }
        }
    }
    assert!(emitted > 1000, "only {emitted} mutated specs emitted, too few to show anything");
    assert!(leaks.is_empty(), "{} spec strings reach the SQL outside a literal:\n{}", leaks.len(), leaks.join("\n"));
}

#[test]
fn the_scanner_sees_a_mark_outside_a_literal_and_not_inside_one() {
    let sql = "SELECT 'a'' mk1x' AS v, \"mk2x\" FROM t -- mk3x\nWHERE x = mk4x AND $$ mk5x $$ /* mk6x */";
    let bare = outside_literals(sql, Backslash::LiteralOutsideEStrings);
    assert_eq!(["mk1x", "mk2x", "mk3x", "mk4x", "mk5x", "mk6x"].map(|m| bare.contains(m)), [false, false, false, true, true, false], "{bare}");
}

#[test]
fn the_scanner_reads_a_backslash_as_postgres_does_under_each_setting() {
    let doubled_only = r"SELECT '\'' OR mk1x OR '''";
    let quote_literal = r"SELECT E'\\'' OR mk2x OR '''";
    let marks = |sql: &str, m: &str| [Backslash::LiteralOutsideEStrings, Backslash::AlwaysEscapes].map(|b| outside_literals(sql, b).contains(m));
    assert_eq!(marks(doubled_only, "mk1x"), [false, true], "{doubled_only}");
    assert_eq!(marks(quote_literal, "mk2x"), [false, false], "{quote_literal}");
}
