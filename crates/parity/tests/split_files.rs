use demesne_emit_sql::{Object, Sql, file_sql, objects, validate, validate_files};
use demesne_parity::corpus::{self, Entry};
use demesne_syntax::{Spec, parse, parse_files};
use std::collections::BTreeMap;
use std::path::Path;

const DECLARATIONS: [&str; 16] = [
    "topology",
    "vocabulary",
    "subject",
    "object",
    "template",
    "procedures",
    "ungoverned",
    "fieldscopes",
    "rolestore",
    "grant",
    "claims",
    "definers",
    "tables",
    "identifiers",
    "external",
    "replace",
];
const DROPPED: &str = "-- ===== Dropped since the previous manifest =====";

fn entries() -> Vec<Entry> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    corpus::collect(&root)
}

fn declaration_starts(src: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut depth = 0i32;
    for (n, line) in src.lines().enumerate() {
        let first = line.split_whitespace().next().unwrap_or("");
        if depth == 0 && DECLARATIONS.contains(&first) {
            starts.push(n);
        }
        let mut in_string = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' => in_string = !in_string,
                '\\' if in_string => {
                    chars.next();
                }
                '/' if !in_string && chars.peek() == Some(&'/') => break,
                '{' if !in_string => depth += 1,
                '}' if !in_string => depth -= 1,
                _ => {}
            }
        }
    }
    starts
}

fn lines_between(src: &str, start: usize, end: usize) -> String {
    src.lines().skip(start).take(end - start).flat_map(|l| [l, "\n"]).collect()
}

fn valid(src: &str) -> bool {
    parse(src).is_ok_and(|s| validate(&s).is_ok())
}

fn cuts(src: &str) -> Vec<usize> {
    declaration_starts(src).into_iter().skip(1).filter(|&c| valid(&lines_between(src, 0, c))).collect()
}

fn all_sql(s: &Spec) -> String {
    let mut b = String::new();
    Sql::new(s).write_all_sql(&mut b).expect("a valid spec's SQL compiles");
    b
}

fn created(sql: &str) -> BTreeMap<Object, String> {
    objects(sql).expect("the SQL has a manifest").into_iter().collect()
}

fn replay(state: &mut BTreeMap<Object, String>, sql: &str) {
    let (made, dropped) = sql.split_once(DROPPED).unwrap_or((sql, ""));
    state.extend(created(made));
    for line in dropped.lines() {
        if let Some(sig) = line.strip_prefix("DROP FUNCTION IF EXISTS ").and_then(|r| r.strip_suffix(';')) {
            state.remove(&Object::Function(sig.to_string()));
        } else if let Some(rest) = line.strip_prefix("DROP POLICY IF EXISTS ").and_then(|r| r.strip_suffix(';')) {
            let (name, table) = rest.split_once(" ON ").expect("a policy drop names its table");
            state.remove(&Object::Policy { table: table.to_string(), name: name.to_string() });
        } else if let Some(rest) = line.strip_prefix("DROP TRIGGER IF EXISTS ").and_then(|r| r.strip_suffix(';')) {
            let (name, table) = rest.split_once(" ON ").expect("a trigger drop names its table");
            state.remove(&Object::Trigger { table: table.to_string(), name: name.to_string() });
        }
    }
}

fn called_before_created(sql: &str) -> Vec<String> {
    let mut early = Vec::new();
    for (o, _) in objects(sql).expect("the SQL has a manifest") {
        let Object::Function(sig) = o else { continue };
        let name = sig.split('(').next().expect("a signature starts with its name");
        let made = sql.find(&format!("CREATE OR REPLACE FUNCTION {name}(")).expect("the function is created") + "CREATE OR REPLACE FUNCTION ".len();
        if sql.find(&format!("{name}(")).is_some_and(|k| k < made) {
            early.push(name.to_string());
        }
    }
    early
}

#[test]
fn splitting_a_spec_into_files_emits_the_same_objects() {
    let mut split = 0;
    let mut whole = 0;
    let mut failures = Vec::new();
    for e in entries() {
        let src = std::fs::read_to_string(&e.path).expect("the spec reads");
        let Ok(single) = parse(&src) else { continue };
        if validate(&single).is_err() {
            continue;
        }
        let cuts = cuts(&src);
        if cuts.is_empty() {
            whole += 1;
            continue;
        }
        let mut bounds = vec![0];
        bounds.extend(&cuts);
        bounds.push(src.lines().count());
        let texts: Vec<String> = bounds.windows(2).map(|w| lines_between(&src, w[0], w[1])).collect();
        let names: Vec<String> = (0..texts.len()).map(|k| format!("part{k}.demesne")).collect();
        let files = match parse_files(names.iter().map(String::as_str).zip(texts.iter().map(String::as_bytes))) {
            Ok(f) => f,
            Err(err) => {
                failures.push(format!("{}: the split does not parse: {err}", e.id));
                continue;
            }
        };
        if let Err(err) = validate_files(&files) {
            failures.push(format!("{}: the split does not validate: {err}", e.id));
            continue;
        }
        let expected = all_sql(&single);
        if all_sql(files.spec()) != expected {
            failures.push(format!("{}: the files together emit different SQL from the one file", e.id));
            continue;
        }
        for (what, one, many) in [
            ("projections", demesne_emit_ts::emit_ts(&single), demesne_emit_ts::emit_ts(files.spec())),
            ("framework", demesne_emit_ts::emit_framework_ts(&single), demesne_emit_ts::emit_framework_ts(files.spec())),
        ] {
            if one.map_err(|x| x.to_string()) != many.map_err(|x| x.to_string()) {
                failures.push(format!("{}: the files together emit different TypeScript {what}", e.id));
            }
        }
        let mut state = BTreeMap::new();
        let mut applied = String::new();
        for k in 0..files.len() {
            let sql = file_sql(&files, k).expect("a file of a valid split emits");
            replay(&mut state, &sql);
            applied.push_str(&sql);
        }
        if state != created(&expected) {
            failures.push(format!("{}: applying the files' SQL in order leaves different objects from the one file's SQL", e.id));
        }
        let early = called_before_created(&applied);
        if !early.is_empty() {
            failures.push(format!("{}: the files' SQL calls {early:?} before creating them", e.id));
        }
        split += 1;
    }
    assert!(failures.is_empty(), "{} of {} split specs fail:\n{}", failures.len(), split + failures.len(), failures.join("\n"));
    assert!(split > 4 * whole, "only {split} specs split into files, and {whole} have no valid split");
}
