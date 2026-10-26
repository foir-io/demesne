use demesne_gocompat::json::{self, MAX_DEPTH, Value};

fn arrays(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

fn objects(depth: usize) -> String {
    format!("{}1{}", r#"{"a":"#.repeat(depth), "}".repeat(depth))
}

#[test]
fn nesting_to_the_limit_parses() {
    for src in [arrays(MAX_DEPTH), objects(MAX_DEPTH)] {
        if let Err(e) = json::parse(&src) {
            panic!("{MAX_DEPTH} levels don't parse: {e}: {src:.40}");
        }
    }
}

#[test]
fn one_level_past_the_limit_is_refused_with_gos_message() {
    for (src, open) in [(arrays(MAX_DEPTH + 1), '['), (objects(MAX_DEPTH + 1), '{')] {
        let err = json::parse(&src).expect_err("JSON past the depth limit parses").to_string();
        assert_eq!(err, format!("json: invalid character '{open}' exceeded max depth"), "{src:.40}");
    }
}

#[test]
fn the_limit_counts_depth_not_containers() {
    let siblings = format!("[{}]", vec!["[]"; MAX_DEPTH * 4].join(","));
    let deep_pair = format!("[{},{}]", arrays(MAX_DEPTH - 1), arrays(MAX_DEPTH - 1));
    for src in [siblings, deep_pair] {
        let v = json::parse(&src).unwrap_or_else(|e| panic!("{e}: {src:.40}"));
        assert!(matches!(&v, Value::Array(kids) if kids.len() >= 2), "{v:?}");
    }
}
