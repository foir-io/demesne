use demesne_gocompat::json::{self, Value};

fn value(src: &str) -> Value {
    json::parse(src).expect("the test JSON parses")
}

#[test]
fn a_strict_accessor_answers_only_when_every_member_has_its_type() {
    assert_eq!(value(r#"["a", "b"]"#).as_strings(), Some(vec!["a".to_string(), "b".to_string()]));
    assert_eq!(value("[]").as_strings(), Some(Vec::new()));
    for src in [r#"["a", null]"#, r#"["a", 1]"#, r#"{"a": "b"}"#, r#""a""#] {
        assert_eq!(value(src).as_strings(), None, "{src}");
    }
    assert_eq!(value(r#"{"b": "2", "a": "1"}"#).as_string_map(), Some(vec![("b".to_string(), "2".to_string()), ("a".to_string(), "1".to_string())]));
    for src in [r#"{"a": 1}"#, r#"{"a": null}"#, r#"["a"]"#] {
        assert_eq!(value(src).as_string_map(), None, "{src}");
    }
    assert_eq!(value(r#"{"a": 1}"#).as_object().map(<[_]>::len), Some(1));
    assert_eq!(value("[1]").as_object(), None);
}
