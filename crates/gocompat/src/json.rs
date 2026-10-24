#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    Struct(Vec<(String, Value)>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    pub fn strings<S: AsRef<str>>(xs: &[S]) -> Value {
        Value::Array(xs.iter().map(|s| Value::Str(s.as_ref().to_string())).collect())
    }

    pub fn nullable_strings<S: AsRef<str>>(xs: Option<&[S]>) -> Value {
        match xs {
            None => Value::Null,
            Some(xs) => Value::strings(xs),
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn write_string(dst: &mut String, s: &str) {
    write_string_opts(dst, s, true)
}

pub fn write_string_opts(dst: &mut String, s: &str, escape_html: bool) {
    dst.push('"');
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                dst.push('\\');
                dst.push(c);
            }
            '\u{8}' => dst.push_str("\\b"),
            '\u{c}' => dst.push_str("\\f"),
            '\n' => dst.push_str("\\n"),
            '\r' => dst.push_str("\\r"),
            '\t' => dst.push_str("\\t"),
            '<' | '>' | '&' if escape_html => push_u00(dst, c as u8),
            c if (c as u32) < 0x20 => push_u00(dst, c as u8),
            '\u{2028}' => dst.push_str("\\u2028"),
            '\u{2029}' => dst.push_str("\\u2029"),
            c => dst.push(c),
        }
    }
    dst.push('"');
}

fn push_u00(dst: &mut String, b: u8) {
    dst.push_str("\\u00");
    dst.push(HEX[(b >> 4) as usize] as char);
    dst.push(HEX[(b & 0xF) as usize] as char);
}

pub fn marshal(v: &Value) -> String {
    marshal_opts(v, true)
}

pub fn marshal_opts(v: &Value, escape_html: bool) -> String {
    let mut out = String::new();
    write_compact(&mut out, v, escape_html);
    out
}

fn write_compact(out: &mut String, v: &Value, h: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Str(s) => write_string_opts(out, s, h),
        Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(out, x, h);
            }
            out.push(']');
        }
        Value::Struct(fields) => write_object(out, fields.iter().map(|(k, v)| (k.as_str(), v)), None, 0, h),
        Value::Map(entries) => write_object(out, sorted(entries).into_iter(), None, 0, h),
    }
}

fn sorted(entries: &[(String, Value)]) -> Vec<(&str, &Value)> {
    let mut v: Vec<(&str, &Value)> = entries.iter().map(|(k, v)| (k.as_str(), v)).collect();
    v.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    v
}

pub fn marshal_indent(v: &Value, prefix: &str, indent: &str) -> String {
    marshal_indent_opts(v, prefix, indent, true)
}

pub fn marshal_indent_opts(v: &Value, prefix: &str, indent: &str, escape_html: bool) -> String {
    let mut out = String::new();
    write_indented(&mut out, v, prefix, indent, 0, escape_html);
    out
}

fn newline(out: &mut String, prefix: &str, indent: &str, depth: usize) {
    out.push('\n');
    out.push_str(prefix);
    for _ in 0..depth {
        out.push_str(indent);
    }
}

fn write_indented(out: &mut String, v: &Value, prefix: &str, indent: &str, depth: usize, h: bool) {
    match v {
        Value::Array(xs) => {
            if xs.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, prefix, indent, depth + 1);
                write_indented(out, x, prefix, indent, depth + 1, h);
            }
            newline(out, prefix, indent, depth);
            out.push(']');
        }
        Value::Struct(fields) => {
            write_object(out, fields.iter().map(|(k, v)| (k.as_str(), v)), Some((prefix, indent)), depth, h)
        }
        Value::Map(entries) => write_object(out, sorted(entries).into_iter(), Some((prefix, indent)), depth, h),
        other => write_compact(out, other, h),
    }
}

fn write_object<'a>(
    out: &mut String,
    fields: impl Iterator<Item = (&'a str, &'a Value)>,
    pretty: Option<(&str, &str)>,
    depth: usize,
    h: bool,
) {
    let fields: Vec<_> = fields.collect();
    if fields.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push('{');
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match pretty {
            Some((prefix, indent)) => {
                newline(out, prefix, indent, depth + 1);
                write_string_opts(out, k, h);
                out.push_str(": ");
                write_indented(out, v, prefix, indent, depth + 1, h);
            }
            None => {
                write_string_opts(out, k, h);
                out.push(':');
                write_compact(out, v, h);
            }
        }
    }
    if let Some((prefix, indent)) = pretty {
        newline(out, prefix, indent, depth);
    }
    out.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_encoding_json() {
        let mut s = String::new();
        write_string(&mut s, "a<b>&\"\\\n\u{1}\u{7f}\u{2028}é");
        assert_eq!(s, "\"a\\u003cb\\u003e\\u0026\\\"\\\\\\n\\u0001\u{7f}\\u2028é\"");
    }

    #[test]
    fn indents_like_marshal_indent() {
        let v = Value::Map(vec![
            ("b".into(), Value::Array(vec![])),
            ("a".into(), Value::Struct(vec![("x".into(), Value::Int(1)), ("e".into(), Value::Map(vec![]))])),
        ]);
        assert_eq!(marshal_indent(&v, "", "  "), "{\n  \"a\": {\n    \"x\": 1,\n    \"e\": {}\n  },\n  \"b\": []\n}");
        assert_eq!(marshal(&v), "{\"a\":{\"x\":1,\"e\":{}},\"b\":[]}");
    }
}
