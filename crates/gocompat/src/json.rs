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

    #[must_use]
    pub fn nullable_strings<S: AsRef<str>>(xs: Option<&[S]>) -> Value {
        match xs {
            None => Value::Null,
            Some(xs) => Value::strings(xs),
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn write_string(dst: &mut String, s: &str) {
    write_string_opts(dst, s, true);
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

#[must_use]
pub fn marshal(v: &Value) -> String {
    marshal_opts(v, true)
}

#[must_use]
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

#[must_use]
pub fn marshal_indent(v: &Value, prefix: &str, indent: &str) -> String {
    marshal_indent_opts(v, prefix, indent, true)
}

#[must_use]
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
            write_object(out, fields.iter().map(|(k, v)| (k.as_str(), v)), Some((prefix, indent)), depth, h);
        }
        Value::Map(entries) => write_object(out, sorted(entries).into_iter(), Some((prefix, indent)), depth, h),
        other => write_compact(out, other, h),
    }
}

fn write_object<'a>(out: &mut String, fields: impl Iterator<Item = (&'a str, &'a Value)>, pretty: Option<(&str, &str)>, depth: usize, h: bool) {
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
        if let Some((prefix, indent)) = pretty {
            newline(out, prefix, indent, depth + 1);
            write_string_opts(out, k, h);
            out.push_str(": ");
            write_indented(out, v, prefix, indent, depth + 1, h);
        } else {
            write_string_opts(out, k, h);
            out.push(':');
            write_compact(out, v, h);
        }
    }
    if let Some((prefix, indent)) = pretty {
        newline(out, prefix, indent, depth);
    }
    out.push('}');
}

/// Parses one JSON document into a [`Value`], keeping object keys in source order.
///
/// # Errors
///
/// Malformed JSON, an integer outside `i64`, or bytes after the document.
pub fn parse(src: &str) -> Result<Value, String> {
    let mut p = Parser { b: src.as_bytes(), i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("json: trailing data at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("json: expected {:?} at byte {}", c as char, self.i))
        }
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("json: bad literal at byte {}", self.i))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.b.get(self.i) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("json: unexpected byte at {}", self.i)),
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Map(out));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value()?;
            out.push((k, v));
            self.ws();
            if self.b.get(self.i) != Some(&b',') {
                self.eat(b'}')?;
                return Ok(Value::Map(out));
            }
            self.i += 1;
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            if self.b.get(self.i) != Some(&b',') {
                self.eat(b']')?;
                return Ok(Value::Array(out));
            }
            self.i += 1;
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        self.i += 1;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).expect("the scanned number holds only ASCII bytes");
        text.parse::<i64>().map(Value::Int).map_err(|e| format!("json: {e}"))
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let Some(&c) = self.b.get(self.i) else { return Err("json: unterminated string".into()) };
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                _ => {
                    let start = self.i - 1;
                    let end = self.b[self.i..].iter().position(|&b| b == b'"' || b == b'\\').map_or(self.b.len(), |n| self.i + n);
                    out.push_str(std::str::from_utf8(&self.b[start..end]).map_err(|e| e.to_string())?);
                    self.i = end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let e = *self.b.get(self.i).ok_or("json: bad escape")?;
        self.i += 1;
        Ok(match e {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => self.unicode_escape()?,
            _ => return Err("json: bad escape".into()),
        })
    }

    fn hex4(&self, at: usize) -> Result<u32, String> {
        let hex = self.b.get(at..at + 4).ok_or("json: truncated \\u escape")?;
        u32::from_str_radix(std::str::from_utf8(hex).map_err(|e| e.to_string())?, 16).map_err(|e| e.to_string())
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let mut cp = self.hex4(self.i)?;
        self.i += 4;
        if (0xD800..0xDC00).contains(&cp)
            && self.b[self.i..].starts_with(b"\\u")
            && let Ok(lo) = self.hex4(self.i + 2)
            && (0xDC00..0xE000).contains(&lo)
        {
            self.i += 6;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        }
        Ok(char::from_u32(cp).unwrap_or('\u{FFFD}'))
    }
}

impl Value {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(e) | Value::Struct(e) => e.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[(String, Value)] {
        match self {
            Value::Map(e) | Value::Struct(e) => e,
            _ => &[],
        }
    }

    #[must_use]
    pub fn string_list(&self) -> Vec<String> {
        self.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
    }
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
