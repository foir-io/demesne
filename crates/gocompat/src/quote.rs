use crate::isprint::{IS_NOT_PRINT16, IS_NOT_PRINT32, IS_PRINT16, IS_PRINT32};

const LOWERHEX: &[u8; 16] = b"0123456789abcdef";

fn bsearch16(s: &[u16], v: u16) -> (usize, bool) {
    let (mut i, mut j) = (0usize, s.len());
    while i < j {
        let h = i + ((j - i) >> 1);
        if s[h] < v {
            i = h + 1;
        } else {
            j = h;
        }
    }
    (i, i < s.len() && s[i] == v)
}

fn bsearch32(s: &[u32], v: u32) -> (usize, bool) {
    let (mut i, mut j) = (0usize, s.len());
    while i < j {
        let h = i + ((j - i) >> 1);
        if s[h] < v {
            i = h + 1;
        } else {
            j = h;
        }
    }
    (i, i < s.len() && s[i] == v)
}

pub fn is_print(r: char) -> bool {
    let r = r as u32;
    if r <= 0xFF {
        if (0x20..=0x7E).contains(&r) {
            return true;
        }
        if (0xA1..=0xFF).contains(&r) {
            return r != 0xAD;
        }
        return false;
    }
    if r < 1 << 16 {
        let rr = r as u16;
        let (i, _) = bsearch16(IS_PRINT16, rr);
        if i >= IS_PRINT16.len() || rr < IS_PRINT16[i & !1] || IS_PRINT16[i | 1] < rr {
            return false;
        }
        let (_, found) = bsearch16(IS_NOT_PRINT16, rr);
        return !found;
    }
    let (i, _) = bsearch32(IS_PRINT32, r);
    if i >= IS_PRINT32.len() || r < IS_PRINT32[i & !1] || IS_PRINT32[i | 1] < r {
        return false;
    }
    if r >= 0x20000 {
        return true;
    }
    let (_, found) = bsearch16(IS_NOT_PRINT32, (r - 0x10000) as u16);
    !found
}

pub fn quote(s: &str) -> String {
    let mut buf = String::with_capacity(s.len() + 2);
    buf.push('"');
    for r in s.chars() {
        escape_rune(&mut buf, r);
    }
    buf.push('"');
    buf
}

fn escape_rune(buf: &mut String, r: char) {
    if r == '"' || r == '\\' {
        buf.push('\\');
        buf.push(r);
        return;
    }
    if is_print(r) {
        buf.push(r);
        return;
    }
    match r {
        '\u{7}' => buf.push_str("\\a"),
        '\u{8}' => buf.push_str("\\b"),
        '\u{c}' => buf.push_str("\\f"),
        '\n' => buf.push_str("\\n"),
        '\r' => buf.push_str("\\r"),
        '\t' => buf.push_str("\\t"),
        '\u{b}' => buf.push_str("\\v"),
        _ => {
            let v = r as u32;
            if v < 0x20 || v == 0x7f {
                buf.push_str("\\x");
                buf.push(LOWERHEX[(v >> 4) as usize & 0xF] as char);
                buf.push(LOWERHEX[v as usize & 0xF] as char);
            } else if v < 0x10000 {
                buf.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    buf.push(LOWERHEX[(v >> shift) as usize & 0xF] as char);
                }
            } else {
                buf.push_str("\\U");
                for shift in [28, 24, 20, 16, 12, 8, 4, 0] {
                    buf.push(LOWERHEX[(v >> shift) as usize & 0xF] as char);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn matches_strconv_quote() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("\n\t\r\u{7}\u{8}\u{c}\u{b}"), "\"\\n\\t\\r\\a\\b\\f\\v\"");
        assert_eq!(quote("\u{1}\u{7f}"), "\"\\x01\\x7f\"");
        assert_eq!(quote("é\u{ad}\u{200b}"), "\"é\\u00ad\\u200b\"");
        assert_eq!(quote("\u{e0001}"), "\"\\U000e0001\"");
        assert_eq!(quote("日本"), "\"日本\"");
    }
}
