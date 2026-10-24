const COMMON_INITIALISMS: &[&str] = &["ID", "URL", "API", "SQL", "UID", "ACL", "PK"];

fn upper_first_byte(p: &str) -> String {
    let b = p.as_bytes()[0];
    if b.is_ascii() {
        let mut out = String::with_capacity(p.len());
        out.push(b.to_ascii_uppercase() as char);
        out.push_str(&p[1..]);
        out
    } else {
        let mut chars = p.chars();
        let first = chars.next().unwrap();
        first.to_uppercase().chain(chars).collect()
    }
}

pub fn go_export(s: &str) -> String {
    s.split(['_', '-', ':', '.'])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let up = p.to_uppercase();
            if COMMON_INITIALISMS.contains(&up.as_str()) { up } else { upper_first_byte(p) }
        })
        .collect()
}

pub fn unexport(s: &str) -> String {
    let r: Vec<char> = go_export(s).chars().collect();
    if r.is_empty() {
        return String::new();
    }
    let mut i = 0;
    while i < r.len() && r[i].is_uppercase() {
        i += 1;
    }
    if i == r.len() {
        return r.iter().collect::<String>().to_lowercase();
    }
    if i > 1 {
        i -= 1;
    }
    let head: String = r[..i].iter().collect();
    let tail: String = r[i..].iter().collect();
    head.to_lowercase() + &tail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_like_go() {
        assert_eq!(go_export("content:read"), "ContentRead");
        assert_eq!(go_export("user_id"), "UserID");
        assert_eq!(go_export("api_key.url"), "APIKeyURL");
        assert_eq!(go_export("__x"), "X");
        assert_eq!(unexport("record"), "record");
        assert_eq!(unexport("acl_entry"), "aclEntry");
        assert_eq!(unexport("id"), "id");
    }
}
