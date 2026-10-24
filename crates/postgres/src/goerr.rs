use demesne_gocompat::quote;

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

pub(crate) fn errno_text(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => {
            let s = std::io::Error::from_raw_os_error(code).to_string();
            let s = match s.rfind(" (os error ") {
                Some(i) => &s[..i],
                None => s.as_str(),
            };
            lower_first(s)
        }
        None => e.to_string(),
    }
}

pub(crate) fn parse_uint_error(s: &str, why: &str) -> String {
    format!("strconv.ParseUint: parsing {}: {why}", quote(s))
}

pub(crate) fn parse_int_error(s: &str, why: &str) -> String {
    format!("strconv.ParseInt: parsing {}: {why}", quote(s))
}
