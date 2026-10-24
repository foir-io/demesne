use crate::goerr::{errno_text, parse_int_error, parse_uint_error};
use demesne_gocompat::quote;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use postgres::config::ChannelBinding;

pub(crate) type Settings = BTreeMap<String, String>;

const NOT_RUNTIME_PARAMS: &[&str] = &[
    "host",
    "port",
    "database",
    "user",
    "password",
    "passfile",
    "connect_timeout",
    "sslmode",
    "sslkey",
    "sslcert",
    "sslrootcert",
    "sslnegotiation",
    "sslpassword",
    "sslsni",
    "krbspn",
    "krbsrvname",
    "target_session_attrs",
    "service",
    "servicefile",
    "min_protocol_version",
    "max_protocol_version",
    "channel_binding",
];

const ENV_SETTINGS: &[(&str, &str)] = &[
    ("PGHOST", "host"),
    ("PGPORT", "port"),
    ("PGDATABASE", "database"),
    ("PGUSER", "user"),
    ("PGPASSWORD", "password"),
    ("PGPASSFILE", "passfile"),
    ("PGAPPNAME", "application_name"),
    ("PGCONNECT_TIMEOUT", "connect_timeout"),
    ("PGSSLMODE", "sslmode"),
    ("PGSSLKEY", "sslkey"),
    ("PGSSLCERT", "sslcert"),
    ("PGSSLSNI", "sslsni"),
    ("PGSSLROOTCERT", "sslrootcert"),
    ("PGSSLPASSWORD", "sslpassword"),
    ("PGSSLNEGOTIATION", "sslnegotiation"),
    ("PGTARGETSESSIONATTRS", "target_session_attrs"),
    ("PGSERVICE", "service"),
    ("PGSERVICEFILE", "servicefile"),
    ("PGTZ", "timezone"),
    ("PGOPTIONS", "options"),
    ("PGMINPROTOCOLVERSION", "min_protocol_version"),
    ("PGMAXPROTOCOLVERSION", "max_protocol_version"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verify {
    None,
    Chain,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Roots {
    System,
    Pem(Vec<CertificateDer<'static>>),
}

#[derive(Debug)]
pub(crate) struct TlsPlan {
    pub verify: Verify,
    pub roots: Roots,
    pub client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    pub sni: bool,
    pub direct: bool,
}

#[derive(Debug)]
pub(crate) struct Fallback {
    pub host: String,
    pub port: u16,
    pub tls: Option<Arc<TlsPlan>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionAttrs {
    Any,
    ReadWrite,
    ReadOnly,
    Primary,
    Standby,
    PreferStandby,
}

#[derive(Debug)]
pub(crate) struct ConnConfig {
    pub user: String,
    pub password: String,
    pub database: String,
    pub runtime_params: Settings,
    pub fallbacks: Vec<Fallback>,
    pub connect_timeout: Option<Duration>,
    pub session_attrs: SessionAttrs,
    pub channel_binding: ChannelBinding,
    pub min_protocol: &'static str,
    pub max_protocol: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseConfigError {
    conn_string: String,
    msg: String,
    err: Option<String>,
}

impl fmt::Display for ParseConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cs = redact_password(&self.conn_string);
        match &self.err {
            None => write!(f, "cannot parse `{cs}`: {}", self.msg),
            Some(e) => write!(f, "cannot parse `{cs}`: {} ({e})", self.msg),
        }
    }
}

fn pce(conn: &str, msg: impl Into<String>, err: Option<String>) -> ParseConfigError {
    ParseConfigError { conn_string: conn.to_string(), msg: msg.into(), err }
}

pub(crate) fn is_absolute_path(p: &str) -> bool {
    let b = p.as_bytes();
    p.starts_with('/') || (b.len() >= 3 && b[0].is_ascii_uppercase() && b[1] == b':' && b[2] == b'\\')
}

struct OsUser {
    name: String,
    home: String,
}

#[cfg(unix)]
fn os_user() -> Option<OsUser> {
    if let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::Uid::current()) {
        return Some(OsUser { name: u.name, home: u.dir.to_string_lossy().into_owned() });
    }
    let name = std::env::var("USER").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    (!name.is_empty() && !home.is_empty()).then_some(OsUser { name, home })
}

#[cfg(windows)]
fn os_user() -> Option<OsUser> {
    let name = std::env::var("USERNAME").ok().filter(|s| !s.is_empty())?;
    let home = std::env::var("USERPROFILE").ok().filter(|s| !s.is_empty())?;
    Some(OsUser { name, home })
}

fn join(base: &str, parts: &[&str]) -> String {
    let mut p = std::path::PathBuf::from(base);
    for part in parts {
        p.push(part);
    }
    p.to_string_lossy().into_owned()
}

fn exists(p: &str) -> bool {
    std::fs::metadata(p).is_ok()
}

#[cfg(unix)]
fn default_settings() -> Settings {
    let mut s = Settings::new();
    s.insert("host".into(), default_host());
    s.insert("port".into(), "5432".into());
    if let Some(u) = os_user() {
        s.insert("user".into(), u.name);
        s.insert("passfile".into(), join(&u.home, &[".pgpass"]));
        s.insert("servicefile".into(), join(&u.home, &[".pg_service.conf"]));
        let sslcert = join(&u.home, &[".postgresql", "postgresql.crt"]);
        let sslkey = join(&u.home, &[".postgresql", "postgresql.key"]);
        if exists(&sslcert) && exists(&sslkey) {
            s.insert("sslcert".into(), sslcert);
            s.insert("sslkey".into(), sslkey);
        }
        let sslrootcert = join(&u.home, &[".postgresql", "root.crt"]);
        if exists(&sslrootcert) {
            s.insert("sslrootcert".into(), sslrootcert);
        }
    }
    s.insert("target_session_attrs".into(), "any".into());
    s
}

#[cfg(windows)]
fn default_settings() -> Settings {
    let mut s = Settings::new();
    s.insert("host".into(), default_host());
    s.insert("port".into(), "5432".into());
    let app_data = std::env::var("APPDATA").unwrap_or_default();
    if let Some(u) = os_user() {
        let name = match u.name.rfind('\\') {
            Some(i) => u.name[i + 1..].to_string(),
            None => u.name,
        };
        s.insert("user".into(), name);
        s.insert("passfile".into(), join(&app_data, &["postgresql", "pgpass.conf"]));
        s.insert("servicefile".into(), join(&u.home, &[".pg_service.conf"]));
        let sslcert = join(&app_data, &["postgresql", "postgresql.crt"]);
        let sslkey = join(&app_data, &["postgresql", "postgresql.key"]);
        if exists(&sslcert) && exists(&sslkey) {
            s.insert("sslcert".into(), sslcert);
            s.insert("sslkey".into(), sslkey);
        }
        let sslrootcert = join(&app_data, &["postgresql", "root.crt"]);
        if exists(&sslrootcert) {
            s.insert("sslrootcert".into(), sslrootcert);
        }
    }
    s.insert("target_session_attrs".into(), "any".into());
    s
}

#[cfg(unix)]
fn default_host() -> String {
    for p in ["/var/run/postgresql", "/private/tmp", "/tmp"] {
        if exists(p) {
            return p.into();
        }
    }
    "localhost".into()
}

#[cfg(windows)]
fn default_host() -> String {
    "localhost".into()
}

fn env_settings() -> Settings {
    let mut s = Settings::new();
    for (env, key) in ENV_SETTINGS {
        if let Ok(v) = std::env::var(env)
            && !v.is_empty()
        {
            s.insert((*key).into(), v);
        }
    }
    s
}

fn merge(sets: &[&Settings]) -> Settings {
    let mut out = Settings::new();
    for s in sets {
        for (k, v) in s.iter() {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

fn ishex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn unhex(c: u8) -> u8 {
    9 * (c >> 6) + (c & 15)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

fn host_should_escape(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
        c,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'[' | b']' | b'<' | b'>' | b'"' | b'-' | b'_' | b'.' | b'~'
    )
}

fn unescape(s: &str, mode: Mode) -> Result<String, String> {
    let b = s.as_bytes();
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                n += 1;
                if i + 2 >= b.len() || !ishex(b[i + 1]) || !ishex(b[i + 2]) {
                    let rest = &b[i..];
                    let cut = &rest[..rest.len().min(3)];
                    return Err(format!("invalid URL escape {}", quote(&String::from_utf8_lossy(cut))));
                }
                if mode == Mode::Host && unhex(b[i + 1]) < 8 && &b[i..i + 3] != b"%25" {
                    return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                }
                if mode == Mode::Zone {
                    let v = (unhex(b[i + 1]) << 4) | unhex(b[i + 2]);
                    if &b[i..i + 3] != b"%25" && v != b' ' && host_should_escape(v) {
                        return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == Mode::QueryComponent;
                i += 1;
            }
            c => {
                if (mode == Mode::Host || mode == Mode::Zone) && c < 0x80 && host_should_escape(c) {
                    return Err(format!("invalid character {} in host name", quote(&s[i..i + 1])));
                }
                i += 1;
            }
        }
    }
    if n == 0 && !has_plus {
        return Ok(s.to_string());
    }
    let plus = if mode == Mode::QueryComponent { b' ' } else { b'+' };
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                out.push((unhex(b[i + 1]) << 4) | unhex(b[i + 2]));
                i += 3;
            }
            b'+' => {
                out.push(plus);
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    let Some(digits) = port.strip_prefix(':') else { return false };
    digits.bytes().all(|b| b.is_ascii_digit())
}

fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|r| {
        r.is_ascii_alphanumeric()
            || matches!(r, '-' | '.' | '_' | ':' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | '%' | '@')
    })
}

fn parse_host(host: &str) -> Result<String, String> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return Err("invalid IP-literal".into());
        }
        let Some(close) = host.rfind(']') else { return Err("missing ']' in host".into()) };
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
        let colon_port = unescape(colon_port, Mode::Host)?;
        let hostname = &host[open + 1..close];
        let unescaped = match hostname.find("%25") {
            Some(z) => unescape(&hostname[..z], Mode::Host)? + &unescape(&hostname[z..], Mode::Zone)?,
            None => unescape(hostname, Mode::Host)?,
        };
        let addr_part = unescaped.split('%').next().unwrap_or("");
        match addr_part.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => return Err("invalid IP-literal".into()),
            Ok(IpAddr::V6(_)) => {}
            Err(_) => return Err(format!("invalid host: ParseAddr({}): unable to parse IP", quote(&unescaped))),
        }
        return Ok(format!("[{unescaped}]{colon_port}"));
    }
    if let Some(i) = host.rfind(':') {
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
    }
    unescape(host, Mode::Host)
}

struct Url {
    scheme: String,
    user: Option<(String, Option<String>)>,
    host: String,
    raw_after_authority: String,
    path: String,
    raw_query: String,
}

fn parse_url(raw: &str) -> Result<Url, String> {
    let (u, frag) = match raw.find('#') {
        Some(i) => (&raw[..i], Some(&raw[i + 1..])),
        None => (raw, None),
    };
    if u.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err("net/url: invalid control character in URL".into());
    }
    let colon = u.find(':').expect("caller checked the postgres scheme");
    let scheme = u[..colon].to_ascii_lowercase();
    let mut rest = &u[colon + 1..];
    let mut raw_query = String::new();
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else if let Some(q) = rest.find('?') {
        raw_query = rest[q + 1..].to_string();
        rest = &rest[..q];
    }
    let mut user = None;
    let mut host = String::new();
    let mut path_part = rest;
    if let Some(after) = rest.strip_prefix("//") {
        let (authority, p) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        path_part = p;
        let at = authority.rfind('@');
        host = parse_host(match at {
            Some(i) => &authority[i + 1..],
            None => authority,
        })?;
        if let Some(i) = at {
            let userinfo = &authority[..i];
            if !valid_userinfo(userinfo) {
                return Err("net/url: invalid userinfo".into());
            }
            user = Some(match userinfo.find(':') {
                None => (unescape(userinfo, Mode::UserPassword)?, None),
                Some(c) => (unescape(&userinfo[..c], Mode::UserPassword)?, Some(unescape(&userinfo[c + 1..], Mode::UserPassword)?)),
            });
        }
    }
    let path = unescape(path_part, Mode::Path)?;
    if let Some(f) = frag
        && !f.is_empty()
    {
        unescape(f, Mode::Fragment)?;
    }
    let after_authority = match raw.find("//") {
        Some(i) => {
            let a = &raw[i + 2..];
            match a.find(['/', '?', '#']) {
                Some(j) => a[j..].to_string(),
                None => String::new(),
            }
        }
        None => String::new(),
    };
    Ok(Url { scheme, user, host, raw_after_authority: after_authority, path, raw_query })
}

fn userinfo_escape(s: &str) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        let keep = c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b',' | b';' | b'=' | b'!' | b'\'' | b'(' | b')' | b'*');
        if keep {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn host_escape(s: &str) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        if c >= 0x80 || !host_should_escape(c) || c == b'%' {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn redact_url(u: &Url) -> String {
    let mut out = format!("{}:", u.scheme);
    if !u.host.is_empty() || !u.path.is_empty() || u.user.is_some() {
        out.push_str("//");
    }
    if let Some((name, pw)) = &u.user {
        out.push_str(&userinfo_escape(name));
        if pw.is_some() {
            out.push_str(":xxxxx");
        }
        out.push('@');
    }
    out.push_str(&host_escape(&u.host));
    out.push_str(&u.raw_after_authority);
    out
}

fn replace_quoted_password(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("password='") {
        let after = &rest[i + "password='".len()..];
        match after.find('\'') {
            Some(j) => {
                out.push_str(&rest[..i]);
                out.push_str("password=xxxxx");
                rest = &after[j + 1..];
            }
            None => {
                out.push_str(&rest[..i + 1]);
                rest = &rest[i + 1..];
            }
        }
    }
    out + rest
}

fn replace_plain_password(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("password=") {
        out.push_str(&rest[..i]);
        out.push_str("password=xxxxx");
        let after = &rest[i + "password=".len()..];
        let end = after.find(' ').unwrap_or(after.len());
        rest = &after[end..];
    }
    out + rest
}

fn replace_broken_url_password(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            let mut k = i + 1;
            while k < b.len() && b[k] != b':' && b[k] != b'@' {
                k += 1;
            }
            if k > i + 1 && k < b.len() && b[k] == b'@' {
                out.push_str(&s[last..i]);
                out.push_str(":xxxxxx@");
                last = k + 1;
                i = k + 1;
                continue;
            }
        }
        i += 1;
    }
    out + &s[last..]
}

pub(crate) fn redact_password(conn: &str) -> String {
    if (conn.starts_with("postgres://") || conn.starts_with("postgresql://"))
        && let Ok(u) = parse_url(conn)
    {
        return redact_url(&u);
    }
    replace_broken_url_password(&replace_plain_password(&replace_quoted_password(conn)))
}

fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let addr_err = |why: &str| format!("address {hostport}: {why}");
    let Some(i) = hostport.rfind(':') else { return Err(addr_err("missing port in address")) };
    let (host, j, k);
    if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else { return Err(addr_err("missing ']' in address")) };
        if end + 1 == hostport.len() {
            return Err(addr_err("missing port in address"));
        } else if end + 1 != i {
            return Err(if hostport.as_bytes()[end + 1] == b':' { addr_err("too many colons in address") } else { addr_err("missing port in address") });
        }
        host = hostport[1..end].to_string();
        j = 1;
        k = end + 1;
    } else {
        host = hostport[..i].to_string();
        if host.contains(':') {
            return Err(addr_err("too many colons in address"));
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') {
        return Err(addr_err("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(addr_err("unexpected ']' in address"));
    }
    Ok((host, hostport[i + 1..].to_string()))
}

fn is_ip_only(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() || !host.contains(':')
}

fn parse_url_settings(conn: &str) -> Result<Settings, String> {
    let u = parse_url(conn)?;
    let mut s = Settings::new();
    if let Some((name, pw)) = &u.user {
        if !name.is_empty() {
            s.insert("user".into(), name.clone());
        }
        if let Some(pw) = pw {
            s.insert("password".into(), pw.clone());
        }
    }
    let mut hosts = Vec::new();
    let mut ports = Vec::new();
    for h in u.host.split(',') {
        if h.is_empty() {
            continue;
        }
        if is_ip_only(h) {
            hosts.push(h.trim_matches(['[', ']']).to_string());
            continue;
        }
        let (hh, pp) = split_host_port(h).map_err(|e| format!("failed to split host:port in '{h}', err: {e}"))?;
        if !hh.is_empty() {
            hosts.push(hh);
        }
        if !pp.is_empty() {
            ports.push(pp);
        }
    }
    if !hosts.is_empty() {
        s.insert("host".into(), hosts.join(","));
    }
    if !ports.is_empty() {
        s.insert("port".into(), ports.join(","));
    }
    let database = u.path.trim_start_matches('/');
    if !database.is_empty() {
        s.insert("database".into(), database.to_string());
    }
    let mut first: BTreeMap<String, String> = BTreeMap::new();
    if u.raw_query.matches('&').count() < 10000 {
        for pair in u.raw_query.split('&') {
            if pair.contains(';') || pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let (Ok(k), Ok(v)) = (unescape(k, Mode::QueryComponent), unescape(v, Mode::QueryComponent)) else { continue };
            first.entry(k).or_insert(v);
        }
    }
    for (k, v) in first {
        let k = if k == "dbname" { "database".to_string() } else { k };
        s.insert(k, v);
    }
    Ok(s)
}

fn is_go_space(c: u8) -> bool {
    matches!(c, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

fn kv_unescape(v: &str) -> String {
    v.replace("\\\\", "\\").replace("\\'", "'")
}

fn parse_keyword_value_settings(input: &str) -> Result<Settings, String> {
    let mut s = Settings::new();
    let mut rest = input;
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { return Err("invalid keyword/value".into()) };
        let mut key = rest[..eq].trim_matches(|c: char| c.is_ascii() && is_go_space(c as u8)).to_string();
        rest = rest[eq + 1..].trim_start_matches(|c: char| c.is_ascii() && is_go_space(c as u8));
        let b = rest.as_bytes();
        let val;
        if b.is_empty() {
            val = String::new();
        } else if b[0] != b'\'' {
            let mut end = 0;
            while end < b.len() {
                if is_go_space(b[end]) {
                    break;
                }
                if b[end] == b'\\' {
                    end += 1;
                    if end == b.len() {
                        return Err("invalid backslash".into());
                    }
                }
                end += 1;
            }
            val = kv_unescape(&rest[..end]);
            rest = if end == b.len() { "" } else { &rest[end + 1..] };
        } else {
            let q = &rest[1..];
            let qb = q.as_bytes();
            let mut end = 0;
            while end < qb.len() {
                if qb[end] == b'\'' {
                    break;
                }
                if qb[end] == b'\\' {
                    end += 1;
                }
                end += 1;
            }
            if end >= qb.len() {
                return Err("unterminated quoted string in connection info string".into());
            }
            val = kv_unescape(&q[..end]);
            rest = &q[end + 1..];
        }
        if key == "dbname" {
            key = "database".into();
        }
        if key.is_empty() {
            return Err("invalid keyword/value".into());
        }
        if key == "user" && val.is_empty() {
            continue;
        }
        s.insert(key, val);
    }
    Ok(s)
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("open {path}: {}", errno_text(&e)))
}

fn parse_service_settings(path: &str, name: &str) -> Result<Settings, String> {
    let read_err = || format!("failed to read service file: {path}");
    let text = std::fs::read(path).map_err(|_| read_err())?;
    let text = String::from_utf8_lossy(&text);
    let mut services: Vec<(String, Settings)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
        } else if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            services.push((line[1..line.len() - 1].to_string(), Settings::new()));
        } else if let Some((_, settings)) = services.last_mut() {
            let Some((k, v)) = line.split_once('=') else { return Err(read_err()) };
            settings.insert(k.trim().to_string(), v.trim().to_string());
        } else {
            return Err(read_err());
        }
    }
    let mut by_name: BTreeMap<String, Settings> = BTreeMap::new();
    for (n, s) in services {
        by_name.insert(n, s);
    }
    let svc = by_name.remove(name).ok_or_else(|| format!("unable to find service: {name}"))?;
    Ok(svc.into_iter().map(|(k, v)| (if k == "dbname" { "database".to_string() } else { k }, v)).collect())
}

fn parse_port(s: &str) -> Result<u16, String> {
    let port: u64 = parse_uint_go(s, 16)?;
    if port < 1 {
        return Err("outside range".into());
    }
    Ok(port as u16)
}

fn parse_uint_go(s: &str, bits: u32) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(parse_uint_error(s, "invalid syntax"));
    }
    let max = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    match s.parse::<u64>() {
        Ok(v) if v <= max => Ok(v),
        _ => Err(parse_uint_error(s, "value out of range")),
    }
}

fn parse_int_go(s: &str, bits: u32) -> Result<i64, String> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(parse_int_error(s, "invalid syntax"));
    }
    let neg = s.starts_with('-');
    let max = if bits == 64 { i64::MAX as i128 } else { (1i128 << (bits - 1)) - 1 };
    let min = -max - 1;
    let mag: i128 = match digits.parse::<u128>() {
        Ok(v) if v <= i128::MAX as u128 => v as i128,
        _ => return Err(parse_int_error(s, "value out of range")),
    };
    let v = if neg { -mag } else { mag };
    if v > max || v < min {
        return Err(parse_int_error(s, "value out of range"));
    }
    Ok(v as i64)
}

fn first_pem_block(buf: &[u8]) -> Option<(String, &[u8])> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut search = 0;
    while let Some(off) = text[search..].find("-----BEGIN ") {
        let start = search + off;
        let label_start = start + "-----BEGIN ".len();
        let label_len = text[label_start..].find("-----")?;
        let label = &text[label_start..label_start + label_len];
        let end_marker = format!("-----END {label}-----");
        if let Some(e) = text[label_start..].find(&end_marker) {
            let end = label_start + e + end_marker.len();
            return Some((label.to_string(), &buf[start..end]));
        }
        search = label_start;
    }
    None
}

fn load_client_cert(sslcert: &str, sslkey: &str, sslpassword: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let key_buf = read_file(sslkey).map_err(|e| format!("unable to read sslkey: {e}"))?;
    let Some((_, block)) = first_pem_block(&key_buf) else { return Err("failed to decode sslkey".into()) };
    if String::from_utf8_lossy(block).contains("DEK-Info:") {
        if sslpassword.is_empty() {
            return Err("unable to find sslpassword".into());
        }
        return Err("unable to decrypt key: encrypted PEM private keys (DEK-Info) are not supported; decrypt the key or use PKCS#8".into());
    }
    let cert_buf = read_file(sslcert).map_err(|e| format!("unable to read cert: {e}"))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_buf).filter_map(Result::ok).collect();
    if certs.is_empty() {
        return Err("unable to load cert: tls: failed to find any PEM data in certificate input".into());
    }
    let key = PrivateKeyDer::from_pem_slice(block).map_err(|_| "unable to load cert: tls: failed to parse private key".to_string())?;
    let provider = rustls::crypto::ring::default_provider();
    rustls::sign::CertifiedKey::from_der(certs.clone(), key.clone_key(), &provider).map_err(|e| match e {
        rustls::Error::InconsistentKeys(_) => "unable to load cert: tls: private key does not match public key".to_string(),
        other => format!("unable to load cert: tls: {other}"),
    })?;
    Ok((certs, key))
}

fn get<'a>(s: &'a Settings, k: &str) -> &'a str {
    s.get(k).map(String::as_str).unwrap_or("")
}

fn config_tls(settings: &Settings, host: &str) -> Result<Vec<Option<Arc<TlsPlan>>>, String> {
    let mut sslmode = get(settings, "sslmode").to_string();
    let sslrootcert = get(settings, "sslrootcert");
    let sslcert = get(settings, "sslcert");
    let sslkey = get(settings, "sslkey");
    let sslpassword = get(settings, "sslpassword");
    let sslsni = match get(settings, "sslsni") {
        "" => "1",
        v => v,
    };
    let direct = get(settings, "sslnegotiation") == "direct";
    if sslmode.is_empty() {
        sslmode = "prefer".into();
    }
    if direct && sslmode == "prefer" {
        sslmode = "require".into();
    }
    let mut roots = Roots::System;
    if !sslrootcert.is_empty() {
        if sslrootcert == "system" {
            sslmode = "verify-full".into();
        } else {
            let buf = read_file(sslrootcert).map_err(|e| format!("unable to read CA file: {e}"))?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&buf).filter_map(Result::ok).collect();
            if certs.is_empty() {
                return Err("unable to add CA to cert pool".into());
            }
            roots = Roots::Pem(certs);
        }
    }
    let verify = match sslmode.as_str() {
        "disable" => return Ok(vec![None]),
        "allow" | "prefer" => Verify::None,
        "require" if sslrootcert.is_empty() => Verify::None,
        "require" | "verify-ca" => Verify::Chain,
        "verify-full" => Verify::Full,
        _ => return Err("sslmode is invalid".into()),
    };
    if sslcert.is_empty() != sslkey.is_empty() {
        return Err("both \"sslcert\" and \"sslkey\" are required".into());
    }
    let client = if !sslcert.is_empty() { Some(load_client_cert(sslcert, sslkey, sslpassword)?) } else { None };
    let plan = Arc::new(TlsPlan { verify, roots, client, sni: sslsni == "1" && host.parse::<IpAddr>().is_err(), direct });
    Ok(match sslmode.as_str() {
        "allow" => vec![None, Some(plan)],
        "prefer" => vec![Some(plan), None],
        _ => vec![Some(plan)],
    })
}

fn read_passfile(path: &str) -> Option<Vec<[String; 5]>> {
    let text = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&text);
    let mut entries = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.starts_with('#') {
            continue;
        }
        let line = line.replace("\\\\", "\r").replace("\\:", "\n");
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 5 {
            continue;
        }
        let un = |p: &str| p.replace('\r', "\\").replace('\n', ":");
        entries.push([un(parts[0]), un(parts[1]), un(parts[2]), un(parts[3]), un(parts[4])]);
    }
    Some(entries)
}

fn find_password(entries: &[[String; 5]], host: &str, port: &str, db: &str, user: &str) -> String {
    for e in entries {
        let m = |a: &str, b: &str| a == "*" || a == b;
        if m(&e[0], host) && m(&e[1], port) && m(&e[2], db) && m(&e[3], user) {
            return e[4].clone();
        }
    }
    String::new()
}

fn protocol_version(s: &str) -> Result<(u32, &'static str), String> {
    match s {
        "" => Ok((30, "")),
        "3.0" => Ok((30, "3.0")),
        "3.2" => Ok((32, "3.2")),
        "latest" => Ok((32, "latest")),
        _ => Err(format!("invalid protocol version: {}", quote(s))),
    }
}

pub(crate) fn parse_config(conn: &str) -> Result<ConnConfig, ParseConfigError> {
    let defaults = default_settings();
    let env = env_settings();
    let conn_settings = if conn.is_empty() {
        Settings::new()
    } else if conn.starts_with("postgres://") || conn.starts_with("postgresql://") {
        parse_url_settings(conn).map_err(|e| pce(conn, "failed to parse as URL", Some(e)))?
    } else {
        parse_keyword_value_settings(conn).map_err(|e| pce(conn, "failed to parse as keyword/value", Some(e)))?
    };
    let mut settings = merge(&[&defaults, &env, &conn_settings]);
    if let Some(service) = settings.get("service").cloned() {
        let svc = parse_service_settings(get(&settings, "servicefile"), &service).map_err(|e| pce(conn, "failed to read service", Some(e)))?;
        settings = merge(&[&defaults, &env, &svc, &conn_settings]);
    }
    let connect_timeout = match settings.get("connect_timeout") {
        Some(v) => {
            let n = parse_int_go(v, 64).map_err(|e| pce(conn, "invalid connect_timeout", Some(e)))?;
            if n < 0 {
                return Err(pce(conn, "invalid connect_timeout", Some("negative timeout".into())));
            }
            Some(Duration::from_secs(n as u64))
        }
        None => None,
    };
    let mut runtime_params: Settings = settings.iter().filter(|(k, _)| !NOT_RUNTIME_PARAMS.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut fallbacks = Vec::new();
    let hosts: Vec<&str> = get(&settings, "host").split(',').collect();
    let ports: Vec<&str> = get(&settings, "port").split(',').collect();
    for (i, host) in hosts.iter().enumerate() {
        let port_str = ports.get(i).copied().unwrap_or(ports[0]);
        let port = parse_port(port_str).map_err(|e| pce(conn, "invalid port", Some(e)))?;
        let tls_plans = if is_absolute_path(host) { vec![None] } else { config_tls(&settings, host).map_err(|e| pce(conn, "failed to configure TLS", Some(e)))? };
        for tls in tls_plans {
            fallbacks.push(Fallback { host: host.to_string(), port, tls });
        }
    }
    let user = get(&settings, "user").to_string();
    let database = get(&settings, "database").to_string();
    let mut password = get(&settings, "password").to_string();
    if let Some(entries) = read_passfile(get(&settings, "passfile"))
        && password.is_empty()
    {
        let first = &fallbacks[0];
        let host = if is_absolute_path(&first.host) { "localhost" } else { first.host.as_str() };
        password = find_password(&entries, host, &first.port.to_string(), &database, &user);
    }
    let session_attrs = match get(&settings, "target_session_attrs") {
        "read-write" => SessionAttrs::ReadWrite,
        "read-only" => SessionAttrs::ReadOnly,
        "primary" => SessionAttrs::Primary,
        "standby" => SessionAttrs::Standby,
        "prefer-standby" => SessionAttrs::PreferStandby,
        "any" => SessionAttrs::Any,
        other => return Err(pce(conn, format!("unknown target_session_attrs value: {other}"), None)),
    };
    let min_raw = get(&settings, "min_protocol_version");
    let max_raw = get(&settings, "max_protocol_version");
    let (min_v, min_name) = protocol_version(min_raw).map_err(|e| pce(conn, format!("invalid min_protocol_version: {}", quote(min_raw)), Some(e)))?;
    let (max_v, max_name) = protocol_version(max_raw).map_err(|e| pce(conn, format!("invalid max_protocol_version: {}", quote(max_raw)), Some(e)))?;
    let min_protocol = if min_name.is_empty() { "3.0" } else { min_name };
    let max_protocol = if !max_name.is_empty() {
        max_name
    } else if min_v > 30 {
        "latest"
    } else {
        "3.0"
    };
    if min_v > max_v && !max_raw.is_empty() {
        return Err(pce(conn, "min_protocol_version cannot be greater than max_protocol_version", None));
    }
    let channel_binding = match get(&settings, "channel_binding") {
        "" | "prefer" => ChannelBinding::Prefer,
        "disable" => ChannelBinding::Disable,
        "require" => ChannelBinding::Require,
        other => return Err(pce(conn, format!("unknown channel_binding value: {other}"), None)),
    };
    for key in ["statement_cache_capacity", "description_cache_capacity"] {
        if let Some(v) = runtime_params.remove(key) {
            parse_int_go(&v, 32).map_err(|e| pce(conn, format!("cannot parse {key}"), Some(e)))?;
        }
    }
    if let Some(v) = runtime_params.remove("default_query_exec_mode")
        && !matches!(v.as_str(), "cache_statement" | "cache_describe" | "describe_exec" | "exec" | "simple_protocol")
    {
        return Err(pce(conn, "invalid default_query_exec_mode", Some(format!("unknown value {}", quote(&v)))));
    }
    Ok(ConnConfig {
        user,
        password,
        database,
        runtime_params,
        fallbacks,
        connect_timeout,
        session_attrs,
        channel_binding,
        min_protocol,
        max_protocol,
    })
}

pub(crate) fn unix_socket_address(dir: &str, port: u16) -> String {
    format!("{}{port}", clean_join(dir, ".s.PGSQL."))
}

fn clean_join(dir: &str, file: &str) -> String {
    let joined = if dir.is_empty() { file.to_string() } else { format!("{dir}/{file}") };
    let rooted = joined.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let body = parts.join("/");
    if rooted { format!("/{body}") } else { body }
}

impl ConnConfig {
    pub(crate) fn startup_options(&self) -> (Option<String>, Option<String>) {
        let mut options = self.runtime_params.get("options").cloned();
        let app = self.runtime_params.get("application_name").cloned();
        for (k, v) in &self.runtime_params {
            if k == "options" || k == "application_name" {
                continue;
            }
            let esc: String = v
                .chars()
                .flat_map(|c| match c {
                    ' ' | '\\' => vec!['\\', c],
                    c => vec![c],
                })
                .collect();
            let o = options.get_or_insert_with(String::new);
            if !o.is_empty() {
                o.push(' ');
            }
            o.push_str(&format!("-c {k}={esc}"));
        }
        (options, app)
    }
}

#[doc(hidden)]
pub fn parse_config_dump(conn: &str) -> String {
    let cfg = match parse_config(conn) {
        Ok(c) => c,
        Err(e) => return format!("err: {e}\n"),
    };
    let mut out = format!(
        "user={} password={} database={} connect_timeout={} tsa={:?} channel_binding={} min={} max={}\n",
        quote(&cfg.user),
        quote(&cfg.password),
        quote(&cfg.database),
        cfg.connect_timeout.map(|d| d.as_secs()).unwrap_or(0),
        cfg.session_attrs,
        match cfg.channel_binding {
            ChannelBinding::Disable => "disable",
            ChannelBinding::Require => "require",
            _ => "prefer",
        },
        cfg.min_protocol,
        cfg.max_protocol
    );
    for (k, v) in &cfg.runtime_params {
        out.push_str(&format!("runtime {}={}\n", k, quote(v)));
    }
    for f in &cfg.fallbacks {
        match &f.tls {
            None => out.push_str(&format!("fallback host={} port={} tls=none\n", quote(&f.host), f.port)),
            Some(p) => out.push_str(&format!(
                "fallback host={} port={} tls={} sni={} direct={} roots={} client={}\n",
                quote(&f.host),
                f.port,
                match p.verify {
                    Verify::None => "noverify",
                    Verify::Chain => "chain",
                    Verify::Full => "full",
                },
                if p.sni || p.verify == Verify::Full { quote(&f.host) } else { quote("") },
                p.direct,
                match &p.roots {
                    Roots::System => "system".to_string(),
                    Roots::Pem(c) => format!("pem:{}", c.len()),
                },
                p.client.is_some()
            )),
        }
    }
    out
}
