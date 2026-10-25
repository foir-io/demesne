use demesne_postgres::parse_config_dump;

fn targets(conn: &str) -> Vec<String> {
    let dump = parse_config_dump(conn);
    let out: Vec<String> = dump
        .lines()
        .filter_map(|l| l.strip_prefix("fallback host="))
        .map(|l| {
            let (host, rest) = l.split_once(" port=").expect("a fallback names its port");
            format!("{}:{}", host.trim_matches('"'), rest.split(' ').next().unwrap_or_default())
        })
        .collect();
    assert!(!out.is_empty(), "{conn} parses to no host: {dump}");
    out
}

fn default_port() -> String {
    let only = targets("postgres://u@probe/db?sslmode=disable");
    only[0].rsplit_once(':').map(|(_, p)| p.to_string()).expect("a port")
}

fn default_host() -> String {
    let only = targets("postgres://u@:1/db?sslmode=disable");
    only[0].rsplit_once(':').map(|(h, _)| h.to_string()).expect("a host")
}

#[test]
fn each_url_host_keeps_its_own_port_and_a_bare_one_takes_the_default() {
    let d = default_port();
    assert_eq!(targets("postgres://u@h1:5001,h2:5002,h3/db?sslmode=disable"), ["h1:5001".to_string(), "h2:5002".into(), format!("h3:{d}")]);
    assert_eq!(targets("postgres://u@h1:5433,h2/db?sslmode=disable"), ["h1:5433".to_string(), format!("h2:{d}")]);
    assert_eq!(targets("postgres://u@h1,h2,h3:5009/db?sslmode=disable"), [format!("h1:{d}"), format!("h2:{d}"), "h3:5009".into()]);
    assert_eq!(targets("postgres://u@[::1]:5432,[::2]:5433/db?sslmode=disable"), ["::1:5432", "::2:5433"]);
}

#[test]
fn an_empty_url_host_is_the_default_host() {
    let (d, h) = (default_port(), default_host());
    assert_eq!(targets("postgres://u@h1,:5009/db?sslmode=disable"), [format!("h1:{d}"), format!("{h}:5009")]);
}

#[test]
fn one_keyword_port_still_serves_every_host() {
    assert_eq!(targets("host=h1,h2 port=5009 user=u sslmode=disable"), ["h1:5009", "h2:5009"]);
}

#[test]
fn a_bad_port_on_any_host_is_refused() {
    let dump = parse_config_dump("postgres://u@h1:x,h2/db");
    assert!(dump.contains(r#"invalid port ":x" after host"#), "{dump}");
}
