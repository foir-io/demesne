#[test]
#[ignore = "needs DEMESNE_PG_URL on a server older than Postgres 18; run with -- --ignored"]
fn a_minimum_protocol_the_server_lacks_is_named_in_the_refusal() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to connect to a live Postgres"));
    let sep = if url.contains('?') { '&' } else { '?' };
    let Err(err) = demesne_postgres::connect(&format!("{url}{sep}min_protocol_version=3.2")) else { panic!("Postgres 17 speaks only protocol 3.0") };
    assert!(err.ends_with("server protocol version too low: min_protocol_version is 3.2, but the server speaks only protocol 3.0"), "{err}");
}
