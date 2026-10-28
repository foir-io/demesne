use demesne_postgres::connect;

#[test]
fn a_connection_string_that_does_not_parse_is_not_a_failed_connection() {
    let Err(err) = connect("postgres://u@localhost:notaport/db") else { panic!("the port is not a number") };
    assert!(err.is_connection_string() && !err.is_connect() && !err.is_query() && !err.is_sql(), "{err:?}");
}

#[test]
fn a_host_that_refuses_the_session_is_a_failed_connection() {
    let Err(err) = connect("postgres://u@127.0.0.1:1/db?sslmode=disable&connect_timeout=2") else { panic!("nothing listens on port 1") };
    assert!(err.is_connect() && !err.is_connection_string(), "{err:?}");
}
