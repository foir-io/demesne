const fn send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    send_sync::<demesne_postgres::Drift>();
    send_sync::<demesne_postgres::DriftKind>();
    send_sync::<demesne_postgres::Finding>();
    send_sync::<demesne_postgres::Error>();
    send_sync::<demesne_postgres::Severity>();
    send_sync::<demesne_postgres::Trap>();
    send_sync::<demesne_postgres::IntrospectMeta>();
}
