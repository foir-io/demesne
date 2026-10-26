const fn send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    send_sync::<demesne_emit_ts::Error>();
}
