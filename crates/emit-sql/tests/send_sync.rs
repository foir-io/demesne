const fn send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    send_sync::<demesne_emit_sql::AsyncIndex>();
    send_sync::<demesne_emit_sql::ChangelogTrigger>();
    send_sync::<demesne_emit_sql::ObjectChangelogTrigger>();
    send_sync::<demesne_emit_sql::ClosureTrigger>();
    send_sync::<demesne_emit_sql::GroupTrigger>();
    send_sync::<demesne_emit_sql::MaterializedFlat>();
    send_sync::<demesne_emit_sql::Error>();
    send_sync::<demesne_emit_sql::ManifestError>();
    send_sync::<demesne_emit_sql::DefinerArm>();
    send_sync::<demesne_emit_sql::GenFn>();
    send_sync::<demesne_emit_sql::Manifest>();
    send_sync::<demesne_emit_sql::Object>();
    send_sync::<demesne_emit_sql::Policy>();
    send_sync::<demesne_emit_sql::RlsResult>();
    send_sync::<demesne_emit_sql::Sql<'static>>();
}
