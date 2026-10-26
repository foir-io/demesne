const fn send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    send_sync::<demesne_model::ConditionalAdmission>();
    send_sync::<demesne_model::Error>();
    send_sync::<demesne_model::Column>();
    send_sync::<demesne_model::ForeignKey>();
    send_sync::<demesne_model::Schema>();
    send_sync::<demesne_model::TableCoverage>();
    send_sync::<demesne_model::Principal>();
    send_sync::<demesne_model::ReachGrantRef<'static>>();
    send_sync::<demesne_model::Structure>();
    send_sync::<demesne_model::analysis::CostClass>();
    send_sync::<demesne_model::analysis::Rels<'static>>();
    send_sync::<demesne_model::pdp::FieldAccessRule>();
    send_sync::<demesne_model::pdp::FieldAccess>();
    send_sync::<demesne_model::scaffold::ScaffoldOptions>();
}
