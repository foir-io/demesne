const fn send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    send_sync::<demesne_runtime::ResourceAccessSurface>();
    send_sync::<demesne_runtime::AppCheck>();
    send_sync::<demesne_runtime::AppCheckSurface>();
    send_sync::<demesne_runtime::AppObjectSurface>();
    send_sync::<demesne_runtime::ClaimEntry>();
    send_sync::<demesne_runtime::LevelClaim>();
    send_sync::<demesne_runtime::Principal>();
    send_sync::<demesne_runtime::Session>();
    send_sync::<demesne_runtime::SubjectIdentity>();
    send_sync::<demesne_runtime::Affordance>();
    send_sync::<demesne_runtime::AffordanceHint>();
    send_sync::<demesne_runtime::AffordanceSource>();
    send_sync::<demesne_runtime::Consistency>();
    send_sync::<demesne_runtime::ConsistencyLevel>();
    send_sync::<demesne_runtime::Freshness>();
    send_sync::<demesne_runtime::Zookie>();
    send_sync::<demesne_runtime::Error>();
    send_sync::<demesne_runtime::GrantSurface>();
    send_sync::<demesne_runtime::EffectivePerms>();
    send_sync::<demesne_runtime::EffectiveRoles>();
    send_sync::<demesne_runtime::HoldsResolver>();
    send_sync::<demesne_runtime::RoleAssignment>();
    send_sync::<demesne_runtime::Decision>();
    send_sync::<demesne_runtime::Pdp>();
    send_sync::<demesne_runtime::RoleAssignmentSurface>();
    send_sync::<demesne_runtime::DelegationCap>();
    send_sync::<demesne_runtime::Implication>();
    send_sync::<demesne_runtime::Preset>();
    send_sync::<demesne_runtime::Vocabulary>();
}
