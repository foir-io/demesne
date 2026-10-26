use demesne_runtime::Decision::{Allow, Deny, NotGoverned};
use demesne_runtime::{
    AffordanceHint, AffordanceSource, Consistency, Freshness, IndexAnswer, Session, SettingLifetime, Zookie, compose_affordance, compose_can,
};

#[test]
fn a_point_check_and_the_pdp_compose_as_the_go_engine_composes_them() {
    let table = [
        (Allow, Allow, Allow),
        (Allow, Deny, Deny),
        (Allow, NotGoverned, Allow),
        (Deny, Allow, Deny),
        (Deny, Deny, Deny),
        (Deny, NotGoverned, Deny),
        (NotGoverned, Allow, Allow),
        (NotGoverned, Deny, Deny),
        (NotGoverned, NotGoverned, NotGoverned),
    ];
    for (point, pdp, want) in table {
        assert_eq!(compose_can(point, pdp), want, "compose_can({point:?}, {pdp:?})");
    }
}

#[test]
fn an_affordance_carries_the_index_answer_unless_the_index_is_behind() {
    let watermark = Zookie::from_xid(100);
    let cases = [
        (IndexAnswer::Allowed, Consistency::MinimizeLatency, AffordanceHint::Likely, Freshness::Unknown),
        (IndexAnswer::Denied, Consistency::MinimizeLatency, AffordanceHint::Unlikely, Freshness::Unknown),
        (IndexAnswer::Allowed, Consistency::FullyConsistent, AffordanceHint::Likely, Freshness::Unknown),
        (IndexAnswer::Allowed, Consistency::AtLeastAsFresh(Zookie::from_xid(99)), AffordanceHint::Likely, Freshness::CaughtUp),
        (IndexAnswer::Denied, Consistency::AtLeastAsFresh(Zookie::from_xid(99)), AffordanceHint::Unlikely, Freshness::CaughtUp),
        (IndexAnswer::Allowed, Consistency::AtLeastAsFresh(Zookie::from_xid(100)), AffordanceHint::Unknown, Freshness::Stale),
        (IndexAnswer::Denied, Consistency::AtLeastAsFresh(Zookie::from_xid(150)), AffordanceHint::Unknown, Freshness::Stale),
    ];
    for (answer, c, hint, freshness) in cases {
        let a = compose_affordance(answer, watermark, c);
        assert_eq!((a.hint, a.freshness, a.source, a.as_of), (hint, freshness, AffordanceSource::AsyncIndex, watermark), "{answer:?} under {c:?}");
        assert_eq!(a.render(), hint == AffordanceHint::Likely, "{answer:?} under {c:?}");
    }
}

#[test]
fn a_transaction_setting_ends_with_the_transaction_and_a_session_setting_does_not() {
    let s = Session::default();
    assert_eq!(s.session_setup_sql(SettingLifetime::Transaction), ["SET LOCAL ROLE authenticated", "SELECT set_config('request.jwt.claims', $1, true)"]);
    assert_eq!(s.session_setup_sql(SettingLifetime::Session), ["SET ROLE authenticated", "SELECT set_config('request.jwt.claims', $1, false)"]);
}
