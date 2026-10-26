#![doc = "The demesne runtime. Everything here operates on compiled data: nothing in this crate parses a spec."]

mod access;
mod app_surface;
mod claims;
mod consistency;
mod error;
mod grant;
mod holds;
mod pdp;
pub mod projection;
mod role_assignment;
mod vocab;

pub use access::ResourceAccessSurface;
pub use app_surface::{AppCheck, AppCheckSurface, AppObjectSurface};
pub use claims::{
    ClaimEntry, LevelClaim, Principal, Session, SettingLifetime, SubjectIdentity, build_claims, mint_claims_values, mint_claims_values_with_extra,
};
pub use consistency::{
    Affordance, AffordanceHint, AffordanceSource, Consistency, ConsistencyLevel, Freshness, IndexAnswer, Zookie, compose_affordance, zookie_now_sql,
};
pub use error::Error;
pub use grant::GrantSurface;
pub use holds::{EffectivePerms, EffectiveRoles, HoldsResolver, RoleAssignment, resolve_roles, scope_all_empty, scope_contains, within_plane};
pub use pdp::{Decision, Pdp, capability_gate_err, compose_can};
pub use role_assignment::{RoleAssignmentSurface, touch_on_conflict};
pub use vocab::{DelegationCap, Implication, Preset, Vocabulary};

pub type SqlArg = Option<String>;

pub type Str = std::borrow::Cow<'static, str>;
pub type Strs = std::borrow::Cow<'static, [Str]>;

/// Quotes `s` as a Postgres string literal, as Postgres's own `quote_literal` does.
///
/// Each `'` is doubled. A value holding a backslash also has each backslash doubled and takes the
/// `E` prefix, so the literal means the same whatever `standard_conforming_strings` is set to.
#[must_use]
pub fn quote_literal(s: &str) -> String {
    if s.contains('\\') { format!("E'{}'", s.replace('\\', "\\\\").replace('\'', "''")) } else { format!("'{}'", s.replace('\'', "''")) }
}

pub fn owned(s: impl Into<String>) -> Str {
    std::borrow::Cow::Owned(s.into())
}

pub fn owned_list<I: IntoIterator<Item = S>, S: Into<String>>(xs: I) -> Strs {
    std::borrow::Cow::Owned(xs.into_iter().map(|s| owned(s)).collect())
}
