use crate::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyLevel {
    MinimizeLatency,
    AtLeastAsFresh,
    FullyConsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consistency {
    MinimizeLatency,
    AtLeastAsFresh(Zookie),
    FullyConsistent,
}

impl Consistency {
    pub fn level(&self) -> ConsistencyLevel {
        match self {
            Consistency::MinimizeLatency => ConsistencyLevel::MinimizeLatency,
            Consistency::AtLeastAsFresh(_) => ConsistencyLevel::AtLeastAsFresh,
            Consistency::FullyConsistent => ConsistencyLevel::FullyConsistent,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Zookie {
    xid: u64,
}

impl Zookie {
    pub fn from_xid(xid: u64) -> Self {
        Zookie { xid }
    }

    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.starts_with('+') {
            return Err(Error::new(format!("invalid zookie {}: strconv.ParseUint: parsing {}: invalid syntax", demesne_gocompat::quote(s), demesne_gocompat::quote(s))));
        }
        s.parse::<u64>().map(Zookie::from_xid).map_err(|e| {
            Error::new(format!("invalid zookie {}: strconv.ParseUint: parsing {}: {}", demesne_gocompat::quote(s), demesne_gocompat::quote(s), go_parse_error(&e)))
        })
    }

    pub fn reflects(&self, writer: Zookie) -> bool {
        self.xid > writer.xid
    }
}

fn go_parse_error(e: &std::num::ParseIntError) -> &'static str {
    match e.kind() {
        std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => "value out of range",
        _ => "invalid syntax",
    }
}

impl fmt::Display for Zookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.xid)
    }
}

pub fn zookie_now_sql() -> &'static str {
    "SELECT pg_current_xact_id()::text"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffordanceHint {
    Unknown,
    Likely,
    Unlikely,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Unknown,
    Stale,
    CaughtUp,
    FloorBacked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffordanceSource {
    AsyncIndex,
    Floor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Affordance {
    pub hint: AffordanceHint,
    pub as_of: Zookie,
    pub freshness: Freshness,
    pub source: AffordanceSource,
}

impl Affordance {
    pub fn render(&self) -> bool {
        self.hint == AffordanceHint::Likely
    }
}

pub fn compose_affordance(allowed: bool, as_of: Zookie, c: Consistency) -> Affordance {
    let hint = if allowed { AffordanceHint::Likely } else { AffordanceHint::Unlikely };
    if let Consistency::AtLeastAsFresh(z) = c {
        if !as_of.reflects(z) {
            return Affordance { hint: AffordanceHint::Unknown, as_of, freshness: Freshness::Stale, source: AffordanceSource::AsyncIndex };
        }
        return Affordance { hint, as_of, freshness: Freshness::CaughtUp, source: AffordanceSource::AsyncIndex };
    }
    Affordance { hint, as_of, freshness: Freshness::Unknown, source: AffordanceSource::AsyncIndex }
}
