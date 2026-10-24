use crate::Error;
use demesne_gocompat::go_export;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    NotGoverned,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::NotGoverned => "ungoverned",
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pdp {
    pub emit_site: String,
    pub policy: BTreeMap<String, String>,
    pub ungoverned: BTreeMap<String, String>,
}

impl Pdp {
    pub fn authorize(&self, procedure: &str, holds: impl Fn(&str) -> bool) -> Decision {
        match self.policy.get(procedure) {
            Some(perm) if holds(perm) => Decision::Allow,
            Some(_) => Decision::Deny,
            None => Decision::NotGoverned,
        }
    }
}

pub fn capability_gate_err(object: &str, verb: &str) -> Error {
    Error::new(format!(
        "{object}.{verb} is a capability (@pdp) verb with no row-level check — resolve held permissions and call Can{}(held) on the {} object",
        go_export(verb),
        go_export(object)
    ))
}

pub fn compose_can(point_governed: bool, point_allow: bool, pdp: Decision) -> Decision {
    if !point_governed && pdp == Decision::NotGoverned {
        return Decision::NotGoverned;
    }
    if point_governed && !point_allow {
        return Decision::Deny;
    }
    if pdp == Decision::Deny {
        return Decision::Deny;
    }
    Decision::Allow
}
