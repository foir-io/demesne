use crate::{Error, Str};
use demesne_gocompat::go_export;
use std::borrow::Cow;
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
    pub emit_site: Str,
    pub policy: Cow<'static, [(Str, Str)]>,
    pub ungoverned: Cow<'static, [(Str, Str)]>,
}

fn lookup<'a>(entries: &'a [(Str, Str)], key: &str) -> Option<&'a str> {
    entries.binary_search_by(|(k, _)| k.as_ref().cmp(key)).ok().map(|i| entries[i].1.as_ref())
}

impl Pdp {
    #[must_use]
    pub fn permission(&self, procedure: &str) -> Option<&str> {
        lookup(&self.policy, procedure)
    }

    #[must_use]
    pub fn ungoverned_reason(&self, procedure: &str) -> Option<&str> {
        lookup(&self.ungoverned, procedure)
    }

    pub fn authorize(&self, procedure: &str, holds: impl Fn(&str) -> bool) -> Decision {
        match self.permission(procedure) {
            Some(perm) if holds(perm) => Decision::Allow,
            Some(_) => Decision::Deny,
            None => Decision::NotGoverned,
        }
    }
}

#[must_use]
pub fn capability_gate_err(object: &str, verb: &str) -> Error {
    Error::new(format!(
        "{object}.{verb} is a capability (@pdp) verb with no row-level check — resolve held permissions and call Can{}(held) on the {} object",
        go_export(verb),
        go_export(object)
    ))
}

#[must_use]
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
