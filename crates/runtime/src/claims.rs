use crate::{Error, Str, Strs};
use demesne_gocompat::json::{self, Value};
use demesne_gocompat::quote;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimEntry {
    pub key: Str,
    pub level: Str,
    pub subjects: Strs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub setting: Str,
    pub cast: Str,
    pub role: Str,
}

impl Default for Session {
    fn default() -> Self {
        Session { setting: Str::Borrowed("request.jwt.claims"), cast: Str::Borrowed("json"), role: Str::Borrowed("authenticated") }
    }
}

/// How long a setting made for one request lasts on its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingLifetime {
    /// Until the transaction ends: `SET LOCAL`, and `set_config(…, true)`.
    ///
    /// On a pooled connection this is the safe choice: the role and the caller's claims can't
    /// outlive the request and reach the next caller to use the connection.
    Transaction,
    /// Until the connection closes or the setting is changed again: `SET`, and `set_config(…, false)`.
    Session,
}

impl Session {
    /// Returns the statement that sets the caller's claims, whose JSON is bound as `$1`.
    #[must_use]
    pub fn claims_set_sql(&self, lifetime: SettingLifetime) -> String {
        let local = match lifetime {
            SettingLifetime::Transaction => true,
            SettingLifetime::Session => false,
        };
        format!("SELECT set_config({}, $1, {local})", crate::quote_literal(&self.setting))
    }

    /// Returns the statement that switches to the connection role the policies are written for.
    #[must_use]
    pub fn set_role_sql(&self, lifetime: SettingLifetime) -> String {
        let kw = match lifetime {
            SettingLifetime::Transaction => "SET LOCAL ROLE",
            SettingLifetime::Session => "SET ROLE",
        };
        format!("{kw} {}", self.role)
    }

    /// Returns the statements that prepare a connection for one caller: the role, then the claims.
    #[must_use]
    pub fn session_setup_sql(&self, lifetime: SettingLifetime) -> Vec<String> {
        vec![self.set_role_sql(lifetime), self.claims_set_sql(lifetime)]
    }
}

/// A subject's identity claim key, as the claims projection lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectIdentity {
    pub name: Str,
    pub identifies: Str,
}

/// A topology level's scope claim key; a virtual level has none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LevelClaim {
    pub name: Str,
    pub claim_key: Str,
    pub is_virtual: bool,
}

/// Whom a session is for: a subject, its id (empty for none), and a scope id per level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
    pub id: String,
    pub scopes: BTreeMap<String, String>,
}

/// Returns the claim values that place `principal`: its subject's identity key and a scope claim per level it names.
///
/// # Errors
///
/// An unknown subject or level, an id for a subject with no identity key, or a scope for a virtual level.
pub fn build_claims(subjects: &[SubjectIdentity], levels: &[LevelClaim], principal: &Principal) -> Result<BTreeMap<String, String>, Error> {
    let p = principal;
    let sub =
        subjects.iter().find(|s| s.name == p.subject).ok_or_else(|| Error::claims(format!("BuildClaims: no subject {} in the spec", quote(&p.subject))))?;
    let mut values = BTreeMap::new();
    if !p.id.is_empty() {
        if sub.identifies.is_empty() {
            return Err(Error::claims(format!("BuildClaims: subject {} has no identity key (`identifies`) but an id was supplied", quote(&p.subject))));
        }
        values.insert(sub.identifies.to_string(), p.id.clone());
    }
    for (name, id) in &p.scopes {
        let level = levels
            .iter()
            .find(|l| l.name == *name)
            .ok_or_else(|| Error::claims(format!("BuildClaims: subject {} presents a scope for unknown level {}", quote(&p.subject), quote(name))))?;
        if level.is_virtual {
            return Err(Error::claims(format!("BuildClaims: level {} is virtual (no scope claim) — it cannot carry a scope id", quote(name))));
        }
        values.insert(level.claim_key.to_string(), id.clone());
    }
    Ok(values)
}

/// Mints a claims JSON object from `values`, refusing keys outside the claims contract.
///
/// # Errors
///
/// A key in `values` that `contract` does not name.
pub fn mint_claims_values<S: AsRef<str>>(contract: &[S], values: &BTreeMap<String, String>) -> Result<String, Error> {
    mint_claims_values_with_extra(contract, values, None)
}

/// Mints a claims JSON object from `values` plus unchecked `extra` keys, which win on conflict.
///
/// # Errors
///
/// A key in `values` that `contract` does not name. Keys in `extra` are not checked.
pub fn mint_claims_values_with_extra<S: AsRef<str>>(
    contract: &[S],
    values: &BTreeMap<String, String>,
    extra: Option<&BTreeMap<String, String>>,
) -> Result<String, Error> {
    let known: HashSet<&str> = contract.iter().map(std::convert::AsRef::as_ref).collect();
    let bad: Vec<&str> = values.keys().map(String::as_str).filter(|k| !known.contains(k)).collect();
    if !bad.is_empty() {
        return Err(Error::claims(format!("MintClaims: key(s) not in the claims contract: [{}]", bad.join(" "))));
    }
    let mut merged: BTreeMap<String, String> = values.clone();
    if let Some(extra) = extra {
        merged.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    Ok(json::marshal(&Value::Map(merged.into_iter().map(|(k, v)| (k, Value::Str(v))).collect())))
}
