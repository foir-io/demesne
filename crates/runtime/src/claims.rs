use crate::Error;
use demesne_gocompat::json::{self, Value};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimEntry {
    pub key: String,
    pub level: String,
    pub subjects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub setting: String,
    pub cast: String,
    pub role: String,
}

impl Default for Session {
    fn default() -> Self {
        Session { setting: "request.jwt.claims".into(), cast: "json".into(), role: "authenticated".into() }
    }
}

impl Session {
    pub fn claims_set_sql(&self, local: bool) -> String {
        format!("SELECT set_config('{}', $1, {local})", self.setting)
    }

    pub fn set_role_sql(&self, local: bool) -> String {
        let kw = if local { "SET LOCAL ROLE" } else { "SET ROLE" };
        format!("{kw} {}", self.role)
    }

    pub fn session_setup_sql(&self, local: bool) -> Vec<String> {
        vec![self.set_role_sql(local), self.claims_set_sql(local)]
    }
}

pub fn mint_claims_values(contract: &[String], values: &BTreeMap<String, String>) -> Result<String, Error> {
    mint_claims_values_with_extra(contract, values, None)
}

pub fn mint_claims_values_with_extra(
    contract: &[String],
    values: &BTreeMap<String, String>,
    extra: Option<&BTreeMap<String, String>>,
) -> Result<String, Error> {
    let known: HashSet<&str> = contract.iter().map(String::as_str).collect();
    let bad: Vec<&str> = values.keys().map(String::as_str).filter(|k| !known.contains(k)).collect();
    if !bad.is_empty() {
        return Err(Error::new(format!("MintClaims: key(s) not in the claims contract: [{}]", bad.join(" "))));
    }
    let mut merged: BTreeMap<String, String> = values.clone();
    if let Some(extra) = extra {
        merged.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    Ok(json::marshal(&Value::Map(merged.into_iter().map(|(k, v)| (k, Value::Str(v))).collect())))
}
