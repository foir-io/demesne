use crate::Error;
use demesne_gocompat::quote;
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Implication {
    pub perm: String,
    pub set: Vec<String>,
    pub star: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preset {
    pub name: String,
    pub level: String,
    pub set: Vec<String>,
    pub star: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vocabulary {
    pub name: String,
    pub permissions: Vec<String>,
    pub implications: Vec<Implication>,
    pub presets: Vec<Preset>,
    pub rank: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationCap {
    pub allowed: bool,
    pub unknown: Vec<String>,
    pub excess: Vec<String>,
}

impl Vocabulary {
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }

    fn implication_of(&self, perm: &str) -> Option<&Implication> {
        self.implications.iter().find(|im| im.perm == perm)
    }

    fn match_wildcard(&self, item: &str) -> Vec<String> {
        let Some(prefix) = item.strip_suffix('*') else { return Vec::new() };
        if !prefix.ends_with(':') {
            return Vec::new();
        }
        self.permissions.iter().filter(|p| p.starts_with(prefix)).cloned().collect()
    }

    pub fn implied_permissions(&self, perm: &str) -> Result<Vec<String>, Error> {
        let mut into = BTreeSet::new();
        self.expand_implication(perm, &mut into, &mut HashSet::new())?;
        Ok(into.into_iter().collect())
    }

    fn expand_implication(&self, perm: &str, into: &mut BTreeSet<String>, on_stack: &mut HashSet<String>) -> Result<(), Error> {
        if on_stack.contains(perm) {
            return Err(Error::new(format!(
                "vocabulary {}: permission {} is cyclic (a permission cannot imply itself, directly or transitively)",
                quote(&self.name),
                quote(perm)
            )));
        }
        into.insert(perm.to_string());
        let Some(im) = self.implication_of(perm) else { return Ok(()) };
        if im.star {
            into.extend(self.permissions.iter().cloned());
            return Ok(());
        }
        on_stack.insert(perm.to_string());
        let result = (|| {
            for item in &im.set {
                let mut matched = self.match_wildcard(item);
                if matched.is_empty() {
                    if !self.has_permission(item) {
                        return Err(Error::new(format!(
                            "vocabulary {}: permission {} implies {}, which is neither a permission of this vocabulary nor a `<domain>:*` wildcard matching one",
                            quote(&self.name),
                            quote(perm),
                            quote(item)
                        )));
                    }
                    matched = vec![item.clone()];
                }
                for m in &matched {
                    self.expand_implication(m, into, on_stack)?;
                }
            }
            Ok(())
        })();
        on_stack.remove(perm);
        result
    }

    pub fn expand_implications(&self, perms: &[String]) -> Result<Vec<String>, Error> {
        if self.implications.is_empty() {
            return Ok(perms.to_vec());
        }
        let mut out = perms.to_vec();
        for p in perms {
            if self.implication_of(p).is_none() {
                continue;
            }
            out.extend(self.implied_permissions(p)?);
        }
        Ok(out)
    }

    fn preset_by_name(&self, name: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.name == name)
    }

    pub fn preset_permissions(&self, name: &str) -> Result<Vec<String>, Error> {
        let mut into = BTreeSet::new();
        self.expand_preset(name, &mut into, &mut HashSet::new())?;
        Ok(into.into_iter().collect())
    }

    fn expand_preset(&self, name: &str, into: &mut BTreeSet<String>, on_stack: &mut HashSet<String>) -> Result<(), Error> {
        if on_stack.contains(name) {
            return Err(Error::new(format!(
                "vocabulary {}: preset {} is cyclic (a preset cannot reference itself, directly or transitively)",
                quote(&self.name),
                quote(name)
            )));
        }
        let Some(p) = self.preset_by_name(name) else {
            return Err(Error::new(format!("vocabulary {}: no preset {}", quote(&self.name), quote(name))));
        };
        if p.star {
            into.extend(self.permissions.iter().cloned());
            return Ok(());
        }
        on_stack.insert(name.to_string());
        let result = (|| {
            for item in &p.set {
                if self.has_permission(item) {
                    into.insert(item.clone());
                } else if self.preset_by_name(item).is_some() {
                    self.expand_preset(item, into, on_stack)?;
                } else {
                    return Err(Error::new(format!(
                        "vocabulary {}: preset {} references {}, which is neither a permission nor a preset in this vocabulary",
                        quote(&self.name),
                        quote(name),
                        quote(item)
                    )));
                }
            }
            Ok(())
        })();
        on_stack.remove(name);
        result
    }

    pub fn rank_of(&self, preset: &str) -> Option<usize> {
        self.rank.iter().position(|r| r == preset)
    }

    pub fn presets_at_or_above(&self, threshold: &str) -> Vec<String> {
        let Some(ti) = self.rank_of(threshold) else { return Vec::new() };
        self.rank[..=ti].to_vec()
    }

    pub fn cap_grant(&self, held: &[String], requested: &[String]) -> DelegationCap {
        let in_vocab: HashSet<&str> = self.permissions.iter().map(String::as_str).collect();
        let held: HashSet<&str> = held.iter().map(String::as_str).collect();
        let mut unknown: Vec<String> = Vec::new();
        let mut excess: Vec<String> = Vec::new();
        for p in requested {
            if !in_vocab.contains(p.as_str()) {
                if !unknown.contains(p) {
                    unknown.push(p.clone());
                }
            } else if !held.contains(p.as_str()) && !excess.contains(p) {
                excess.push(p.clone());
            }
        }
        unknown.sort();
        excess.sort();
        DelegationCap { allowed: unknown.is_empty() && excess.is_empty(), unknown, excess }
    }
}
