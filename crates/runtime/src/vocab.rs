use crate::{Error, Str, Strs};
use demesne_gocompat::quote;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Implication {
    pub perm: Str,
    pub set: Strs,
    pub star: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preset {
    pub name: Str,
    pub level: Str,
    pub set: Strs,
    pub star: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vocabulary {
    pub name: Str,
    pub permissions: Strs,
    pub implications: Cow<'static, [Implication]>,
    pub presets: Cow<'static, [Preset]>,
    pub rank: Strs,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationCap {
    pub allowed: bool,
    pub unknown: Vec<String>,
    pub excess: Vec<String>,
}

impl Vocabulary {
    #[must_use]
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
        self.permissions.iter().filter(|p| p.starts_with(prefix)).map(std::string::ToString::to_string).collect()
    }

    /// Returns `perm` and every permission it implies, transitively, in sorted order.
    ///
    /// # Errors
    ///
    /// A cyclic implication, or an implication naming a permission the vocabulary does not declare.
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
            into.extend(self.permissions.iter().map(std::string::ToString::to_string));
            return Ok(());
        }
        on_stack.insert(perm.to_string());
        let result = self.expand_implied_items(perm, im, into, on_stack);
        on_stack.remove(perm);
        result
    }

    fn expand_implied_items(&self, perm: &str, im: &Implication, into: &mut BTreeSet<String>, on_stack: &mut HashSet<String>) -> Result<(), Error> {
        for item in im.set.iter() {
            for m in &self.implied_item_targets(perm, item)? {
                self.expand_implication(m, into, on_stack)?;
            }
        }
        Ok(())
    }

    fn implied_item_targets(&self, perm: &str, item: &str) -> Result<Vec<String>, Error> {
        let matched = self.match_wildcard(item);
        if !matched.is_empty() {
            return Ok(matched);
        }
        if !self.has_permission(item) {
            return Err(Error::new(format!(
                "vocabulary {}: permission {} implies {}, which is neither a permission of this vocabulary nor a `<domain>:*` wildcard matching one",
                quote(&self.name),
                quote(perm),
                quote(item)
            )));
        }
        Ok(vec![item.to_string()])
    }

    /// Returns `perms` followed by everything each implying permission among them implies.
    ///
    /// # Errors
    ///
    /// An implication that is cyclic or names neither a permission nor a matching wildcard.
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

    /// Returns the permissions preset `name` grants, with nested presets expanded, in sorted order.
    ///
    /// # Errors
    ///
    /// No preset called `name`, a cyclic preset, or a preset entry that is neither a permission nor a preset.
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
            into.extend(self.permissions.iter().map(std::string::ToString::to_string));
            return Ok(());
        }
        on_stack.insert(name.to_string());
        let result = self.expand_preset_items(name, p, into, on_stack);
        on_stack.remove(name);
        result
    }

    fn expand_preset_items(&self, name: &str, p: &Preset, into: &mut BTreeSet<String>, on_stack: &mut HashSet<String>) -> Result<(), Error> {
        for item in p.set.iter() {
            if self.has_permission(item) {
                into.insert(item.to_string());
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
    }

    #[must_use]
    pub fn rank_of(&self, preset: &str) -> Option<usize> {
        self.rank.iter().position(|r| r == preset)
    }

    #[must_use]
    pub fn presets_at_or_above(&self, threshold: &str) -> Vec<String> {
        let Some(ti) = self.rank_of(threshold) else { return Vec::new() };
        self.rank[..=ti].iter().map(std::string::ToString::to_string).collect()
    }

    pub fn cap_grant(&self, held: &[String], requested: &[String]) -> DelegationCap {
        let in_vocab: HashSet<&str> = self.permissions.iter().map(std::convert::AsRef::as_ref).collect();
        let held: HashSet<&str> = held.iter().map(String::as_str).collect();
        let mut unknown: Vec<String> = Vec::new();
        let mut excess: Vec<String> = Vec::new();
        for p in requested {
            let bucket = if !in_vocab.contains(p.as_str()) {
                &mut unknown
            } else if !held.contains(p.as_str()) {
                &mut excess
            } else {
                continue;
            };
            if !bucket.contains(p) {
                bucket.push(p.clone());
            }
        }
        unknown.sort();
        excess.sort();
        DelegationCap { allowed: unknown.is_empty() && excess.is_empty(), unknown, excess }
    }
}
