use crate::error::Error;
use crate::manifest::{Manifest, Object, units};
use crate::{Sql, validate, validate_warnings};
use demesne_syntax::{Finding, SpecFiles};
use std::collections::BTreeMap;

/// Validates a spec written in several files, one prefix at a time: each file with the files before it.
///
/// Every prefix has to validate on its own, as it is what a database holds once the files up to it are applied, so a
/// file may refer to what the files before it declare and never to what a later file does.
///
/// # Errors
///
/// The first prefix that does not validate, with each finding placed in its file: a finding that belongs to no line is
/// placed in that prefix's last file.
pub fn validate_files(files: &SpecFiles) -> Result<(), Error> {
    for k in 0..files.len() {
        if let Err(e) = validate(files.prefix(k)) {
            return Err(Error::of_findings(e.findings().iter().map(|f| files.place_in(k, f)).collect()));
        }
    }
    Ok(())
}

/// Returns the warnings each prefix of a valid spec in several files earns, each once and placed in its file.
#[must_use]
pub fn validate_files_warnings(files: &SpecFiles) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for k in 0..files.len() {
        for w in validate_warnings(files.prefix(k)) {
            let w = files.place_in(k, &w);
            if !out.contains(&w) {
                out.push(w);
            }
        }
    }
    out
}

/// Returns the SQL of the `k`-th file of a spec in several files, counting from zero.
///
/// It is what the file's prefix emits that the prefix before it does not, or emits differently, followed by the drops
/// of what the prefix before it creates and this prefix no longer does. Applied in order, the files' SQL leaves the
/// database holding what the whole spec's SQL creates. A function a later file changes, because the file adds to what
/// the function covers or replaces the declaration it comes from, is written again in that file, and its
/// `CREATE OR REPLACE` replaces the earlier body. The first file's SQL is its whole SQL, as [`Sql::write_all_sql`]
/// writes it.
///
/// # Errors
///
/// A prefix's SQL does not compile, or it creates an object the manifest does not record.
///
/// # Panics
///
/// When there is no `k`-th file.
pub fn file_sql(files: &SpecFiles, k: usize) -> Result<String, Error> {
    let current = all_sql(files.prefix(k))?;
    let Some(before) = k.checked_sub(1) else { return Ok(current) };
    let previous = all_sql(files.prefix(before))?;
    let mut b = changed_units(&current, &previous)?;
    b.push_str(&manifest_of(&current)?.drops_since(&manifest_of(&previous)?));
    Ok(b)
}

/// Returns a migration of the `k`-th file of a spec in several files from the surface `previous` records for its prefix.
///
/// It is the file's share of the SQL, as [`file_sql`] writes it, followed by the drops of what `previous` or the prefix
/// before it creates and this prefix no longer does. For the first file it is [`Sql::migration`].
///
/// # Errors
///
/// A prefix's SQL does not compile, or it creates an object the manifest does not record.
///
/// # Panics
///
/// When there is no `k`-th file.
pub fn file_migration(files: &SpecFiles, k: usize, previous: &Manifest) -> Result<String, Error> {
    let Some(before) = k.checked_sub(1) else { return Sql::new(files.prefix(0)).migration(previous) };
    let current = all_sql(files.prefix(k))?;
    let earlier = all_sql(files.prefix(before))?;
    let mut b = changed_units(&current, &earlier)?;
    b.push_str(&manifest_of(&current)?.drops_since(&previous.clone().union(&manifest_of(&earlier)?)));
    Ok(b)
}

fn all_sql(s: &demesne_syntax::Spec) -> Result<String, Error> {
    let mut b = String::new();
    Sql::new(s).write_all_sql(&mut b)?;
    Ok(b)
}

fn manifest_of(sql: &str) -> Result<Manifest, Error> {
    Manifest::from_sql(sql).map_err(|e| Error::unplaced(e.to_string()))
}

fn changed_units(current: &str, previous: &str) -> Result<String, Error> {
    let before: BTreeMap<Object, String> = units(previous).map_err(Error::unplaced)?.into_iter().collect();
    let mut b = String::new();
    for (object, unit) in units(current).map_err(Error::unplaced)? {
        if before.get(&object) != Some(&unit) {
            if !b.is_empty() {
                b.push('\n');
            }
            b.push_str(&unit);
        }
    }
    Ok(b)
}
