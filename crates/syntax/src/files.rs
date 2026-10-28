use crate::ast::Spec;
use crate::error::{Error, Finding};
use crate::parser::{Fragment, Kind, Replace, expand_templates, parse_fragment};
use demesne_gocompat::quote;

/// A spec written in several files and compiled as one model.
///
/// The files are read in order, and each may refer to what the files before it declare, never to what a later file
/// does. Each file joins the files before it as if their text ran on into it, so a spec split into files compiles to
/// the model its text in one file does. A later file may also write `replace` before a declaration, which swaps it
/// in for an earlier file's declaration of the same kind and name, at that declaration's place.
///
/// The spec made of a file and the files before it is that file's prefix: what a database holds once the files up to
/// it are applied.
///
/// Lines in the prefixes' positions count on from file to file: the first line of a file follows the last line of
/// the file before. [`SpecFiles::place`] turns such a line back into a file and its own line.
#[derive(Debug, Clone)]
pub struct SpecFiles {
    names: Vec<String>,
    starts: Vec<usize>,
    prefixes: Vec<Spec>,
}

impl SpecFiles {
    /// Returns the files' names, in the order they were given.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Returns how many files the spec has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Returns whether the spec has no files, which [`parse_files`] never returns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Returns the spec made of the `k`-th file, counting from zero, and every file before it.
    ///
    /// # Panics
    ///
    /// When there is no `k`-th file.
    #[must_use]
    pub fn prefix(&self, k: usize) -> &Spec {
        &self.prefixes[k]
    }

    /// Returns the spec made of every file.
    ///
    /// # Panics
    ///
    /// Never for a value [`parse_files`] returns, which has at least one file.
    #[must_use]
    pub fn spec(&self) -> &Spec {
        self.prefixes.last().expect("parse_files refuses an empty list of files")
    }

    /// Returns `finding` with the file and the file's own line it sits on, or unchanged when it belongs to no line.
    #[must_use]
    pub fn place(&self, finding: &Finding) -> Finding {
        match finding.line() {
            Some(line) => {
                let k = self.starts.iter().rposition(|&start| start <= line).unwrap_or(0);
                finding.in_file(&self.names[k], Some(line + 1 - self.starts[k]))
            }
            None => finding.clone(),
        }
    }

    /// Returns `finding` placed as [`SpecFiles::place`] places it, or, when it belongs to no line, placed in the `k`-th
    /// file: the last file of the prefix it was found in.
    ///
    /// # Panics
    ///
    /// When there is no `k`-th file.
    #[must_use]
    pub fn place_in(&self, k: usize, finding: &Finding) -> Finding {
        match finding.line() {
            Some(_) => self.place(finding),
            None => finding.in_file(&self.names[k], None),
        }
    }

    fn place_error(&self, e: &Error) -> Error {
        Error::from_finding(self.place(e.finding()))
    }
}

/// Parses a spec written in several files, given in order as each file's name and text.
///
/// # Errors
///
/// No files; a file that does not parse; a file that declares again what an earlier file declares where the spec allows
/// it once (a `topology`, `claims`, `definers`, `tables` or `identifiers` declaration, or an external predicate);
/// a `replace` with no earlier declaration to replace; or a template that cannot be expanded. A finding names its file.
pub fn parse_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Result<SpecFiles, Error> {
    let mut out = SpecFiles { names: Vec::new(), starts: Vec::new(), prefixes: Vec::new() };
    let mut merged = Spec::default();
    let mut start = 1;
    for (name, src) in files {
        out.names.push(name.to_string());
        out.starts.push(start);
        let fragment = parse_fragment(src, start).map_err(|e| out.place_error(&e))?;
        start += src.split(|&b| b == b'\n').count();
        merge(&mut merged, fragment).map_err(|e| out.place_error(&e))?;
        let mut spec = merged.clone();
        expand_templates(&mut spec).map_err(|e| Error::from_finding(e.finding().in_file(name, e.line())))?;
        out.prefixes.push(spec);
    }
    if out.prefixes.is_empty() {
        return Err(Error::new("no spec files to parse"));
    }
    Ok(out)
}

fn merge(into: &mut Spec, fragment: Fragment) -> Result<(), Error> {
    let Fragment { spec: from, replaces, singles } = fragment;
    for &(kind, pos) in &singles {
        let replacing = replaces.iter().any(|r| r.kind == kind);
        match (single_declared(into, kind), replacing) {
            (true, false) => return Err(Error::at(pos.line, duplicate_single(kind))),
            (false, true) => return Err(Error::at(pos.line, format!("replace {}: no earlier file declares one", kind.keyword()))),
            _ => {}
        }
    }
    let Spec {
        topology,
        vocabs,
        subjects,
        objects,
        procedures,
        ungoverned,
        field_scopes,
        role_stores,
        grants,
        templates,
        externals,
        claims,
        definer_schema,
        table_schema,
        identifiers,
    } = from;
    into.topology = topology.or(into.topology.take());
    into.claims = claims.or(into.claims.take());
    into.definer_schema = definer_schema.or(into.definer_schema.take());
    into.table_schema = table_schema.or(into.table_schema.take());
    into.identifiers = identifiers.or(into.identifiers.take());
    let marked = |kind: Kind| -> Vec<Replace> { replaces.iter().filter(|r| r.kind == kind).copied().collect() };
    let external_replaces = marked(Kind::External);
    for (i, e) in externals.iter().enumerate() {
        let replacing = external_replaces.iter().any(|r| r.index == i);
        if !replacing && into.external_by_name(&e.name).is_some() {
            return Err(Error::at(e.pos.line, format!("duplicate external predicate {}", quote(&e.name))));
        }
    }
    join(&mut into.vocabs, vocabs, &marked(Kind::Vocabulary), Kind::Vocabulary, |v| &v.name)?;
    join(&mut into.subjects, subjects, &marked(Kind::Subject), Kind::Subject, |v| &v.name)?;
    join(&mut into.objects, objects, &marked(Kind::Object), Kind::Object, |v| &v.name)?;
    join(&mut into.procedures, procedures, &marked(Kind::Procedures), Kind::Procedures, |v| &v.emit_site)?;
    join(&mut into.ungoverned, ungoverned, &marked(Kind::Ungoverned), Kind::Ungoverned, |v| &v.emit_site)?;
    join(&mut into.field_scopes, field_scopes, &marked(Kind::FieldScopes), Kind::FieldScopes, |v| &v.site)?;
    join(&mut into.role_stores, role_stores, &marked(Kind::RoleStore), Kind::RoleStore, |v| &v.name)?;
    join(&mut into.grants, grants, &marked(Kind::Grant), Kind::Grant, |v| &v.name)?;
    join(&mut into.templates, templates, &marked(Kind::Template), Kind::Template, |v| &v.name)?;
    join(&mut into.externals, externals, &external_replaces, Kind::External, |v| &v.name)?;
    Ok(())
}

fn join<T>(into: &mut Vec<T>, from: Vec<T>, replaces: &[Replace], kind: Kind, name: fn(&T) -> &String) -> Result<(), Error> {
    let mut earlier = into.len();
    for (i, item) in from.into_iter().enumerate() {
        let Some(r) = replaces.iter().find(|r| r.index == i) else {
            into.push(item);
            continue;
        };
        let hits: Vec<usize> = (0..earlier).filter(|&j| name(&into[j]) == name(&item)).collect();
        let Some(&first) = hits.first() else {
            return Err(Error::at(r.pos.line, format!("replace {} {}: no earlier file declares it", kind.keyword(), quote(name(&item)))));
        };
        into[first] = item;
        for &j in hits[1..].iter().rev() {
            into.remove(j);
        }
        earlier -= hits.len() - 1;
    }
    Ok(())
}

fn single_declared(s: &Spec, kind: Kind) -> bool {
    match kind {
        Kind::Topology => s.topology.is_some(),
        Kind::Claims => s.claims.is_some(),
        Kind::Definers => s.definer_schema.is_some(),
        Kind::Tables => s.table_schema.is_some(),
        Kind::Identifiers => s.identifiers.is_some(),
        _ => false,
    }
}

fn duplicate_single(kind: Kind) -> &'static str {
    match kind {
        Kind::Topology => "duplicate topology block",
        Kind::Claims => "duplicate claims block",
        Kind::Definers => "duplicate definers block",
        Kind::Tables => "duplicate tables block",
        _ => "duplicate identifiers declaration",
    }
}

#[cfg(test)]
mod tests {
    use super::parse_files;

    #[test]
    fn a_line_is_placed_in_the_file_it_falls_in() {
        let files = parse_files([("a.demesne", &b"topology { level tenant }\n"[..]), ("b.demesne", &b"\n\nidentifiers uuid\n"[..])]).expect("the files parse");
        let line = |l| crate::Finding::at(l, "x");
        assert_eq!(files.place(&line(1)).to_string(), "a.demesne:1: x");
        assert_eq!(files.place(&line(2)).to_string(), "a.demesne:2: x");
        assert_eq!(files.place(&line(3)).to_string(), "b.demesne:1: x");
        assert_eq!(files.place(&line(5)).to_string(), "b.demesne:3: x");
        assert_eq!(files.prefix(1).identifiers.as_deref(), Some("uuid"));
    }
}
