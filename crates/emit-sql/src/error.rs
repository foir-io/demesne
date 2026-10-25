use demesne_syntax::Finding;
use std::fmt;

/// A spec the SQL emitter refuses, with every problem found, each on its line when it has one.
///
/// It displays as the findings joined by newlines, in the order they were found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    repr: Repr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Repr {
    Model(demesne_model::Error),
    Findings(Vec<Finding>),
}

impl Error {
    pub(crate) fn unplaced(message: impl Into<String>) -> Self {
        Error { repr: Repr::Findings(vec![Finding::unplaced(message)]) }
    }

    /// Returns every problem found, in the order they are reported.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        match &self.repr {
            Repr::Model(e) => e.findings(),
            Repr::Findings(f) => f,
        }
    }
}

impl From<demesne_model::Error> for Error {
    fn from(e: demesne_model::Error) -> Self {
        Error { repr: Repr::Model(e) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Model(e) => e.fmt(f),
            Repr::Findings(findings) => findings.iter().enumerate().try_for_each(|(i, finding)| if i == 0 { finding.fmt(f) } else { write!(f, "\n{finding}") }),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn refuse_any(findings: Vec<Finding>) -> Result<(), Error> {
    if findings.is_empty() { Ok(()) } else { Err(Error { repr: Repr::Findings(findings) }) }
}

/// A manifest, or SQL read back into one, that is not in the form demesne writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    message: String,
}

impl ManifestError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        ManifestError { message: message.into() }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ManifestError {}
