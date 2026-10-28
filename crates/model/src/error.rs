use demesne_syntax::Finding;
use std::fmt;

/// A spec the model refuses, with every problem found, each on its line when it has one.
///
/// It displays as the findings joined by newlines, in the order they were found. An error from one emitter
/// names it first, as in `PDP emit:`, and indents its findings beneath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    heading: Option<&'static str>,
    findings: Vec<Finding>,
}

impl Error {
    pub(crate) fn new(findings: Vec<Finding>) -> Self {
        Error { heading: None, findings }
    }

    pub(crate) fn headed(heading: &'static str, findings: Vec<Finding>) -> Self {
        Error { heading: Some(heading), findings }
    }

    pub(crate) fn at(line: usize, message: impl Into<String>) -> Self {
        Error::new(vec![Finding::at(line, message)])
    }

    pub(crate) fn unplaced(message: impl Into<String>) -> Self {
        Error::new(vec![Finding::unplaced(message)])
    }

    /// Returns every problem found, in the order they are reported.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Returns every problem found, consuming the error.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

impl From<Finding> for Error {
    fn from(f: Finding) -> Self {
        Error::new(vec![f])
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(heading) = self.heading {
            write!(f, "{heading}:")?;
            return self.findings.iter().try_for_each(|finding| write!(f, "\n  {finding}"));
        }
        self.findings.iter().enumerate().try_for_each(|(i, finding)| if i == 0 { finding.fmt(f) } else { write!(f, "\n{finding}") })
    }
}

impl std::error::Error for Error {}

pub(crate) fn refuse_any<T>(findings: Vec<Finding>, ok: T) -> Result<T, Error> {
    if findings.is_empty() { Ok(ok) } else { Err(Error::new(findings)) }
}
