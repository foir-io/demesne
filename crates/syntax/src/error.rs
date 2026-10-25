use std::fmt;

/// A problem found in a spec, and the line it sits on when it belongs to one.
///
/// It displays as `line N: message`, or as the message alone when it belongs to no single line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    line: Option<usize>,
    message: String,
}

impl Finding {
    /// Creates a finding on a 1-based `line`.
    pub fn at(line: usize, message: impl Into<String>) -> Self {
        Finding { line: Some(line), message: message.into() }
    }

    /// Creates a finding that belongs to no single line.
    pub fn unplaced(message: impl Into<String>) -> Self {
        Finding { line: None, message: message.into() }
    }

    /// Returns the 1-based line the finding sits on, if it belongs to one.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// Returns the finding's text without its line.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// A spec that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    finding: Finding,
}

impl Error {
    pub(crate) fn at(line: usize, message: impl Into<String>) -> Self {
        Error { finding: Finding::at(line, message) }
    }

    pub(crate) fn new(message: impl Into<String>) -> Self {
        Error { finding: Finding::unplaced(message) }
    }

    /// Returns where the spec stops parsing, and why.
    #[must_use]
    pub fn finding(&self) -> &Finding {
        &self.finding
    }

    /// Returns the 1-based line the spec stops parsing on, if the problem belongs to one line.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        self.finding.line()
    }

    /// Returns why the spec does not parse, without its line.
    #[must_use]
    pub fn message(&self) -> &str {
        self.finding.message()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.finding.fmt(f)
    }
}

impl std::error::Error for Error {}
