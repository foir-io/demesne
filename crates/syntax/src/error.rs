use std::fmt;

/// A problem found in a spec, and the file and line it sits on when it belongs to one.
///
/// It displays as `line N: message`, or as the message alone when it belongs to no single line. A finding in a spec
/// made of several files names its file too: `file:N: message`, or `file: message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    file: Option<String>,
    line: Option<usize>,
    message: String,
}

impl Finding {
    /// Creates a finding on a 1-based `line`.
    pub fn at(line: usize, message: impl Into<String>) -> Self {
        Finding { file: None, line: Some(line), message: message.into() }
    }

    /// Creates a finding that belongs to no single line.
    pub fn unplaced(message: impl Into<String>) -> Self {
        Finding { file: None, line: None, message: message.into() }
    }

    pub(crate) fn in_file(&self, file: &str, line: Option<usize>) -> Self {
        Finding { file: Some(file.to_string()), line, message: self.message.clone() }
    }

    /// Returns the file the finding sits in, when the spec is made of several files.
    #[must_use]
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    /// Returns the 1-based line the finding sits on, if it belongs to one.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// Returns the finding's text without its file or line.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{file}:{line}: {}", self.message),
            (Some(file), None) => write!(f, "{file}: {}", self.message),
            (None, Some(line)) => write!(f, "line {line}: {}", self.message),
            (None, None) => f.write_str(&self.message),
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

    pub(crate) fn from_finding(finding: Finding) -> Self {
        Error { finding }
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
