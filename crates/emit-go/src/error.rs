use std::fmt;

/// A spec the Go emitter cannot render, or a package name Go refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Error { message: message.into() }
    }
}

impl From<demesne_model::Error> for Error {
    fn from(e: demesne_model::Error) -> Self {
        Error::new(e.to_string())
    }
}

impl From<demesne_emit_sql::Error> for Error {
    fn from(e: demesne_emit_sql::Error) -> Self {
        Error::new(e.to_string())
    }
}

impl From<demesne_emit_ts::Error> for Error {
    fn from(e: demesne_emit_ts::Error) -> Self {
        Error::new(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
