use std::fmt;

/// Why the Rust surface cannot be generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Io,
    Spec,
    Surface,
}

impl Error {
    pub(crate) fn io(message: impl Into<String>) -> Self {
        Error { kind: Kind::Io, message: message.into() }
    }

    pub(crate) fn spec(message: impl Into<String>) -> Self {
        Error { kind: Kind::Spec, message: message.into() }
    }

    pub(crate) fn surface(message: impl Into<String>) -> Self {
        Error { kind: Kind::Surface, message: message.into() }
    }

    /// Returns whether a file could not be read or written, or `OUT_DIR` is unset.
    #[must_use]
    pub fn is_io(&self) -> bool {
        self.kind == Kind::Io
    }

    /// Returns whether the spec does not parse or validate.
    #[must_use]
    pub fn is_spec(&self) -> bool {
        self.kind == Kind::Spec
    }

    /// Returns whether a requested surface cannot be built from the spec.
    #[must_use]
    pub fn is_surface(&self) -> bool {
        self.kind == Kind::Surface
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
