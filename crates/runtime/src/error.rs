use std::fmt;

/// Why a runtime surface refused a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Claims,
    Consistency,
    Vocabulary,
    Access,
    CapabilityGate,
    Input,
}

impl Error {
    pub(crate) fn claims(message: impl Into<String>) -> Self {
        Error { kind: Kind::Claims, message: message.into() }
    }

    pub(crate) fn consistency(message: impl Into<String>) -> Self {
        Error { kind: Kind::Consistency, message: message.into() }
    }

    pub(crate) fn vocabulary(message: impl Into<String>) -> Self {
        Error { kind: Kind::Vocabulary, message: message.into() }
    }

    pub(crate) fn access(message: impl Into<String>) -> Self {
        Error { kind: Kind::Access, message: message.into() }
    }

    pub(crate) fn capability_gate(message: impl Into<String>) -> Self {
        Error { kind: Kind::CapabilityGate, message: message.into() }
    }

    pub(crate) fn input(message: impl Into<String>) -> Self {
        Error { kind: Kind::Input, message: message.into() }
    }

    /// Returns why the call was refused.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns whether the claims or principal handed in do not fit the spec's subjects, levels or claims contract.
    #[must_use]
    pub fn is_claims(&self) -> bool {
        self.kind == Kind::Claims
    }

    /// Returns whether a consistency token does not parse.
    #[must_use]
    pub fn is_consistency(&self) -> bool {
        self.kind == Kind::Consistency
    }

    /// Returns whether a vocabulary's presets or implications are cyclic or name something it does not declare.
    #[must_use]
    pub fn is_vocabulary(&self) -> bool {
        self.kind == Kind::Vocabulary
    }

    /// Returns whether a conditional access surface was asked for as an unconditional one.
    #[must_use]
    pub fn is_access(&self) -> bool {
        self.kind == Kind::Access
    }

    /// Returns whether the verb is a capability with no row-level check, to be decided from held permissions instead.
    #[must_use]
    pub fn is_capability_gate(&self) -> bool {
        self.kind == Kind::CapabilityGate
    }

    /// Returns whether a projection, principal or role assignment handed in has a field missing or of the wrong type.
    #[must_use]
    pub fn is_input(&self) -> bool {
        self.kind == Kind::Input
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
