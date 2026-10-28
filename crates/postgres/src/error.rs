use std::fmt;

/// Why a live database could not be reached or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ConnectionString,
    Connect,
    Query,
    Sql,
}

impl Error {
    pub(crate) fn connection_string(message: impl Into<String>) -> Self {
        Error { kind: Kind::ConnectionString, message: message.into() }
    }

    pub(crate) fn connect(message: impl Into<String>) -> Self {
        Error { kind: Kind::Connect, message: message.into() }
    }

    pub(crate) fn query(message: impl Into<String>) -> Self {
        Error { kind: Kind::Query, message: message.into() }
    }

    pub(crate) fn sql(message: impl Into<String>) -> Self {
        Error { kind: Kind::Sql, message: message.into() }
    }

    /// Returns whether the connection string does not parse.
    #[must_use]
    pub fn is_connection_string(&self) -> bool {
        self.kind == Kind::ConnectionString
    }

    /// Returns whether no host in the connection string accepted a session: DNS, the network, TLS or authentication failed.
    #[must_use]
    pub fn is_connect(&self) -> bool {
        self.kind == Kind::Connect
    }

    /// Returns whether a query against the connected database failed.
    #[must_use]
    pub fn is_query(&self) -> bool {
        self.kind == Kind::Query
    }

    /// Returns whether the SQL to compare is not in the form demesne writes.
    #[must_use]
    pub fn is_sql(&self) -> bool {
        self.kind == Kind::Sql
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
