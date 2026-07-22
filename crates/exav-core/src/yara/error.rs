//! Error type for compilation and scanning.

use std::fmt;

/// An error produced while compiling or scanning YARA rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    msg: String,
}

impl Error {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }

    /// A compile error for a construct that this Phase-A implementation does
    /// not (yet) support. Such rules are REJECTED, never silently
    /// mis-evaluated.
    pub(crate) fn unsupported(what: impl fmt::Display) -> Self {
        Self {
            msg: format!("unsupported YARA construct: {what}"),
        }
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
