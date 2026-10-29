use std::fmt;

/// Why a document was not converted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a document of the format asked for.
    NotFormat(String),
    /// Encrypted with a password other than the default one, or with a
    /// method this reader does not have.
    Encrypted,
    /// A valid document of a version or kind this reader does not convert.
    Unsupported(String),
    /// Past one of the [`Limits`](crate::formats::office::sheets::Limits): what it was.
    TooLarge(&'static str),
    /// Damaged beyond what this reader recovers from.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFormat(why) => write!(f, "not a document of this format: {why}"),
            Error::Encrypted => f.write_str("encrypted with a password"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
            Error::TooLarge(what) => write!(f, "too large: {what}"),
            Error::Malformed(why) => write!(f, "damaged: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// A short machine-readable kind: `not-format`, `encrypted`,
    /// `unsupported`, `too-large` or `malformed`.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::NotFormat(_) => "not-format",
            Error::Encrypted => "encrypted",
            Error::Unsupported(_) => "unsupported",
            Error::TooLarge(_) => "too-large",
            Error::Malformed(_) => "malformed",
        }
    }
}

impl From<crate::formats::office::common::xml::Error> for Error {
    fn from(e: crate::formats::office::common::xml::Error) -> Self {
        use crate::formats::office::common::xml::Error as X;
        match e {
            X::Malformed(why) => Error::Malformed(format!("XML: {why}")),
            X::TooLarge(what) => Error::TooLarge(what),
            X::NotFormat(why) => Error::NotFormat(why),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
