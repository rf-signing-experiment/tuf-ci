//! The error type shared by everything in this crate.

use std::fmt;

/// Errors produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The metadata could not be parsed or written.
    #[error("{0}")]
    Encoding(String),

    /// The metadata parsed, but says something this crate refuses to accept.
    #[error("{0}")]
    Invalid(String),

    /// A key could not be understood well enough to verify a signature with it.
    #[error("key {key_id}: {reason}")]
    Key {
        /// The key that could not be used.
        key_id: crate::crypto::KeyId,
        /// Why it could not be used.
        reason: String,
    },

    /// A signature did not verify against the key that claims to have produced it.
    #[error("signature by key {0} does not verify")]
    BadSignature(crate::crypto::KeyId),

    /// A role was asked for that the delegating metadata does not define.
    #[error("no such role: {0}")]
    NoSuchRole(String),

    /// Reading or writing the repository failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub(crate) fn encoding(msg: impl fmt::Display) -> Self {
        Error::Encoding(msg.to_string())
    }

    pub(crate) fn invalid(msg: impl fmt::Display) -> Self {
        Error::Invalid(msg.to_string())
    }

    pub(crate) fn io(context: impl fmt::Display, source: std::io::Error) -> Self {
        Error::Io {
            context: context.to_string(),
            source,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Encoding(err.to_string())
    }
}

/// A `Result` whose error is this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
