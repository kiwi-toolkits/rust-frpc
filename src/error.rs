//! The crate error type.

use std::io;

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong, with the peer-visible distinction kept: a
/// server-side rejection is not the same as a broken connection, and callers
/// (reconnect vs. rename-retry) branch on that.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    /// The server accepted the connection but refused the request, e.g.
    /// `proxy [x] already exists`.
    #[error("server rejected: {0}")]
    Rejected(String),

    #[error("login failed: {0}")]
    Login(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(message: impl Into<String>) -> Self {
        Error::Other(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Error::Protocol(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Error::Config(message.into())
    }
}
