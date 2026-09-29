//! Byte-stream plumbing: framing, crypto and compression.
//!
//! The layers stack in a fixed order, and getting the order wrong is silent
//! corruption rather than an error:
//!
//! ```text
//! transport (tcp/tls/websocket/kcp)
//!   └── optional snappy framed compression      (use_compression)
//!         └── optional AES-128-CFB stream       (use_encryption, and always
//!                                                on the control connection)
//!               └── message framing             (v1 or v2)
//! ```
//!
//! The control connection always has the crypto layer, whatever the config says;
//! [`crate::crypto`] explains why.

pub mod codec;
pub mod compress;
pub mod connector;
pub mod mux;
pub mod stream;
pub mod transport;

pub use codec::{Codec, WireProtocol};
pub use connector::{Connector, LogicalConn};
pub use mux::Session as MuxSession;
pub use stream::CryptoStream;
