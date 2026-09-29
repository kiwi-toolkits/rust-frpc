//! Handing out logical connections to `frps`.
//!
//! With `transport.tcpMux` on — the default — one TCP connection carries every
//! logical connection as a yamux stream. With it off, each logical connection is
//! its own socket. Both look the same to the caller, which is what
//! [`Connector`] is for; the Go client has the same split in
//! `client/connector.go`.
//!
//! A connector is shared between the control session and every work connection,
//! so opening a stream has to be safe from several tasks at once.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::proto::mux;
use crate::proto::transport;

/// A logical connection to `frps`: a yamux stream, or a whole TCP socket.
#[derive(Debug)]
pub enum LogicalConn {
    Plain(TcpStream),
    Stream(mux::Stream),
}

impl AsyncRead for LogicalConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LogicalConn::Plain(socket) => Pin::new(socket).poll_read(cx, buf),
            LogicalConn::Stream(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LogicalConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            LogicalConn::Plain(socket) => Pin::new(socket).poll_write(cx, buf),
            LogicalConn::Stream(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LogicalConn::Plain(socket) => Pin::new(socket).poll_flush(cx),
            LogicalConn::Stream(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LogicalConn::Plain(socket) => Pin::new(socket).poll_shutdown(cx),
            LogicalConn::Stream(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// How the client reaches `frps`.
///
/// Cloning is cheap: the multiplexed variant shares one session behind an `Arc`,
/// so a clone is a handle rather than a second connection.
#[derive(Debug, Clone)]
pub enum Connector {
    /// One socket per logical connection.
    Plain(PlainConnector),
    /// One socket, many streams.
    Muxed(MuxConnector),
}

impl Connector {
    /// Opens a fresh logical connection.
    pub async fn connect(&self) -> Result<LogicalConn> {
        match self {
            Connector::Plain(connector) => connector.connect().await,
            Connector::Muxed(connector) => connector.connect().await,
        }
    }

    /// Whether this connector multiplexes.
    pub fn is_muxed(&self) -> bool {
        matches!(self, Connector::Muxed(_))
    }

    /// Closes the underlying connection, if the connector owns one.
    pub async fn close(&self) {
        if let Connector::Muxed(connector) = self {
            connector.session.close().await;
        }
    }

    /// Builds a connector from a completed transport config.
    pub async fn open(
        addr: &str,
        dial_timeout: Duration,
        local_ip: &str,
        keepalive: Option<Duration>,
        tcp_mux: bool,
        mux_keepalive: Duration,
    ) -> Result<Connector> {
        if tcp_mux {
            let socket = transport::connect(addr, dial_timeout, local_ip, keepalive).await?;
            let session = mux::Session::client(
                socket,
                mux::Config {
                    keepalive_interval: mux_keepalive,
                    ..mux::Config::default()
                },
            );
            Ok(Connector::Muxed(MuxConnector { session }))
        } else {
            Ok(Connector::Plain(PlainConnector {
                addr: addr.to_string(),
                dial_timeout,
                local_ip: local_ip.to_string(),
                keepalive,
            }))
        }
    }
}

/// A connector for the non-multiplexed case: every logical connection is a dial.
#[derive(Debug, Clone)]
pub struct PlainConnector {
    addr: String,
    dial_timeout: Duration,
    local_ip: String,
    keepalive: Option<Duration>,
}

impl PlainConnector {
    async fn connect(&self) -> Result<LogicalConn> {
        let socket = transport::connect(
            &self.addr,
            self.dial_timeout,
            &self.local_ip,
            self.keepalive,
        )
        .await?;
        Ok(LogicalConn::Plain(socket))
    }
}

/// A connector over a single multiplexed socket.
#[derive(Debug, Clone)]
pub struct MuxConnector {
    session: mux::Session,
}

impl MuxConnector {
    async fn connect(&self) -> Result<LogicalConn> {
        let stream = self.session.open_stream().await?;
        Ok(LogicalConn::Stream(stream))
    }

    /// The session, for callers that need to accept server-initiated streams.
    pub fn session(&self) -> &mux::Session {
        &self.session
    }
}

/// Whether a failure is worth retrying.
///
/// Transport-level problems are: a dial that never connected, a stream a dead
/// session refused, a socket error. A server that understood us and said no
/// is not — retrying `proxy [x] already exists` just repeats it, and retrying a
/// rejected login is a config problem, not a transient one.
pub fn is_retryable(error: &Error) -> bool {
    match error {
        Error::Io(_) | Error::Other(_) | Error::Protocol(_) => true,
        Error::Rejected(_) | Error::Login(_) => false,
        // A bad config or a TLS handshake failure will fail the same way next
        // time, so retrying only delays the report.
        Error::Config(_) | Error::Tls(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn retryability_distinguishes_transport_from_policy() {
        assert!(is_retryable(&Error::other("connection refused")));
        assert!(is_retryable(&Error::protocol("session closed")));
        // A server that understood us and refused is not a transient failure.
        assert!(!is_retryable(&Error::Rejected("already exists".into())));
        assert!(!is_retryable(&Error::Login("bad token".into())));
        assert!(!is_retryable(&Error::config("bad key")));
    }

    #[tokio::test]
    async fn a_plain_connector_dials_per_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let mut first = listener.accept().await.unwrap().0;
            let mut buf = [0u8; 3];
            first.read_exact(&mut buf).await.unwrap();
            let mut second = listener.accept().await.unwrap().0;
            let mut buf2 = [0u8; 3];
            second.read_exact(&mut buf2).await.unwrap();
            (buf, buf2)
        });

        let connector = Connector::Plain(PlainConnector {
            addr: addr.to_string(),
            dial_timeout: Duration::from_secs(5),
            local_ip: String::new(),
            keepalive: None,
        });
        assert!(!connector.is_muxed());

        for payload in [b"one", b"two"] {
            let mut conn = connector.connect().await.unwrap();
            conn.write_all(payload).await.unwrap();
            conn.flush().await.unwrap();
        }

        let (first, second) = accept.await.unwrap();
        assert_eq!(&first, b"one");
        assert_eq!(&second, b"two");
    }

    #[tokio::test]
    async fn a_muxed_connector_reuses_one_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_socket = tokio::spawn(async move { listener.accept().await.unwrap().0 });

        let connector = Connector::open(
            &addr.to_string(),
            Duration::from_secs(5),
            "",
            None,
            true,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert!(connector.is_muxed());

        let socket = server_socket.await.unwrap();
        let session = mux::Session::server(socket, mux::Config::default());

        // Two logical connections, one socket.
        let acceptor = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut stream = session.accept().await.unwrap();
                let mut buf = [0u8; 3];
                tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                seen.push(buf);
            }
            seen
        });

        for payload in [b"one", b"two"] {
            let mut conn = connector.connect().await.unwrap();
            conn.write_all(payload).await.unwrap();
            conn.flush().await.unwrap();
        }

        let seen = acceptor.await.unwrap();
        assert_eq!(&seen[0], b"one");
        assert_eq!(&seen[1], b"two");
    }
}
