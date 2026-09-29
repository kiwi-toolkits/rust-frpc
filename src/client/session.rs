//! An established control session.

use crate::config::ClientConfig;
use crate::error::Result;
use crate::msg::{LoginResp, Message};
use crate::proto::{Codec, Connector, CryptoStream, LogicalConn};

/// A logged-in control connection to `frps`.
///
/// Owns the connection and the framing, so the rest of the client deals in
/// messages rather than bytes. The crypto layer is already installed: `frps`
/// encrypts the control connection unconditionally, whatever `transport.tls` and
/// `useEncryption` say.
pub struct Session {
    codec: Codec,
    stream: CryptoStream<LogicalConn>,
    /// The connector this session's control stream came from. Kept because work
    /// and visitor connections are opened from the same multiplexed socket.
    connector: Connector,
    /// The run id `frps` assigned. Sent on every reconnect so the server can
    /// hand back the proxies this client owned.
    run_id: String,
    /// The server's version, for the log line and for capability decisions.
    server_version: String,
    config: ClientConfig,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("run_id", &self.run_id)
            .field("server_version", &self.server_version)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(
        codec: Codec,
        stream: CryptoStream<LogicalConn>,
        connector: Connector,
        resp: LoginResp,
        config: ClientConfig,
    ) -> Self {
        Self {
            codec,
            stream,
            connector,
            run_id: resp.run_id,
            server_version: resp.version,
            config,
        }
    }

    /// The run id `frps` assigned to this session.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The version string `frps` reported.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// The connector, which work and visitor connections are opened from.
    pub fn connector(&self) -> &Connector {
        &self.connector
    }

    /// Sends one message.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        self.codec.write(&mut self.stream, message).await
    }

    /// Receives one message.
    pub async fn recv(&mut self) -> Result<Message> {
        self.codec.read(&mut self.stream).await
    }

    /// Sends a message and waits for the reply, with a deadline.
    ///
    /// frp's control conversation is strictly one message in flight, so a
    /// request/response helper is enough for `NewProxy`, `Ping` and
    /// `CloseProxy`.
    pub async fn round_trip(
        &mut self,
        message: &Message,
        timeout: std::time::Duration,
    ) -> Result<Message> {
        self.send(message).await?;
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => Err(crate::error::Error::protocol(format!(
                "no reply within {timeout:?}"
            ))),
        }
    }

    /// Closes the connection.
    pub async fn close(mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Splits the session so the control loop can read and write from different
    /// tasks.
    ///
    /// Needed because the conversation is genuinely concurrent: `frps` sends
    /// `ReqWorkConn` whenever it wants a connection, while the client is sending
    /// `Ping` on its own schedule. A single `recv` loop that also answers means
    /// a heartbeat cannot be sent while the loop is parked waiting for the server
    /// to say something, which is exactly when it is needed.
    pub fn split(self) -> (SessionControl, SessionEvents) {
        let (reader, writer) = tokio::io::split(self.stream);
        (
            SessionControl {
                codec: self.codec,
                writer,
            },
            SessionEvents {
                codec: self.codec,
                reader,
                run_id: self.run_id,
                server_version: self.server_version,
                config: self.config,
                connector: self.connector,
            },
        )
    }
}

/// The write half of a session: sends messages.
#[derive(Debug)]
pub struct SessionControl {
    codec: Codec,
    writer: tokio::io::WriteHalf<CryptoStream<LogicalConn>>,
}

impl SessionControl {
    /// Sends one message.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        self.codec.write(&mut self.writer, message).await
    }

    /// The framing, which work connections have to match.
    pub fn codec(&self) -> Codec {
        self.codec
    }
}

/// The read half of a session: receives messages, and carries the facts about
/// the session that the rest of the client needs.
#[derive(Debug)]
pub struct SessionEvents {
    codec: Codec,
    reader: tokio::io::ReadHalf<CryptoStream<LogicalConn>>,
    run_id: String,
    server_version: String,
    config: ClientConfig,
    connector: Connector,
}

impl SessionEvents {
    /// Receives one message.
    pub async fn recv(&mut self) -> Result<Message> {
        self.codec.read(&mut self.reader).await
    }

    /// The run id `frps` assigned.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The version `frps` reported.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// The connector work connections are opened from.
    pub fn connector(&self) -> &Connector {
        &self.connector
    }
}
