//! `stcp` and `sudp` visitors: reaching a proxy that has no public port.
//!
//! A `stcp` proxy is the opposite of a `tcp` one. Nothing is published on the
//! server; the server instead keeps an *internal* listener that only visitors can
//! reach, and the visitor is the side that opens a local port:
//!
//! ```text
//!   visitor's client                       stcp proxy's client
//!   local listener  ←─ visitor conn ─←  internal listener (server)
//!        ↑                                      ↑
//!   a user connects here                        └─ NewVisitorConn{proxy_name, sign_key}
//! ```
//!
//! So the direction is reversed: the visitor connects *out* to the server and
//! names the proxy it wants, the server checks that name against the one an `stcp`
//! proxy registered, and the connection is handed to that proxy's client, which
//! joins it to its local service.
//!
//! `sudp` is the same handshake over a UDP socket instead of a TCP listener. What
//! that changes is that UDP has no connection to hang a session on, so the session
//! belongs to the *visitor* rather than to a user: the first datagram to arrive
//! opens one, every later datagram — from any user — rides on it, and each one is
//! tagged with the address it came from so the answer can find its way back. That
//! tag is the whole routing mechanism, and it is why one shared session can serve
//! several users without mixing them up.
//!
//! Three details decide whether the handshake works:
//!
//! * **The name on the wire is the target's, not ours.** `serverName` (and
//!   `serverUser`) name the proxy; the local `user` is only a fallback for
//!   `serverUser`.
//! * **The signature is over the *proxy's* secret key**, not the auth token:
//!   `hex(md5(sk ‖ decimal(timestamp)))`. A visitor that signs with the token is
//!   turned away by the server.
//! * **The per-connection crypto is keyed on the secret key too**, while the
//!   control connection is keyed on the token. Two keys in one session.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::config::{ClientConfig, VisitorConfig, VisitorKind};
use crate::crypto::auth_key;
use crate::error::{Error, Result};
use crate::logging;
use crate::msg::{Message, NewVisitorConn};
use crate::naming;
use crate::proto::{Codec, Connector, CryptoStream};

use super::bridge;
use super::control::Traffic;

/// How long to wait for the server's answer to a `NewVisitorConn`.
///
/// The Go client uses 10 seconds (`client/visitor/visitor.go`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// One visitor, reduced to what the run loop needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visitor {
    pub name: String,
    pub bind_addr: String,
    pub bind_port: u16,
    pub server_name: String,
    pub server_user: String,
    pub secret_key: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    /// `stcp` or `sudp`: the same handshake, but TCP and UDP respectively.
    pub kind: &'static str,
}

impl Visitor {
    /// Builds one from its config, or `None` for a type this client cannot run.
    ///
    /// `stcp` and `sudp` share everything except the transport; `xtcp` needs NAT
    /// hole punching, which is its own milestone.
    pub fn from_config(config: &VisitorConfig) -> Option<Self> {
        let kind = match config.kind {
            VisitorKind::Stcp {} => "stcp",
            VisitorKind::Sudp {} => "sudp",
            VisitorKind::Xtcp { .. } => return None,
        };
        let transport = config.transport.clone().unwrap_or_default();
        Some(Self {
            name: config.name.clone(),
            bind_addr: config.bind_addr.clone(),
            // A negative `bindPort` means "receive visitor connections only,
            // without a local listener", which this does not implement.
            bind_port: u16::try_from(config.bind_port).unwrap_or(0),
            server_name: config.server_name.clone(),
            server_user: config.server_user.clone(),
            secret_key: config.secret_key.expose().to_string(),
            use_encryption: transport.use_encryption,
            use_compression: transport.use_compression,
            kind,
        })
    }

    /// Whether this visitor should run at all.
    pub fn is_enabled(&self, config: &VisitorConfig, start: &[String]) -> bool {
        if config.enabled == Some(false) {
            return false;
        }
        start.is_empty() || start.iter().any(|name| name == &self.name)
    }
}

/// Starts every configured visitor.
///
/// Visitors start alongside the proxies rather than inside one: they have their
/// own listeners and their own handshakes, and a visitor is useful even while a
/// proxy on the same client is failing to start.
pub async fn start_all(
    config: &ClientConfig,
    connector: Connector,
    codec: Codec,
    run_id: &str,
    traffic: Arc<Traffic>,
) -> Visitors {
    let mut tasks = JoinSet::new();
    let mut started = Vec::new();

    for visitor_config in &config.visitors {
        let Some(visitor) = Visitor::from_config(visitor_config) else {
            logging::warn(format!(
                "visitor {}: only stcp and sudp visitors are implemented; skipping",
                visitor_config.name
            ));
            continue;
        };
        if !visitor.is_enabled(visitor_config, &config.common.start) {
            continue;
        }

        let connector = connector.clone();
        let run_id = run_id.to_string();
        let user = config.common.user.clone();
        let traffic = traffic.clone();
        let name = visitor.name.clone();

        tasks.spawn(async move {
            if let Err(err) = run(visitor, connector, codec, run_id, user, traffic).await {
                logging::warn(format!("visitor {name}: {err}"));
            }
        });
        started.push(visitor_config.name.clone());
    }

    if !started.is_empty() {
        logging::info(format!(
            "start {} visitor(s): {}",
            started.len(),
            started.join(", ")
        ));
    }
    Visitors { tasks }
}

/// The running visitors. Dropping this stops them.
pub struct Visitors {
    tasks: JoinSet<()>,
}

impl Visitors {
    /// How many are still running.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

impl Drop for Visitors {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

/// Runs one visitor: bind the local port, then serve connections on it.
async fn run(
    visitor: Visitor,
    connector: Connector,
    codec: Codec,
    run_id: String,
    user: String,
    traffic: Arc<Traffic>,
) -> Result<()> {
    if visitor.use_compression {
        // The wrapping order is the proxy's, and it is not wired up here;
        // refusing beats sending the server bytes it cannot read.
        return Err(Error::config(format!(
            "visitor {}: useCompression is not implemented",
            visitor.name
        )));
    }
    if visitor.bind_port == 0 {
        return Err(Error::config(format!(
            "visitor {}: bindPort is required",
            visitor.name
        )));
    }

    let addr = crate::proto::transport::join_host_port(&visitor.bind_addr, visitor.bind_port);
    let target =
        naming::build_target_server_proxy_name(&user, &visitor.server_user, &visitor.server_name);

    if visitor.kind == "sudp" {
        return run_udp(visitor, connector, codec, run_id, target, addr, traffic).await;
    }

    let listener = TcpListener::bind(&addr).await.map_err(|err| {
        Error::config(format!(
            "visitor {}: cannot bind {addr}: {err}",
            visitor.name
        ))
    })?;
    logging::info(format!(
        "visitor {} is listening on {addr}, forwarding to proxy {target}",
        visitor.name
    ));

    loop {
        let (user_conn, peer) = listener.accept().await?;
        logging::debug(format!("visitor {}: connection from {peer}", visitor.name));

        let connector = connector.clone();
        let visitor_name = visitor.name.clone();
        let target = target.clone();
        let secret = visitor.secret_key.clone();
        let run_id = run_id.clone();
        let use_encryption = visitor.use_encryption;
        let traffic = traffic.clone();

        // One task per user connection, like the TCP bridge: the handshake costs
        // a round trip, and nothing about it should hold up the next user.
        tokio::spawn(async move {
            let result = serve_one(
                user_conn,
                connector,
                codec,
                run_id,
                target,
                secret,
                use_encryption,
                &visitor_name,
                traffic,
            )
            .await;
            if let Err(err) = result {
                logging::warn(format!("visitor {visitor_name}: {err}"));
            }
        });
    }
}

/// Runs a `sudp` visitor.
///
/// Two things differ from `stcp` and both follow from UDP having no connection:
/// the local side is a socket rather than a listener, and a *session* belongs to
/// the visitor rather than to a user. That second one is worth stating plainly,
/// because it is the opposite of what a TCP-shaped intuition suggests, and the Go
/// client is where you can see it: it reads the bound socket through
/// `ForwardUserConn`, which tags every datagram with the address it came from and
/// drops it into one channel, and a single dispatcher opens a visitor connection
/// for the *first* datagram to land there. Every datagram after that — from that
/// user or from any other — is written onto that same connection, each one still
/// carrying its own `remote_addr`. The tag is the entire routing mechanism.
///
/// So the session here has the same shape: one visitor connection, one datagram at
/// a time off the local socket, tagged and written, with the answers coming back
/// on the session already addressed. Nobody is dropped, and nobody has to wait for
/// anybody else to fall silent first.
///
/// A session ends when nothing has moved on it for [`IDLE_TIMEOUT`], which is the
/// same window the Go visitor gets from a 30-second read deadline on the visitor
/// connection, and the next datagram opens a fresh one. The bound socket is never
/// dropped, so from the outside a session ending is invisible.
async fn run_udp(
    visitor: Visitor,
    connector: Connector,
    codec: Codec,
    run_id: String,
    target: String,
    addr: String,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let local = tokio::net::UdpSocket::bind(&addr).await.map_err(|err| {
        Error::config(format!(
            "visitor {}: cannot bind {addr}: {err}",
            visitor.name
        ))
    })?;
    logging::info(format!(
        "visitor {} is listening on {addr} (udp), forwarding to proxy {target}",
        visitor.name
    ));

    let mut datagram = vec![0u8; crate::client::udp::MAX_DATAGRAM];
    loop {
        // Whoever's datagram this is, it opens a session if there is not one
        // already — the Go dispatcher does not look at the sender either.
        let Ok((read, user)) = local.recv_from(&mut datagram).await else {
            return Ok(());
        };
        let first = datagram[..read].to_vec();

        if let Err(err) = udp_session(
            &connector,
            codec,
            &run_id,
            &target,
            &visitor.secret_key,
            visitor.use_encryption,
            first,
            &local,
            user,
            &visitor.name,
            &traffic,
        )
        .await
        {
            logging::warn(format!("visitor {}: {err}", visitor.name));
        }
    }
}

/// One `sudp` session: the handshake, then the relay until it goes quiet.
///
/// `first_datagram` is what opened it and is written first; everything after that
/// comes off the same socket in [`relay`], tagged with the address it arrived
/// from.
#[allow(clippy::too_many_arguments)]
async fn udp_session(
    connector: &Connector,
    codec: Codec,
    run_id: &str,
    target_proxy: &str,
    secret_key: &str,
    use_encryption: bool,
    first_datagram: Vec<u8>,
    local: &tokio::net::UdpSocket,
    user: std::net::SocketAddr,
    visitor_name: &str,
    traffic: &Traffic,
) -> Result<()> {
    let mut conn = connector.connect().await?;
    codec.write_handshake_prefix(&mut conn).await?;

    let timestamp = chrono::Utc::now().timestamp();
    codec
        .write(
            &mut conn,
            &Message::NewVisitorConn(Box::new(NewVisitorConn {
                run_id: run_id.to_string(),
                proxy_name: target_proxy.to_string(),
                sign_key: auth_key(secret_key, timestamp),
                timestamp,
                // Carried from the config rather than hard-coded: the server
                // wraps its side of the session on this bit, and a mismatch
                // would be a stream of bytes neither end could read.
                use_encryption,
                use_compression: false,
            })),
        )
        .await?;

    let resp = match tokio::time::timeout(HANDSHAKE_TIMEOUT, codec.read(&mut conn)).await {
        Ok(Ok(Message::NewVisitorConnResp(resp))) => *resp,
        Ok(Ok(other)) => {
            return Err(Error::protocol(format!(
                "expected NewVisitorConnResp, got {}",
                super::control::describe(&other)
            )))
        }
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            return Err(Error::protocol(format!(
                "no NewVisitorConnResp within {HANDSHAKE_TIMEOUT:?}"
            )))
        }
    };
    if !resp.error.is_empty() {
        return Err(Error::Rejected(resp.error));
    }

    let first = Message::UdpPacket(Box::new(crate::msg::UdpPacket {
        content: first_datagram.clone().into(),
        local_addr: None,
        remote_addr: Some(crate::client::udp::from_socket_addr(&user)),
    }));
    traffic.record(first_datagram.len() as u64, 0);

    // Keyed on the proxy's secret key rather than the token, and only when the
    // visitor asked for it — the same primitive as a work connection, with a
    // different secret.
    if use_encryption {
        let conn = CryptoStream::encrypted(conn, secret_key.as_bytes());
        relay(conn, codec, local, first, visitor_name, traffic).await
    } else {
        relay(conn, codec, local, first, visitor_name, traffic).await
    }
}

/// The relay half of a session, over whichever wrapping the handshake agreed on.
///
/// Datagrams are read from the local socket one at a time rather than raced
/// against each other, which is the only reason the two directions can share one
/// `datagram` buffer. The cost is that a user cannot send while an answer is being
/// written — UDP has no ordering to preserve anyway, and the write is to a socket
/// that was already accepting datagrams.
async fn relay<S>(
    conn: S,
    codec: Codec,
    local: &tokio::net::UdpSocket,
    first: Message,
    visitor_name: &str,
    traffic: &Traffic,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(conn);
    codec.write(&mut writer, &first).await?;

    let mut datagram = vec![0u8; crate::client::udp::MAX_DATAGRAM];
    // Restarted whenever anything moves in either direction, so a session lives as
    // long as the conversation does — the same rule as the Go visitor's 30-second
    // read deadline on the visitor connection.
    let mut deadline = tokio::time::Instant::now() + crate::client::udp::IDLE_TIMEOUT;
    loop {
        tokio::select! {
            read = codec.read(&mut reader) => {
                match read? {
                    Message::UdpPacket(packet) => {
                        // The answer is addressed to whoever asked. That address is
                        // the whole reason one session can carry several users'
                        // conversations without mixing them up.
                        match packet.remote_addr.as_ref().and_then(crate::client::udp::to_socket_addr) {
                            Some(peer) => {
                                local
                                    .send_to(packet.content.as_slice(), peer)
                                    .await
                                    .map_err(|err| {
                                        Error::other(format!("answer the local user: {err}"))
                                    })?;
                                traffic.record(0, packet.content.len() as u64);
                            }
                            None => logging::debug(format!(
                                "visitor {visitor_name}: a udp answer arrived without an \
                                 address; dropping it"
                            )),
                        }
                        deadline = tokio::time::Instant::now() + crate::client::udp::IDLE_TIMEOUT;
                    }
                    // The proxy pings to keep a quiet session alive; answer it.
                    Message::Ping(_) => {
                        codec
                            .write(&mut writer, &Message::Pong(Box::default()))
                            .await?;
                    }
                    other => logging::debug(format!(
                        "visitor {visitor_name}: ignoring {} on a sudp connection",
                        super::control::describe(&other)
                    )),
                }
            }

            // Anyone may speak on an open session, whether or not they are the one
            // who opened it: this is exactly what the Go visitor does with its send
            // channel, and refusing the second user would be a bug rather than a
            // limitation.
            read = local.recv_from(&mut datagram) => {
                let Ok((read, from)) = read else { continue };
                let content = datagram[..read].to_vec();
                traffic.record(content.len() as u64, 0);
                codec
                    .write(
                        &mut writer,
                        &Message::UdpPacket(Box::new(crate::msg::UdpPacket {
                            content: content.into(),
                            local_addr: None,
                            remote_addr: Some(crate::client::udp::from_socket_addr(&from)),
                        })),
                    )
                    .await?;
                deadline = tokio::time::Instant::now() + crate::client::udp::IDLE_TIMEOUT;
            }

            // Nothing in either direction: the conversation is over and the next
            // datagram will open a new session.
            _ = tokio::time::sleep_until(deadline) => {
                logging::debug(format!("visitor {visitor_name}: sudp session went quiet"));
                return Ok(());
            }
        }
    }
}

/// Opens one visitor connection and bridges it to `user_conn`.
#[allow(clippy::too_many_arguments)]
async fn serve_one(
    user_conn: tokio::net::TcpStream,
    connector: Connector,
    codec: Codec,
    run_id: String,
    target_proxy: String,
    secret_key: String,
    use_encryption: bool,
    visitor_name: &str,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let mut conn = connector.connect().await?;
    codec.write_handshake_prefix(&mut conn).await?;

    // The signature is over the *proxy's* secret key, not the auth token: the
    // server compares it against what the `stcp` proxy registered.
    let timestamp = chrono::Utc::now().timestamp();
    codec
        .write(
            &mut conn,
            &Message::NewVisitorConn(Box::new(NewVisitorConn {
                run_id,
                proxy_name: target_proxy,
                sign_key: auth_key(&secret_key, timestamp),
                timestamp,
                use_encryption,
                use_compression: false,
            })),
        )
        .await?;

    let resp = match tokio::time::timeout(HANDSHAKE_TIMEOUT, codec.read(&mut conn)).await {
        Ok(Ok(Message::NewVisitorConnResp(resp))) => *resp,
        Ok(Ok(other)) => {
            return Err(Error::protocol(format!(
                "expected NewVisitorConnResp, got {}",
                super::control::describe(&other)
            )))
        }
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            return Err(Error::protocol(format!(
                "no NewVisitorConnResp within {HANDSHAKE_TIMEOUT:?}"
            )))
        }
    };
    if !resp.error.is_empty() {
        return Err(Error::Rejected(resp.error));
    }

    // From here it is a plain tunnel, keyed on the secret key when the visitor
    // asked for encryption — the same primitive as a work connection, with a
    // different secret.
    let result = if use_encryption {
        let visitor_conn = CryptoStream::encrypted(conn, secret_key.as_bytes());
        bridge::join(visitor_conn, user_conn, visitor_name).await
    } else {
        bridge::join(conn, user_conn, visitor_name).await
    };

    let (to_local, to_work) = result?;
    traffic.record(to_local, to_work);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VisitorKind;
    use crate::crypto::Secret;

    fn config(name: &str, kind: VisitorKind, bind_port: i32) -> VisitorConfig {
        VisitorConfig {
            name: name.into(),
            enabled: None,
            kind,
            server_name: "db".into(),
            server_user: String::new(),
            bind_addr: "127.0.0.1".into(),
            bind_port,
            secret_key: Secret::new("s3cret"),
            transport: None,
            nat_traversal: None,
            plugin: None,
        }
    }

    #[test]
    fn stcp_and_sudp_visitors_are_both_recognized() {
        let stcp = Visitor::from_config(&config("v", VisitorKind::Stcp {}, 6000)).unwrap();
        assert_eq!(stcp.kind, "stcp");
        assert_eq!(stcp.bind_port, 6000);
        assert_eq!(stcp.server_name, "db");
        // The key is un-masked here: it is the secret the handshake is signed
        // with, so masking it would be a bug rather than a precaution.
        assert_eq!(stcp.secret_key, "s3cret");

        // The same config in every respect but the transport.
        let sudp = Visitor::from_config(&config("v", VisitorKind::Sudp {}, 6000)).unwrap();
        assert_eq!(sudp.kind, "sudp");
        assert_eq!(sudp.secret_key, stcp.secret_key);
    }

    #[test]
    fn xtcp_is_skipped_rather_than_mistaken_for_something_it_can_run() {
        assert!(Visitor::from_config(&config(
            "v",
            VisitorKind::Xtcp {
                protocol: String::new(),
                keep_tunnel_open: false,
                max_retries_an_hour: 0,
                min_retry_interval: 0,
                fallback_to: String::new(),
                fallback_timeout_ms: 0,
            },
            6000
        ))
        .is_none());
    }

    #[test]
    fn a_negative_bind_port_becomes_zero_so_it_is_reported_rather_than_wrapped() {
        // `bindPort = -1` is the Go spelling of "visitor connections only". A
        // plain cast would make it 65535 and bind a port nobody asked for.
        let visitor = Visitor::from_config(&config("v", VisitorKind::Stcp {}, -1)).unwrap();
        assert_eq!(visitor.bind_port, 0);
    }

    #[test]
    fn the_start_allowlist_applies_to_visitors() {
        let visitor = Visitor::from_config(&config("v", VisitorKind::Stcp {}, 6000)).unwrap();

        let mut enabled = config("v", VisitorKind::Stcp {}, 6000);
        assert!(visitor.is_enabled(&enabled, &[]));
        assert!(visitor.is_enabled(&enabled, &["v".to_string()]));
        assert!(!visitor.is_enabled(&enabled, &["other".to_string()]));

        enabled.enabled = Some(false);
        assert!(!visitor.is_enabled(&enabled, &[]));
    }
}
