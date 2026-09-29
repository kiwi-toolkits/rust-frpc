//! The client's login handshake.
//!
//! One function, but it is the single most compatibility-sensitive piece of the
//! whole client: everything after it depends on getting the framing, the crypto
//! and the signature exactly right, and a mistake here looks like a server that
//! simply hangs up.
//!
//! The exchange, in order:
//!
//! 1. dial the control port;
//! 2. write the v2 magic, if v2 (nothing for v1);
//! 3. send `Login` **in the clear** — the crypto layer only starts afterwards;
//! 4. read `LoginResp`, also in the clear;
//! 5. wrap the connection in the AES-CFB stream, keyed on the token, and return
//!    it. From here on every byte is encrypted, and the IV occupies the first 16
//!    bytes the client writes.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::config::{ClientConfig, ProxyTransport};
use crate::crypto::auth_key;
use crate::error::{Error, Result};
use crate::logging;
use crate::msg::{Login, LoginResp, Message};
use crate::proto::{transport, Codec, Connector, CryptoStream, LogicalConn, WireProtocol};

use super::session::Session;

/// frp's `auth.additionalScopes` values.
pub const SCOPE_HEARTBEATS: &str = "HeartBeats";
pub const SCOPE_NEW_WORK_CONNS: &str = "NewWorkConns";

/// How long to wait for the server's reply to a `Login`.
///
/// The Go client uses 10 seconds (`client/control_session.go:171`), and the
/// server's own read deadline is the same, so a slow reply means something is
/// wrong rather than merely slow.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Dials, logs in, and returns the established session.
///
/// `previous_run_id` is sent in `Login.run_id` so the server can recognize a
/// reconnecting client and hand over the proxies the old session owned.
pub async fn login(config: &ClientConfig, previous_run_id: &str) -> Result<Session> {
    let (codec, connector) = connect(config).await?;
    login_over(codec, connector, config, previous_run_id).await
}

/// Builds the codec and the connector a session will use.
///
/// Split out because the control loop re-establishes a session on the same
/// connector after a reconnect, and only the login exchange needs repeating.
pub async fn connect(config: &ClientConfig) -> Result<(Codec, Connector)> {
    let common = &config.common;
    let transport_cfg = common.transport.clone().unwrap_or_default();

    let codec = Codec::new(WireProtocol::parse(&transport_cfg.wire_protocol));

    let addr = transport::join_host_port(&common.server_addr, common.server_port);
    logging::info(format!(
        "start frpc, server: {addr}, protocol: {}, wire: {}, tcpMux: {}",
        transport_cfg.protocol,
        codec.protocol().as_str(),
        transport_cfg.tcp_mux.unwrap_or(true),
    ));

    let dial_timeout = Duration::from_secs(transport_cfg.dial_server_timeout.max(1) as u64);
    // A negative `dialServerKeepalive` means "no probes".
    let keepalive = match transport_cfg.dial_server_keepalive {
        value if value > 0 => Some(Duration::from_secs(value as u64)),
        _ => None,
    };
    let mux_keepalive = Duration::from_secs(transport_cfg.tcp_mux_keepalive_interval.max(1) as u64);

    let connector = Connector::open(
        &addr,
        dial_timeout,
        &transport_cfg.connect_server_local_ip,
        keepalive,
        transport_cfg.tcp_mux.unwrap_or(true),
        mux_keepalive,
    )
    .await?;

    Ok((codec, connector))
}

/// Runs the login exchange on an existing connector.
pub async fn login_over(
    codec: Codec,
    connector: Connector,
    config: &ClientConfig,
    previous_run_id: &str,
) -> Result<Session> {
    let common = &config.common;
    let login = build_login(config, previous_run_id);

    // The login itself is cleartext: the crypto layer starts once it is answered.
    let mut stream = connector.connect().await?;
    codec.write_handshake_prefix(&mut stream).await?;
    codec
        .write(&mut stream, &Message::Login(Box::new(login)))
        .await?;
    stream.flush().await?;

    let resp = match tokio::time::timeout(LOGIN_TIMEOUT, codec.read(&mut stream)).await {
        Err(_) => {
            return Err(Error::Login(format!(
                "no LoginResp within {LOGIN_TIMEOUT:?}"
            )))
        }
        Ok(Ok(Message::LoginResp(resp))) => *resp,
        Ok(Ok(other)) => {
            return Err(Error::Login(format!(
                "expected LoginResp, got {}",
                message_kind(&other)
            )))
        }
        Ok(Err(err)) => return Err(err),
    };

    if !resp.error.is_empty() {
        return Err(Error::Login(resp.error));
    }

    logging::info(format!(
        "login to server success, server version: {}, run id: {}",
        resp.version, resp.run_id
    ));

    // Everything after the login is encrypted, which is unconditional — not
    // something `useEncryption` turns on.
    let token = common
        .auth
        .as_ref()
        .map(|auth| auth.token.as_str())
        .unwrap_or_default();
    let stream: CryptoStream<LogicalConn> = CryptoStream::encrypted(stream, token.as_bytes());

    Ok(Session::new(codec, stream, connector, resp, config.clone()))
}

/// Builds the `Login` message, including the token signature.
fn build_login(config: &ClientConfig, previous_run_id: &str) -> Login {
    let common = &config.common;
    let auth = common.auth.clone().unwrap_or_default();
    let timestamp = chrono::Utc::now().timestamp();

    Login {
        version: crate::version::full(),
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        user: common.user.clone(),
        privilege_key: auth_key(&auth.token, timestamp),
        timestamp,
        run_id: previous_run_id.to_string(),
        client_id: common.client_id.clone(),
        metas: common.metadatas.clone(),
        client_spec: Default::default(),
        pool_count: common
            .transport
            .as_ref()
            .map(|transport| transport.pool_count)
            .unwrap_or(1),
    }
}

/// The machine's hostname, as Go's `os.Hostname` reports it.
///
/// Best effort: an environment without a hostname reports an empty string, which
/// the server only ever logs.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

/// A message's name, for error text.
fn message_kind(message: &Message) -> &'static str {
    match message {
        Message::Login(_) => "Login",
        Message::LoginResp(_) => "LoginResp",
        Message::NewProxy(_) => "NewProxy",
        Message::NewProxyResp(_) => "NewProxyResp",
        Message::CloseProxy(_) => "CloseProxy",
        Message::NewWorkConn(_) => "NewWorkConn",
        Message::ReqWorkConn(_) => "ReqWorkConn",
        Message::StartWorkConn(_) => "StartWorkConn",
        Message::NewVisitorConn(_) => "NewVisitorConn",
        Message::NewVisitorConnResp(_) => "NewVisitorConnResp",
        Message::Ping(_) => "Ping",
        Message::Pong(_) => "Pong",
        Message::UdpPacket(_) => "UDPPacket",
        Message::NatHoleVisitor(_) => "NatHoleVisitor",
        Message::NatHoleClient(_) => "NatHoleClient",
        Message::NatHoleResp(_) => "NatHoleResp",
        Message::NatHoleSid(_) => "NatHoleSid",
        Message::NatHoleReport(_) => "NatHoleReport",
    }
}

/// Whether a proxy asked for encryption, for the work-connection wrapper.
pub fn proxy_uses_encryption(transport: Option<&ProxyTransport>) -> bool {
    transport.is_some_and(|transport| transport.use_encryption)
}

/// Whether the token signature belongs in a heartbeat, per
/// `auth.additionalScopes`.
pub fn signs_heartbeats(config: &ClientConfig) -> bool {
    config
        .common
        .auth
        .as_ref()
        .is_some_and(|auth| auth.additional_scopes.iter().any(|s| s == SCOPE_HEARTBEATS))
}

/// Whether the token signature belongs in a `NewWorkConn`.
pub fn signs_new_work_conns(config: &ClientConfig) -> bool {
    config.common.auth.as_ref().is_some_and(|auth| {
        auth.additional_scopes
            .iter()
            .any(|s| s == SCOPE_NEW_WORK_CONNS)
    })
}

/// The control connection's token.
pub fn token_of(config: &ClientConfig) -> String {
    config
        .common
        .auth
        .as_ref()
        .map(|auth| auth.token.clone())
        .unwrap_or_default()
}

/// Kept for the reconnect path: a `LoginResp` with a fresh run id.
pub fn run_id_of(resp: &LoginResp) -> &str {
    &resp.run_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthClientConfig;

    fn config_with(auth: AuthClientConfig) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.common.auth = Some(auth);
        config.complete();
        config
    }

    #[test]
    fn the_login_carries_the_token_signature_and_run_id() {
        let config = config_with(AuthClientConfig {
            method: "token".into(),
            token: "12345678".into(),
            ..Default::default()
        });
        let login = build_login(&config, "previous");

        assert_eq!(login.run_id, "previous");
        assert_eq!(login.privilege_key, auth_key("12345678", login.timestamp));
        assert_eq!(login.version, crate::version::full());
        assert!(login.timestamp > 1_700_000_000);
        assert_eq!(login.pool_count, 1);
    }

    #[test]
    fn an_empty_token_still_produces_a_signature() {
        // The server compares it against its own token, so an unset client token
        // has to produce the signature of the empty string rather than nothing.
        let config = config_with(AuthClientConfig::default());
        let login = build_login(&config, "");
        assert_eq!(login.privilege_key, auth_key("", login.timestamp));
        assert_eq!(login.privilege_key.len(), 32);
    }

    #[test]
    fn the_user_prefix_is_sent_verbatim() {
        let mut config = config_with(AuthClientConfig::default());
        config.common.user = "alice".into();
        let login = build_login(&config, "");
        assert_eq!(login.user, "alice");
    }

    #[test]
    fn scopes_decide_whether_heartbeats_and_work_conns_are_signed() {
        let unsigned = config_with(AuthClientConfig::default());
        assert!(!signs_heartbeats(&unsigned));
        assert!(!signs_new_work_conns(&unsigned));

        let signed = config_with(AuthClientConfig {
            additional_scopes: vec![SCOPE_HEARTBEATS.into(), SCOPE_NEW_WORK_CONNS.into()],
            ..Default::default()
        });
        assert!(signs_heartbeats(&signed));
        assert!(signs_new_work_conns(&signed));
    }

    #[test]
    fn a_client_spec_is_always_present_on_the_wire() {
        // The Go struct is a value, so `client_spec` is emitted even when empty;
        // `msg.rs` reproduces that, and this pins that the login uses it.
        let config = config_with(AuthClientConfig::default());
        let login = build_login(&config, "");
        let json = String::from_utf8(login_json(&login)).unwrap();
        assert!(json.contains("\"client_spec\":{}"), "{json}");
    }

    fn login_json(login: &Login) -> Vec<u8> {
        crate::msg::go_json::to_vec(login).unwrap()
    }
}
