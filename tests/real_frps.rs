//! End-to-end test against a real `frps`.
//!
//! Ignored by default, because it needs a frps binary and a config. Run it with:
//!
//! ```text
//! RUN_REAL_FRPS_TESTS=1 \
//! FRPS_BIN=/path/to/frps \
//! FRPS_CONFIG=tests/fixtures/frps-integration.toml \
//! cargo test --test real_frps -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` rather than an early return on purpose: an early return reports
//! as a pass, so a CI job that forgets the environment variables would look
//! green while testing nothing.
//!
//! This is the test that actually proves the compatibility claim. Unit tests can
//! show that the framing and the crypto round-trip against themselves; only a
//! real server shows that the bytes, the signature and the `[type][length]`
//! prefix are the ones `frps` expects.

#![allow(clippy::field_reassign_with_default)]

use std::process::Stdio;
use std::time::Duration;

use rust_frpc::client::ControlEvent;
use rust_frpc::config::{self, AuthClientConfig, ProxyConfig, ProxyKind, Qos};
use rust_frpc::msg::{Message, Ping};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

/// Must match tests/fixtures/frps-integration.toml.
const CONTROL_PORT: u16 = 17_000;
/// Must match tests/fixtures/frps-integration-nomux.toml.
const CONTROL_PORT_NO_MUX: u16 = 17_100;
/// The public port the multiplexed round-trip test asks `frps` to open.
/// Deliberately away from the control ports and from anything a developer is
/// likely to be using.
const REMOTE_PORT: u16 = 17_200;
/// The same for the non-multiplexed round trip.
const REMOTE_PORT_NO_MUX: u16 = 17_201;
/// The UDP port `frps` is asked to publish.
const REMOTE_PORT_UDP: u16 = 17_210;
/// The local port the stcp *visitor* binds, which is where a user connects.
const VISITOR_PORT: u16 = 17_220;
/// The same for a `sudp` visitor, which binds a UDP port.
const VISITOR_PORT_UDP: u16 = 17_221;
/// The secret key shared between the `stcp` proxy and its visitor.
const STCP_SECRET: &str = "rust-frpc-stcp-secret";
/// The admin API port the client is asked to listen on.
const ADMIN_PORT: u16 = 17_300;
/// The vhost port the `http` round-trip test asks `frps` to open.
const VHOST_PORT: u16 = 17_510;
/// The `HTTP CONNECT` port `frps` serves every `tcpmux` proxy on.
const MUX_PORT: u16 = 17_511;
/// Must match `subDomainHost` in tests/fixtures/frps-integration.toml, because a
/// subdomain is only served as `<subdomain>.<subDomainHost>`.
const SUBDOMAIN_HOST: &str = "rust-frpc.test";
const TOKEN: &str = "rust-frpc-integration";

fn frps() -> Option<(String, String)> {
    std::env::var_os("RUN_REAL_FRPS_TESTS")?;
    let bin = std::env::var("FRPS_BIN").expect("FRPS_BIN is required");
    let config = std::env::var("FRPS_CONFIG")
        .expect("FRPS_CONFIG is required; use tests/fixtures/frps-integration.toml");
    Some((bin, config))
}

/// The same, but for the fixture that disables multiplexing.
///
/// `transport.tcpMux` is a server-side decision — frps wraps whatever it accepts
/// in yamux when its own setting is on — so a client that disagrees cannot be
/// tested against the multiplexed fixture.
fn frps_without_mux() -> Option<(String, String)> {
    let (bin, config) = frps()?;
    let no_mux = config.replace("frps-integration.toml", "frps-integration-nomux.toml");
    Some((bin, no_mux))
}

async fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "frps did not start listening on {port} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Starts the fixture `frps`.
///
/// `kill_on_drop` so a panicking assertion cannot leave the server holding the
/// control port for every later test — including the next one in CI.
fn start(bin: &str, config: &str) -> Child {
    Command::new(bin)
        .arg("-c")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start frps")
}

fn client_config() -> config::ClientConfig {
    let mut config = config::ClientConfig::default();
    config.common.server_addr = "127.0.0.1".into();
    config.common.server_port = CONTROL_PORT;
    config.common.auth = Some(AuthClientConfig {
        method: "token".into(),
        token: TOKEN.into(),
        ..Default::default()
    });
    config.complete();
    config
}

/// The same config, with multiplexing off, so both transports get exercised
/// against the real server.
fn client_config_without_mux() -> config::ClientConfig {
    let mut config = client_config();
    if let Some(transport) = config.common.transport.as_mut() {
        transport.tcp_mux = Some(false);
    }
    config.common.server_port = CONTROL_PORT_NO_MUX;
    config
}

/// A config carrying one `tcp` proxy that points at `local_port`.
fn client_config_with_proxy(remote_port: u16, local_port: u16) -> config::ClientConfig {
    let mut config = client_config();
    add_proxy(&mut config, remote_port, local_port);
    config
}

/// Adds the `tcp` proxy to an already-completed config.
fn add_proxy(config: &mut config::ClientConfig, remote_port: u16, local_port: u16) {
    config.proxies.push(ProxyConfig::new(
        "echo",
        None,
        ProxyKind::Tcp { remote_port },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
}

/// A config with one `sudp` proxy pointing at `local_port`.
fn client_config_with_sudp_proxy(local_port: u16) -> config::ClientConfig {
    let mut config = client_config();
    config.proxies.push(ProxyConfig::new(
        "secret-echo-udp",
        None,
        ProxyKind::Sudp {
            secret_key: rust_frpc::crypto::Secret::new(STCP_SECRET),
            allow_users: vec!["*".into()],
        },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
    config
}

/// The same visitor, as a `sudp` one.
fn client_config_with_sudp_visitor(server_name: &str, bind_port: u16) -> config::ClientConfig {
    let mut config = client_config_with_visitor(server_name);
    config.visitors[0].kind = config::VisitorKind::Sudp {};
    config.visitors[0].bind_port = i32::from(bind_port);
    config.complete();
    config
}

/// An `http` proxy whose local service is a small HTTP responder.
///
/// The client's part in an `http` proxy is bytes to `localIP:localPort`, so the
/// local side has to speak HTTP for the round trip to mean anything.
fn client_config_with_http_proxy(local_port: u16, subdomain: &str) -> config::ClientConfig {
    let mut config = client_config();
    config.proxies.push(ProxyConfig::new(
        "web",
        None,
        ProxyKind::Http {
            custom_domains: Vec::new(),
            subdomain: subdomain.into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_password: String::new(),
            host_header_rewrite: String::new(),
            request_headers: None,
            response_headers: None,
            route_by_http_user: String::new(),
        },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
    config
}

/// A `tcpmux` proxy over `HTTP CONNECT`.
fn client_config_with_tcpmux_proxy(local_port: u16, domain: &str) -> config::ClientConfig {
    let mut config = client_config();
    config.proxies.push(ProxyConfig::new(
        "mux",
        None,
        ProxyKind::Tcpmux {
            custom_domains: vec![domain.into()],
            subdomain: String::new(),
            http_user: String::new(),
            http_password: String::new(),
            route_by_http_user: String::new(),
            multiplexer: "httpconnect".into(),
        },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
    config
}

/// A `udp` proxy whose datagrams go to a local UDP service.
fn client_config_with_udp_proxy(remote_port: u16, local_port: u16) -> config::ClientConfig {
    let mut config = client_config();
    config.proxies.push(ProxyConfig::new(
        "echo-udp",
        None,
        ProxyKind::Udp { remote_port },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
    config
}

/// An `stcp` proxy, and nothing else: no public port, no visitor.
fn client_config_with_stcp_proxy(local_port: u16) -> config::ClientConfig {
    let mut config = client_config();
    config.proxies.push(ProxyConfig::new(
        "secret-echo",
        None,
        ProxyKind::Stcp {
            secret_key: rust_frpc::crypto::Secret::new(STCP_SECRET),
            allow_users: vec!["*".into()],
        },
        Qos {
            local_ip: "127.0.0.1".into(),
            local_port,
            ..Qos::default()
        },
        None,
    ));
    config.complete();
    config
}

/// The other half: a client with no proxy, only a visitor for `secret-echo`.
fn client_config_with_visitor(server_name: &str) -> config::ClientConfig {
    let mut config = client_config();
    config.visitors.push(config::VisitorConfig {
        name: "secret-visitor".into(),
        enabled: None,
        kind: config::VisitorKind::Stcp {},
        server_name: server_name.into(),
        server_user: String::new(),
        bind_addr: "127.0.0.1".into(),
        bind_port: i32::from(VISITOR_PORT),
        secret_key: rust_frpc::crypto::Secret::new(STCP_SECRET),
        transport: None,
        nat_traversal: None,
        plugin: None,
    });
    config.complete();
    config
}

/// Starts a local UDP echo service, returning its port.
///
/// The reply is prefixed so the assertion can tell the service's answer from the
/// datagram it was sent, which is what makes "the reply reached the right user"
/// testable rather than merely "some bytes came back".
async fn start_udp_echo() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..read]);
            if socket.send_to(&reply, peer).await.is_err() {
                return;
            }
        }
    });
    port
}

/// Starts a local TCP echo service, returning its port.
async fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if socket.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Starts a minimal local HTTP service, returning its port.
///
/// It answers any request with `http-ok:<path>`, so the assertion can read the
/// path the request actually carried — which is what shows the server forwarded
/// the user's own request rather than a fixed probe.
async fn start_http_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let Ok(read) = socket.read(&mut buf).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let body = format!("http-ok:{path}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    port
}

/// Requests `path` until the server routes it to the proxy instead of answering
/// its own 404 page.
///
/// `frps`'s vhost listener is up from startup, so a connect says nothing about
/// whether a proxy has been registered on it; only the response does.
async fn http_get_until_ok(host: String, path: &str) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match http_get(host.clone(), path).await {
            Ok(body) => return body,
            Err(status) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "frps never routed {host} to the proxy: {status}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Makes one HTTP/1.1 request through `frps`'s vhost port, addressed by `Host`.
///
/// `Err` carries the status line when the server answered with its own page
/// rather than forwarding to the proxy.
async fn http_get(host: String, path: &str) -> std::result::Result<String, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", VHOST_PORT)).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("frps should answer the http request within ten seconds")
        .expect("read the http response");

    let response = String::from_utf8_lossy(&response).to_string();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .expect("an HTTP response has a header block");
    if head.starts_with("HTTP/1.1 200") {
        Ok(body.to_string())
    } else {
        Err(head.lines().next().unwrap_or_default().to_string())
    }
}

/// Waits until `frps` has published the proxy on `port`.
///
/// Registration is asynchronous — the client sends `NewProxy` and the listener
/// appears some time later — so connecting immediately would be a race.
async fn wait_for_published(port: u16, timeout: Duration) -> TcpStream {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(socket) = TcpStream::connect(("127.0.0.1", port)).await {
            return socket;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "frps never published a proxy on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Drives the client in the background and returns a handle to observe and stop
/// it.
///
/// The real top-level entry point rather than a hand-rolled session, because the
/// point of this test is the whole path: login, registration, the work-connection
/// pool and the bridge.
fn spawn_client(config: config::ClientConfig) -> ClientHandle {
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(16);
    let task = tokio::spawn(async move {
        rust_frpc::client::run_client(config, shutdown_rx, Some(events_tx)).await
    });
    ClientHandle {
        shutdown,
        task,
        events: events_rx,
    }
}

struct ClientHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<rust_frpc::Result<()>>,
    events: tokio::sync::mpsc::Receiver<ControlEvent>,
}

impl ClientHandle {
    /// Waits for a bridged connection to finish and reports its byte counts.
    async fn next_connection(&mut self, timeout: Duration) -> (u64, u64) {
        let event = tokio::time::timeout(timeout, self.events.recv())
            .await
            .expect("the client should report a finished connection")
            .expect("the event channel should stay open");
        match event {
            ControlEvent::ConnectionClosed {
                bytes_to_local,
                bytes_to_work,
                ..
            } => (bytes_to_local, bytes_to_work),
        }
    }

    /// Asks the client to stop and waits for it, which is also what proves the
    /// shutdown path deregisters rather than hanging.
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        match tokio::time::timeout(Duration::from_secs(5), self.task).await {
            Ok(Ok(Ok(()))) => {}
            other => panic!("the client did not stop cleanly: {other:?}"),
        }
    }

    /// Waits for the client to stop on its own, without being asked.
    async fn expect_stopped(self, timeout: Duration) {
        match tokio::time::timeout(timeout, self.task).await {
            Ok(Ok(Ok(()))) => {}
            other => panic!("the client did not stop on its own: {other:?}"),
        }
    }
}

/// The core claim: a stock `frps` accepts this client's login.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_accepts_the_login() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let config = client_config();
    let session = rust_frpc::client::login(&config, "")
        .await
        .expect("login should succeed");

    // `frps` reports its own version and assigns a run id. Both being present
    // means the LoginResp was parsed and the crypto layer was installed on the
    // right byte boundary.
    assert!(!session.server_version().is_empty());
    assert_eq!(session.run_id().len(), 16, "run id should be 16 hex chars");
    assert!(session.run_id().chars().all(|c| c.is_ascii_hexdigit()));

    session.close().await.ok();
    let _ = frps.kill().await;
}

/// A wrong token must be rejected by the server rather than quietly accepted,
/// which is what proves the signature in `Login` is actually being checked.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_rejects_a_wrong_token() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let mut config = client_config();
    config.common.auth = Some(AuthClientConfig {
        method: "token".into(),
        token: "definitely-not-the-token".into(),
        ..Default::default()
    });

    let err = rust_frpc::client::login(&config, "")
        .await
        .expect_err("a wrong token must not log in");
    assert!(err.to_string().contains("token"), "unexpected error: {err}");

    let _ = frps.kill().await;
}

/// A heartbeat sent on the encrypted control connection must be answered. This
/// is the first thing after login that exercises the crypto layer in both
/// directions.
///
/// The server talks first: it asks for work connections as soon as a session is
/// established, so the reply to a `Ping` is not necessarily the next message.
/// Those requests are consumed here rather than answered, because this test is
/// about the heartbeat, not about the pool.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_answers_a_ping() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let config = client_config();
    let mut session = rust_frpc::client::login(&config, "")
        .await
        .expect("login should succeed");

    session
        .send(&Message::Ping(Box::new(Ping {
            timestamp: chrono::Utc::now().timestamp(),
            privilege_key: String::new(),
        })))
        .await
        .expect("send Ping");

    let mut saw_work_conn_request = false;
    let pong = loop {
        let message = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("the server should reply within five seconds")
            .expect("read reply");
        match message {
            // The server replenishing its work-conn pool. Expected, and proof in
            // its own right that the control connection works both ways.
            Message::ReqWorkConn(_) => saw_work_conn_request = true,
            Message::Pong(pong) => break pong,
            other => panic!("expected Pong, got {other:?}"),
        }
    };

    assert!(
        pong.error.is_empty(),
        "the server rejected the heartbeat: {}",
        pong.error
    );
    assert!(
        saw_work_conn_request,
        "frps should have asked for a work connection"
    );

    session.close().await.ok();
    let _ = frps.kill().await;
}

/// An `http` proxy: a request to `frps`'s vhost port, routed by `Host`, is
/// forwarded to the local HTTP service.
///
/// The client's whole part in an `http` proxy is bytes to `localIP:localPort` —
/// domains, subdomains and locations are all the server's business. What this
/// proves is that it registers the right type and then bridges what it is handed,
/// which is the part that can be wrong on this side.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_routes_an_http_request_by_host() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let web_port = start_http_echo().await;
    let client = spawn_client(client_config_with_http_proxy(web_port, "web"));
    wait_for_port(VHOST_PORT, Duration::from_secs(10)).await;

    // `frps`'s vhost listener comes up at startup, so the connect above only
    // proves the server is listening. What proves the *proxy* is routed is a
    // request that reaches the local service rather than the 404 page, so this
    // retries until it does.
    let host = format!("web.{SUBDOMAIN_HOST}");
    let body = http_get_until_ok(host.clone(), "/").await;
    assert_eq!(body, "http-ok:/");

    // The path is matched by the server and forwarded, so a second request proves
    // the bytes that came out are the ones the user sent rather than a fixed probe.
    let body = http_get(host, "/status")
        .await
        .expect("the proxy should still be routed");
    assert_eq!(body, "http-ok:/status");

    client.stop().await;
    let _ = frps.kill().await;
}

/// A `tcpmux` proxy: `frps` speaks `HTTP CONNECT` on its multiplexer port and the
/// tunnel that comes out is a plain byte pipe.
///
/// A `CONNECT` names the target in the request line and carries no `Host`, so
/// `frps` routes it by the authority — which is why the request is absolute-form.
/// The acknowledgement is `HTTP/1.1 200 OK` followed by at least a
/// `Content-Length: 0`; the tunnel starts after the blank line.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_a_tcpmux_connect() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let client = spawn_client(client_config_with_tcpmux_proxy(echo_port, "mux"));

    // The muxer port is listening from the moment `frps` starts — it is one
    // listener shared by every `tcpmux` proxy — so a successful connect says
    // nothing about registration. An unregistered authority gets a 404, so the
    // response is what this loop waits on.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match connect_muxer("mux").await {
            Ok(stream) => break stream,
            Err(response) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the muxer never accepted a CONNECT for mux: {response:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };

    // Past the CONNECT response it is the ordinary TCP bridge to the local
    // service, which is the only part of a `tcpmux` proxy this client owns.
    stream.write_all(b"through the muxer").await.unwrap();
    stream.flush().await.unwrap();
    let mut got = [0u8; 17];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
        .await
        .expect("the echoed bytes should come back within ten seconds")
        .expect("read the echo");
    assert_eq!(&got, b"through the muxer");

    client.stop().await;
    let _ = frps.kill().await;
}

/// Sends `CONNECT <domain>:<port>` to `frps`'s multiplexer port and reads back
/// its response headers.
///
/// The response is read up to the blank line rather than a fixed number of bytes:
/// the muxer writes its own status line and at least a `Content-Length`, and
/// counting bytes would bake in one server's exact framing. Whatever comes after
/// the blank line is the tunnel.
///
/// `Ok` carries the stream once the status was 200; `Err` carries the status line
/// otherwise, which for an unregistered authority is a 404.
async fn connect_muxer(domain: &str) -> std::result::Result<TcpStream, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", MUX_PORT))
        .await
        .map_err(|e| e.to_string())?;
    // Absolute-form with an explicit port: both are what a real proxy client
    // sends, and `frps` matches the authority against the domain it registered.
    let request = format!("CONNECT {domain}:{MUX_PORT} HTTP/1.1\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .map_err(|_| "no response to CONNECT".to_string())?
            .map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("the muxer closed without a response".to_string());
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 4096 {
            return Err("the CONNECT response headers do not end".to_string());
        }
    }

    let head = String::from_utf8_lossy(&head).to_string();
    if head.starts_with("HTTP/1.1 200") {
        Ok(stream)
    } else {
        Err(head.lines().next().unwrap_or_default().to_string())
    }
}

/// The same login over the non-multiplexed transport, so a regression in either
/// path is caught.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_accepts_the_login_without_mux() {
    let Some((bin, config_path)) = frps_without_mux() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT_NO_MUX, Duration::from_secs(10)).await;

    let config = client_config_without_mux();
    let session = rust_frpc::client::login(&config, "")
        .await
        .expect("login without tcpMux should succeed");
    assert!(!session.connector().is_muxed());
    assert_eq!(session.run_id().len(), 16);

    session.close().await.ok();
    let _ = frps.kill().await;
}

/// Reconnecting with the previous run id must be accepted: that is what lets a
/// server hand the proxies back to a client that just restarted, and it is the
/// path the reconnect loop depends on.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_accepts_a_reconnect_with_the_previous_run_id() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let config = client_config();
    let first = rust_frpc::client::login(&config, "")
        .await
        .expect("first login");
    let run_id = first.run_id().to_string();
    first.close().await.ok();

    let second = rust_frpc::client::login(&config, &run_id)
        .await
        .expect("reconnect should be accepted");
    assert_eq!(second.run_id(), run_id, "the server should keep the run id");

    second.close().await.ok();
    let _ = frps.kill().await;
}

/// The end-to-end proof: a `tcp` proxy registered by this client carries real
/// bytes from the port `frps` published through to a local service and back.
///
/// Everything the client does has to be right for this to pass — the login, the
/// `NewProxy` registration, the work-connection pool, the yamux stream and the
/// bridge — which is why it is the one test that would catch a mistake anywhere
/// in the stack.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_a_tcp_round_trip() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let mut client = spawn_client(client_config_with_proxy(REMOTE_PORT, echo_port));

    let mut user = wait_for_published(REMOTE_PORT, Duration::from_secs(10)).await;

    // A payload larger than one read is worth testing: it is the case where a
    // stream that mishandles flow control stalls instead of corrupting.
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    user.write_all(&payload).await.expect("write to the proxy");
    user.flush().await.expect("flush");

    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), user.read_exact(&mut got))
        .await
        .expect("the echo should come back within ten seconds")
        .expect("read the echo");
    assert_eq!(got, payload, "the bytes came back changed");

    // Closing the user side must end the bridge, which is what makes the
    // byte counts observable.
    drop(user);
    let (to_local, to_work) = client.next_connection(Duration::from_secs(10)).await;
    assert_eq!(
        to_local,
        payload.len() as u64,
        "bytes reaching the local end"
    );
    assert_eq!(to_work, payload.len() as u64, "bytes leaving the local end");

    client.stop().await;
    let _ = frps.kill().await;
}

/// The same round trip with multiplexing off, so the whole path is exercised
/// once with yamux in the middle and once without.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_a_tcp_round_trip_without_mux() {
    let Some((bin, config_path)) = frps_without_mux() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT_NO_MUX, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let mut config = client_config();
    add_proxy(&mut config, REMOTE_PORT_NO_MUX, echo_port);
    config.common.server_port = CONTROL_PORT_NO_MUX;
    config.common.transport.as_mut().unwrap().tcp_mux = Some(false);
    let client = spawn_client(config);

    let mut user = wait_for_published(REMOTE_PORT_NO_MUX, Duration::from_secs(10)).await;
    user.write_all(b"hello over a plain socket").await.unwrap();
    user.flush().await.unwrap();

    let mut got = [0u8; 25];
    tokio::time::timeout(Duration::from_secs(10), user.read_exact(&mut got))
        .await
        .expect("the echo should come back within ten seconds")
        .expect("read the echo");
    assert_eq!(&got, b"hello over a plain socket");

    client.stop().await;
    let _ = frps.kill().await;
}

/// Sends a datagram to `target` and waits for an answer, retrying until one
/// comes back.
///
/// A UDP port has no `connect` to wait on, so the only way to know the proxy is
/// registered is to get an answer. Each attempt uses a **fresh socket**: on
/// Windows a datagram to a closed port draws an ICMP unreachable, which the
/// socket surfaces as a reset on the next read and which then repeats on every
/// later read of that socket — so a retry loop that reuses one spins instead of
/// waiting.
async fn udp_round_trip(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    const ATTEMPTS: u32 = 40;
    for attempt in 0..ATTEMPTS {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Best effort: Windows reports the ICMP unreachable here, and the read
        // below is what actually decides.
        let _ = socket.send_to(payload, target).await;

        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((read, _))) => {
                buf.truncate(read);
                return buf;
            }
            // Refused, timed out, or reset: try again on a new socket.
            _ if attempt + 1 < ATTEMPTS => continue,
            other => panic!("frps never carried a udp datagram to the local service: {other:?}"),
        }
    }
    unreachable!("the loop returns or panics")
}

/// A `udp` proxy: a datagram out through the port `frps` published, an answer
/// back from a local UDP service.
///
/// The reply is prefixed by the local service, so this asserts the datagram was
/// really forwarded and answered rather than merely echoed back by something in
/// the middle.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_a_udp_round_trip() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_udp_echo().await;
    let client = spawn_client(client_config_with_udp_proxy(REMOTE_PORT_UDP, echo_port));

    let target: std::net::SocketAddr = format!("127.0.0.1:{REMOTE_PORT_UDP}").parse().unwrap();
    let reply = udp_round_trip(target, b"hello over udp").await;
    // The local service's prefix, then the payload it was sent.
    assert_eq!(reply, b"echo:hello over udp");

    // A second, larger datagram on the same mapping, so this is not one lucky
    // packet and the per-user socket is being reused rather than re-opened.
    let payload: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
    let reply = udp_round_trip(target, &payload).await;
    assert_eq!(&reply[..5], b"echo:");
    assert_eq!(&reply[5..], &payload[..]);

    client.stop().await;
    let _ = frps.kill().await;
}

/// Two UDP users at once: each one's answer must go back to *it*.
///
/// This is the failure mode a UDP forwarder actually has — the per-user socket
/// table exists precisely to prevent it — and it is invisible to a single-user
/// test.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_keeps_udp_users_apart() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_udp_echo().await;
    let client = spawn_client(client_config_with_udp_proxy(REMOTE_PORT_UDP, echo_port));

    let target: std::net::SocketAddr = format!("127.0.0.1:{REMOTE_PORT_UDP}").parse().unwrap();
    // The first call doubles as the wait for registration; only then is the
    // two-in-flight assertion about the server rather than about a race.
    let first = udp_round_trip(target, b"warm up").await;
    assert_eq!(first, b"echo:warm up");

    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Both send before either reads, so the two datagrams are in flight together
    // and the server has to have kept them apart.
    a.send_to(b"from-a", target).await.unwrap();
    b.send_to(b"from-b", target).await.unwrap();

    let mut buf = [0u8; 512];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), a.recv_from(&mut buf))
        .await
        .expect("the first user should be answered within ten seconds")
        .expect("read from the first user's socket");
    assert_eq!(&buf[..read], b"echo:from-a");

    let (read, _) = tokio::time::timeout(Duration::from_secs(10), b.recv_from(&mut buf))
        .await
        .expect("the second user should be answered within ten seconds")
        .expect("read from the second user's socket");
    assert_eq!(&buf[..read], b"echo:from-b");

    client.stop().await;
    let _ = frps.kill().await;
}

/// An `stcp` tunnel, end to end: two clients, no public port.
///
/// This is the direction a `tcp` proxy never exercises. One client registers an
/// `stcp` proxy — which publishes nothing — and the other runs a *visitor* that
/// binds a local port and names that proxy. The visitor's handshake is what has to
/// be right, and it is signed with the proxy's secret key rather than the auth
/// token, with the per-connection crypto keyed on that same secret. Two clients
/// and two keys in one test is the point.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_an_stcp_round_trip_through_a_visitor() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;

    // The proxy side. It has to be registered before the visitor's handshake can
    // name it, and the integration test cannot see the server's registry, so the
    // visitor's own retry is what waits — see below.
    let _proxy_client = spawn_client(client_config_with_stcp_proxy(echo_port));

    // The visitor side.
    let _visitor_client = spawn_client(client_config_with_visitor("secret-echo"));

    // The visitor binds its port once the visitor task starts, which is
    // immediately, but the *proxy* has to be registered first or the handshake is
    // refused. Each attempt therefore dials afresh, exactly as the admin API's
    // status polling does not — this is a real race in the protocol, and retrying
    // is how the Go client's own tests deal with it too.
    let mut last_error = String::new();
    let mut connected = None;
    let payload = b"through the secret tunnel";
    for _ in 0..40 {
        match TcpStream::connect(("127.0.0.1", VISITOR_PORT)).await {
            Ok(mut socket) => {
                if socket.write_all(payload).await.is_err() {
                    last_error = "writing to the visitor failed".into();
                    continue;
                }
                if socket.flush().await.is_err() {
                    last_error = "flushing to the visitor failed".into();
                    continue;
                }
                let mut got = vec![0u8; payload.len()];
                match tokio::time::timeout(Duration::from_millis(500), socket.read_exact(&mut got))
                    .await
                {
                    Ok(Ok(_)) => {
                        connected = Some(got);
                        break;
                    }
                    Ok(Err(err)) => last_error = format!("read failed: {err}"),
                    Err(_) => last_error = "the echo did not come back in time".into(),
                }
            }
            Err(err) => last_error = format!("connecting to the visitor failed: {err}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let got = connected.unwrap_or_else(|| {
        panic!("the stcp tunnel never carried a round trip; last attempt: {last_error}")
    });
    assert_eq!(&got[..], payload);

    _proxy_client.stop().await;
    _visitor_client.stop().await;
    let _ = frps.kill().await;
}

/// A visitor whose secret key does not match must be refused by the server.
///
/// The signature is over the *proxy's* key, so a visitor that signs with anything
/// else has to be turned away — which is the whole reason the key exists.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn a_visitor_with_the_wrong_secret_key_is_refused() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let _proxy_client = spawn_client(client_config_with_stcp_proxy(echo_port));

    // Give the proxy time to register, so a refusal cannot be "not found yet".
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut config = client_config_with_visitor("secret-echo");
    config.visitors[0].secret_key = rust_frpc::crypto::Secret::new("not-the-secret");
    let _visitor_client = spawn_client(config);

    // The visitor still binds its port — it has no way to know the key is wrong
    // until it tries — so the refusal shows up as the handshake failing, which
    // the visitor logs and which leaves the user connection unanswered.
    let mut socket = wait_for_published(VISITOR_PORT, Duration::from_secs(10)).await;
    socket.write_all(b"should not get through").await.unwrap();
    socket.flush().await.unwrap();

    // Either the connection is closed, or nothing comes back: both mean the
    // handshake was refused. Anything else means a wrong key was accepted.
    let mut buf = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(read)) => panic!(
            "a visitor with the wrong secret key was answered with {:?}",
            String::from_utf8_lossy(&buf[..read])
        ),
        Ok(Err(_)) => {}
    }

    _proxy_client.stop().await;
    _visitor_client.stop().await;
    let _ = frps.kill().await;
}

/// A `sudp` tunnel: the same shape as the `stcp` one, over a UDP socket.
///
/// The proxy end is the *same code* as a `udp` proxy — the server appends an
/// internal listener to the `sudp` proxy's listener list and then asks for a work
/// connection exactly as a public `udp` proxy does — so what this really tests is
/// the visitor half, where a UDP session has to be tied to one user and no
/// connection exists to end it.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_carries_a_sudp_round_trip_through_a_visitor() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_udp_echo().await;
    let _proxy_client = spawn_client(client_config_with_sudp_proxy(echo_port));
    let _visitor_client = spawn_client(client_config_with_sudp_visitor(
        "secret-echo-udp",
        VISITOR_PORT_UDP,
    ));

    // As with `stcp`, the visitor binds immediately but the proxy has to have
    // registered before the handshake can succeed, so each attempt is a fresh
    // datagram and the reply is the signal.
    let target: std::net::SocketAddr = format!("127.0.0.1:{VISITOR_PORT_UDP}").parse().unwrap();
    let reply = udp_round_trip(target, b"through the secret udp tunnel").await;
    assert_eq!(reply, b"echo:through the secret udp tunnel");

    // A second datagram, so this is not one lucky packet: a `sudp` session is
    // rebuilt per user, and a larger payload exercises the relay rather than the
    // opening handshake.
    let payload: Vec<u8> = (0..900u32).map(|i| (i % 251) as u8).collect();
    let reply = udp_round_trip(target, &payload).await;
    assert_eq!(&reply[..5], b"echo:");
    assert_eq!(&reply[5..], &payload[..]);

    _proxy_client.stop().await;
    _visitor_client.stop().await;
    let _ = frps.kill().await;
}

/// Two `sudp` users, one after the other.
///
/// The visitor serialises sessions — one user at a time — so the second user is
/// served once the first has gone quiet. What this pins is that the answer reaches
/// the user who asked: a relay that answered the wrong socket would show up here
/// as a reply arriving at the wrong port, which is the UDP equivalent of mixing
/// two users up.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_keeps_sudp_users_apart() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_udp_echo().await;
    let _proxy_client = spawn_client(client_config_with_sudp_proxy(echo_port));
    let _visitor_client = spawn_client(client_config_with_sudp_visitor(
        "secret-echo-udp",
        VISITOR_PORT_UDP,
    ));

    let target: std::net::SocketAddr = format!("127.0.0.1:{VISITOR_PORT_UDP}").parse().unwrap();
    // The first exchange doubles as the wait for the proxy to register.
    assert_eq!(
        udp_round_trip(target, b"warm up").await,
        b"echo:warm up".to_vec()
    );

    // Two users, one after the other: the visitor serialises sessions, so the
    // second user's turn comes only once the first has gone quiet — which is
    // exactly the behaviour worth pinning, because a relay that answered the
    // wrong socket would show up here as a reply arriving at the wrong port.
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(b"from-a", target).await.unwrap();
    let mut buf = [0u8; 512];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), a.recv_from(&mut buf))
        .await
        .expect("the first user should be answered within ten seconds")
        .expect("read from the first user's socket");
    assert_eq!(&buf[..read], b"echo:from-a");

    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    b.send_to(b"from-b", target).await.unwrap();
    let (read, from) = tokio::time::timeout(Duration::from_secs(10), b.recv_from(&mut buf))
        .await
        .expect("the second user should be answered within ten seconds")
        .expect("read from the second user's socket");
    assert_eq!(&buf[..read], b"echo:from-b");
    assert_eq!(
        from, target,
        "the answer should come from the visitor's port"
    );

    _proxy_client.stop().await;
    _visitor_client.stop().await;
    let _ = frps.kill().await;
}

/// A proxy whose local service is not listening must fail that one connection
/// rather than take the client down with it.
///
/// This is the failure a real deployment hits most often — the service behind the
/// tunnel restarted — so the client surviving it is a correctness property, not a
/// nicety.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn real_frps_survives_a_dead_local_service() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    // Bind and drop, so the port is almost certainly closed.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let client = spawn_client(client_config_with_proxy(REMOTE_PORT, dead_port));
    let _user = wait_for_published(REMOTE_PORT, Duration::from_secs(10)).await;

    // The registration still stands, so a second proxy on the same session would
    // still be reachable; the cheapest proof is that the client is still alive
    // and shuts down cleanly afterwards.
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.stop().await;
    let _ = frps.kill().await;
}

/// The admin API: a real `frpc status` against a running client, over the wire.
///
/// The unit tests cover the response shapes; this covers the part they cannot —
/// that the two halves of the HTTP implementation, written separately here and in
/// the CLI, actually agree.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn the_admin_api_reports_status_over_http() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let mut config = client_config_with_proxy(REMOTE_PORT, echo_port);
    config.common.web_server = Some(config::WebServerConfig {
        addr: "127.0.0.1".into(),
        port: ADMIN_PORT,
        ..Default::default()
    });

    let mut client = spawn_client(config);
    // Held rather than dropped: the probe connection is the one the round trip
    // below uses, so the only connection the bridge ever sees is the real one and
    // the byte counts at the end mean what they say.
    let mut user = wait_for_published(REMOTE_PORT, Duration::from_secs(10)).await;

    let admin = rust_frpc::client::AdminClient::new(
        "127.0.0.1",
        ADMIN_PORT,
        "",
        "",
        Some(Duration::from_secs(5)),
    );
    let reply = admin.status().await.expect("the admin API should answer");
    assert_eq!(reply.status, 200, "{}", reply.body);

    // The proxy the client registered, by the name in the config, with the
    // address the server published.
    assert!(reply.body.contains("\"name\":\"echo\""), "{}", reply.body);
    assert!(
        reply.body.contains("\"status\":\"running\""),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains(&format!("127.0.0.1:{REMOTE_PORT}")),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains(&format!("127.0.0.1:{echo_port}")),
        "{}",
        reply.body
    );

    // `/metrics` too, since it is served by the same server and the same state.
    let metrics = admin
        .request_for_test("GET", "/metrics", None)
        .await
        .expect("metrics should answer");
    assert_eq!(metrics.status, 200);
    assert!(
        metrics.body.contains("frpc_connected 1\n"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("frpc_proxies 1\n"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("frpc_proxies_running 1\n"),
        "{}",
        metrics.body
    );

    // A round trip on the connection the probe opened, so the status poll is
    // shown not to have disturbed the bridge.
    user.write_all(b"still alive").await.unwrap();
    user.flush().await.unwrap();
    let mut got = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(10), user.read_exact(&mut got))
        .await
        .expect("the echo should come back")
        .expect("read the echo");
    assert_eq!(&got, b"still alive");
    drop(user);

    let (to_local, to_work) = client.next_connection(Duration::from_secs(10)).await;
    assert_eq!(to_local, 11);
    assert_eq!(to_work, 11);

    // The counters the admin API reports are the ones the bridge actually moved.
    let metrics = admin
        .request_for_test("GET", "/metrics", None)
        .await
        .expect("metrics should answer");
    assert!(
        metrics.body.contains("frpc_connections_closed 1\n"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("frpc_bytes_to_local 11\n"),
        "{}",
        metrics.body
    );

    client.stop().await;
    let _ = frps.kill().await;
}

/// `stop` through the admin API must end the client the same way a signal does.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn the_admin_api_can_stop_the_client() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let mut config = client_config_with_proxy(REMOTE_PORT, echo_port);
    config.common.web_server = Some(config::WebServerConfig {
        addr: "127.0.0.1".into(),
        port: ADMIN_PORT,
        ..Default::default()
    });

    let client = spawn_client(config);
    // Held rather than dropped, so the proxy is up while `stop` is called
    // instead of being deregistered out from under the request.
    let _user = wait_for_published(REMOTE_PORT, Duration::from_secs(10)).await;

    let admin = rust_frpc::client::AdminClient::new(
        "127.0.0.1",
        ADMIN_PORT,
        "",
        "",
        Some(Duration::from_secs(5)),
    );
    let reply = admin.stop().await.expect("the admin API should answer");
    assert_eq!(reply.status, 200);

    // The client task should finish on its own, without the test's own shutdown.
    client.expect_stopped(Duration::from_secs(5)).await;
    let _ = frps.kill().await;
}

/// Authentication on the admin API, in both directions: refused without it,
/// accepted with the right credentials.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN and FRPS_CONFIG"]
async fn the_admin_api_checks_credentials() {
    let Some((bin, config_path)) = frps() else {
        return;
    };
    let mut frps = start(&bin, &config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let echo_port = start_echo().await;
    let mut config = client_config_with_proxy(REMOTE_PORT, echo_port);
    config.common.web_server = Some(config::WebServerConfig {
        addr: "127.0.0.1".into(),
        port: ADMIN_PORT,
        user: "admin".into(),
        password: "hunter2".into(),
        ..Default::default()
    });

    let client = spawn_client(config);
    // Held, so the probe connection is the one the credential checks are about.
    let _user = wait_for_published(REMOTE_PORT, Duration::from_secs(10)).await;

    let anonymous = rust_frpc::client::AdminClient::new(
        "127.0.0.1",
        ADMIN_PORT,
        "",
        "",
        Some(Duration::from_secs(5)),
    );
    let reply = anonymous.status().await.expect("the API should answer");
    assert_eq!(reply.status, 401);

    let authenticated = rust_frpc::client::AdminClient::new(
        "127.0.0.1",
        ADMIN_PORT,
        "admin",
        "hunter2",
        Some(Duration::from_secs(5)),
    );
    let reply = authenticated.status().await.expect("the API should answer");
    assert_eq!(reply.status, 200, "{}", reply.body);

    // `/healthz` is outside the auth check, which is what a supervisor polls.
    let health = anonymous
        .request_for_test("GET", "/healthz", None)
        .await
        .expect("healthz should answer");
    assert_eq!(health.status, 200);

    client.stop().await;
    let _ = frps.kill().await;
}
