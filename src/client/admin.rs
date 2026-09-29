//! The admin API: a small HTTP server on `webServer`.
//!
//! Same paths and same response shapes as the Go client, because the things that
//! talk to it are not just people — `frpc status`, `frpc reload`, `frpc stop` and
//! the dashboard all speak this protocol, and a client that answers differently
//! is a client those tools cannot manage.
//!
//! Written on `tokio` directly rather than on an HTTP framework. The surface is
//! eight routes with no middleware to speak of, and a framework would cost more
//! binary size than the routing it replaces — which matters for a crate whose
//! whole reason for existing is the size of the process.
//!
//! What is here: `/healthz`, `/api/status`, `/api/config` (GET/PUT),
//! `/api/proxy/{name}/config`, `/api/reload`, `/api/stop`, `/metrics`.
//! What is not yet: `/api/visitor/{name}/config`, `/api/store/*`, and the static
//! dashboard assets.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::config::{ClientConfig, WebServerConfig};
use crate::error::Result;
use crate::logging;
use crate::msg::go_json;
use crate::naming;

use super::control::{StatusSnapshot, Traffic};

/// How long a request may take to arrive.
///
/// The admin API is called by a local `frpc status`, not by the internet, so a
/// connection that has not sent a request by then is a scanner rather than a
/// client.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The largest request body accepted, matching what `frpc` will ever be sent.
const MAX_BODY: usize = 4 * 1024 * 1024;

/// How long to wait after a failed authentication, matching the Go middleware's
/// 200ms, which exists to make brute-forcing the admin password tedious.
const AUTH_FAIL_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

/// Something the admin API needs the client to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCommand {
    /// Re-read the config file and apply it.
    Reload { strict: bool },
    /// Stop the client.
    Stop,
}

/// The running admin server.
pub struct AdminServer {
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl AdminServer {
    /// The address actually bound, which is what to report in the log.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the server. The caller does not wait: the listener closes as soon as
    /// the task notices, and nothing depends on it being gone.
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// Starts the admin server if `webServer.port` is set.
///
/// Returns `None` when the admin API is off, which is the default — the Go client
/// only starts it for a non-zero port, and so does this one.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    config: Arc<ClientConfig>,
    web: &WebServerConfig,
    status: watch::Receiver<StatusSnapshot>,
    traffic: Arc<Traffic>,
    commands: mpsc::Sender<AdminCommand>,
    config_path: std::path::PathBuf,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<AdminServer>> {
    if web.port == 0 {
        return Ok(None);
    }

    let addr = crate::proto::transport::join_host_port(&web.addr, web.port);
    let listener = TcpListener::bind(&addr).await.map_err(|err| {
        crate::error::Error::other(format!("admin server cannot bind {addr}: {err}"))
    })?;
    let bound = listener
        .local_addr()
        .map_err(|err| crate::error::Error::other(format!("admin server address: {err}")))?;

    let server = Admin {
        config,
        user: web.user.clone(),
        password: web.password.clone(),
        status,
        traffic,
        commands,
        config_path,
    };

    let (stop_tx, mut stop_rx) = watch::channel(false);
    let mut shutdown = shutdown;
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => return,
                _ = shutdown.changed() => return,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((socket, peer)) => {
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Err(err) = serve(server, socket).await {
                                    logging::debug(format!("admin: {peer}: {err}"));
                                }
                            });
                        }
                        Err(err) => {
                            logging::warn(format!("admin: accept failed: {err}"));
                            return;
                        }
                    }
                }
            }
        }
    });

    Ok(Some(AdminServer {
        addr: bound,
        shutdown: stop_tx,
        task,
    }))
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

/// Everything a request handler needs.
#[derive(Clone)]
struct Admin {
    config: Arc<ClientConfig>,
    user: String,
    password: String,
    status: watch::Receiver<StatusSnapshot>,
    /// Read live rather than through the snapshot, so a counter is never a second
    /// behind the connection it counts.
    traffic: Arc<Traffic>,
    commands: mpsc::Sender<AdminCommand>,
    config_path: std::path::PathBuf,
}

/// A parsed request, reduced to what the routes look at.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl Request {
    /// The query parameter's value, un-escaped the way Go's `url.Values` does.
    fn query_value(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == key).then(|| percent_decode(value))
        })
    }
}

/// Reads one request from the connection.
///
/// Deliberately minimal: `Content-Length` only, no chunked bodies, no keep-alive.
/// The clients that matter — `frpc status`, `curl`, a browser — all send a
/// length, and every one of them opens a fresh connection anyway.
async fn read_request(stream: &mut BufReader<TcpStream>) -> std::io::Result<Request> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers are too large",
            ));
        }
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-request",
            ));
        }
        head.push(byte[0]);
    }

    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target.to_string(), String::new()),
    };

    let mut authorization = None;
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
    }
    if content_length > MAX_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body is too large",
        ));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await?;
    }

    Ok(Request {
        method,
        path,
        query,
        authorization,
        body,
    })
}

/// Handles one connection: exactly one request, one response, close.
async fn serve(admin: Admin, socket: TcpStream) -> std::io::Result<()> {
    let mut stream = BufReader::new(socket);
    let request = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    let response = tokio::time::timeout(REQUEST_TIMEOUT, admin.route(request))
        .await
        .unwrap_or_else(|_| Response::text(500, "the request timed out"));

    let mut stream = stream.into_inner();
    stream.write_all(&response.encode()).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// A response, ready to write.
struct Response {
    status: u16,
    content_type: &'static str,
    /// One extra header, for the `WWW-Authenticate` challenge.
    extra_header: Option<(&'static str, &'static str)>,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json",
            extra_header: None,
            body,
        }
    }

    fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            extra_header: None,
            body: body.into().into_bytes(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            extra_header: None,
            body: Vec::new(),
        }
    }

    /// The error envelope Go's `MakeHTTPHandlerFunc` writes.
    fn error(status: u16, message: impl Into<String>) -> Self {
        #[derive(serde::Serialize)]
        struct GeneralResponse {
            code: u16,
            msg: String,
        }
        let body = go_json::to_vec(&GeneralResponse {
            code: status,
            msg: message.into(),
        })
        .unwrap_or_default();
        Self::json(status, body)
    }

    fn encode(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            reason(self.status),
            self.content_type,
            self.body.len(),
        );
        if let Some((name, value)) = self.extra_header {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");

        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

impl Admin {
    async fn route(&self, request: Request) -> Response {
        // `/healthz` is deliberately outside the auth check, matching the Go
        // router: it is what a supervisor polls, and it reveals nothing.
        if request.path == "/healthz" {
            return Response::empty(200);
        }

        if !self.authorized(&request) {
            tokio::time::sleep(AUTH_FAIL_DELAY).await;
            let mut response = Response::text(401, "Unauthorized\n");
            // The header Go's middleware sets, so a browser prompts. Set after
            // `text` because that is a plain-text body either way.
            response.extra_header = Some(("WWW-Authenticate", "Basic realm=\"Restricted\""));
            return response;
        }

        match (&request.method[..], request.path.as_str()) {
            ("GET", "/api/status") => self.status_response(),
            ("GET", "/metrics") => self.metrics_response(),
            ("GET", "/api/config") => self.get_config(),
            ("PUT", "/api/config") => self.put_config(request.body).await,
            ("GET", "/api/reload") => {
                let strict = request.query_value("strictConfig").as_deref() == Some("true");
                self.send(AdminCommand::Reload { strict }).await;
                Response::empty(200)
            }
            ("POST", "/api/stop") => {
                self.send(AdminCommand::Stop).await;
                Response::empty(200)
            }
            (_, "/api/status")
            | (_, "/metrics")
            | (_, "/api/config")
            | (_, "/api/reload")
            | (_, "/api/stop") => Response::error(405, "method not allowed"),
            ("GET", path) if path.starts_with("/api/proxy/") => self.proxy_config(path),
            _ => Response::error(404, "not found"),
        }
    }

    /// Whether the request carries acceptable credentials.
    ///
    /// With no user and no password configured the API is open, which is the Go
    /// behaviour: it is bound to localhost by default and the alternative would
    /// be to lock the operator out of their own client.
    fn authorized(&self, request: &Request) -> bool {
        if self.user.is_empty() && self.password.is_empty() {
            return true;
        }
        let Some(header) = request.authorization.as_deref() else {
            return false;
        };
        let Some(encoded) = header.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64_decode(encoded.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = decoded.split_once(':') else {
            return false;
        };
        // Compared in constant time, as the Go middleware does, so the reply
        // cannot be used to discover the password a byte at a time.
        constant_time_eq(user.as_bytes(), self.user.as_bytes())
            && constant_time_eq(password.as_bytes(), self.password.as_bytes())
    }

    async fn send(&self, command: AdminCommand) {
        // A full queue means the client is already busy stopping or reloading;
        // dropping the request is the right answer, not blocking the caller.
        let _ = self.commands.try_send(command);
    }

    fn snapshot(&self) -> StatusSnapshot {
        self.status.borrow().clone()
    }

    /// `GET /api/status`, shaped exactly like the Go client's.
    fn status_response(&self) -> Response {
        let snapshot = self.snapshot();
        let mut by_type: std::collections::BTreeMap<&str, Vec<ProxyStatusOut>> =
            std::collections::BTreeMap::new();

        for proxy in &snapshot.proxies {
            let local_addr = snapshot
                .local_addrs
                .get(&proxy.name)
                .cloned()
                .unwrap_or_default();
            let plugin = snapshot
                .plugins
                .get(&proxy.name)
                .cloned()
                .unwrap_or_default();
            // Only when the proxy is running does the address mean anything, and
            // a `tcp`/`udp` port is the server's, so it is absolute rather than
            // host-relative the way frps reports it.
            let remote_addr = if proxy.phase == super::control::ProxyPhase::Running {
                if matches!(proxy.proxy_type, "tcp" | "udp") {
                    format!("{}{}", self.config.common.server_addr, proxy.remote_addr)
                } else {
                    proxy.remote_addr.clone()
                }
            } else {
                String::new()
            };

            by_type
                .entry(proxy.proxy_type)
                .or_default()
                .push(ProxyStatusOut {
                    name: proxy.name.clone(),
                    proxy_type: proxy.proxy_type.to_string(),
                    status: proxy.phase.as_str().to_string(),
                    err: proxy.error.clone(),
                    local_addr,
                    plugin,
                    remote_addr,
                });
        }

        for proxies in by_type.values_mut() {
            proxies.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Response::json(200, go_json::to_vec(&by_type).unwrap_or_default())
    }

    /// `GET /metrics`: plain text, no Prometheus client library.
    fn metrics_response(&self) -> Response {
        let snapshot = self.snapshot();
        let mut out = String::new();

        let mut running = 0;
        for proxy in &snapshot.proxies {
            if proxy.phase == super::control::ProxyPhase::Running {
                running += 1;
            }
        }

        out.push_str("# TYPE frpc_connected gauge\n");
        out.push_str(&format!(
            "frpc_connected {}\n",
            u8::from(snapshot.connected)
        ));
        out.push_str("# TYPE frpc_proxies gauge\n");
        out.push_str(&format!("frpc_proxies {}\n", snapshot.proxies.len()));
        out.push_str("# TYPE frpc_proxies_running gauge\n");
        out.push_str(&format!("frpc_proxies_running {running}\n"));
        out.push_str("# TYPE frpc_connections_closed counter\n");
        out.push_str(&format!(
            "frpc_connections_closed {}\n",
            self.traffic.closed()
        ));
        out.push_str("# TYPE frpc_bytes_to_local counter\n");
        out.push_str(&format!(
            "frpc_bytes_to_local {}\n",
            self.traffic.to_local()
        ));
        out.push_str("# TYPE frpc_bytes_to_work counter\n");
        out.push_str(&format!("frpc_bytes_to_work {}\n", self.traffic.to_work()));

        for proxy in &snapshot.proxies {
            out.push_str(&format!(
                "frpc_proxy_running{{proxy=\"{}\",type=\"{}\"}} {}\n",
                proxy.name,
                proxy.proxy_type,
                u8::from(proxy.phase == super::control::ProxyPhase::Running)
            ));
        }

        Response::text(200, out)
    }

    /// `GET /api/config`: the file as it is on disk, byte for byte.
    fn get_config(&self) -> Response {
        match std::fs::read_to_string(&self.config_path) {
            Ok(content) => {
                let mut response = Response::text(200, content);
                response.content_type = "text/plain; charset=utf-8";
                response
            }
            Err(err) => Response::error(
                500,
                format!("read config file {}: {err}", self.config_path.display()),
            ),
        }
    }

    /// `PUT /api/config`: write the file, then reload.
    ///
    /// Written through a temporary file and renamed, so a crash mid-write leaves
    /// the previous config intact rather than a truncated one.
    async fn put_config(&self, body: Vec<u8>) -> Response {
        if body.is_empty() {
            return Response::error(400, "body can't be empty");
        }
        let text = match String::from_utf8(body) {
            Ok(text) => text,
            Err(_) => return Response::error(400, "the config must be UTF-8 text"),
        };

        // Validated before it is written: a config the client cannot load would
        // otherwise be persisted and then fail on the next restart.
        if let Err(message) = crate::config::load_from_str(&text) {
            return Response::error(400, format!("invalid config: {message}"));
        }

        if let Err(err) = write_atomically(&self.config_path, text.as_bytes()) {
            return Response::error(
                500,
                format!("write config file {}: {err}", self.config_path.display()),
            );
        }

        self.send(AdminCommand::Reload { strict: true }).await;
        Response::empty(200)
    }

    /// `GET /api/proxy/{name}/config`: the proxy as the client has it.
    fn proxy_config(&self, path: &str) -> Response {
        let Some(rest) = path.strip_prefix("/api/proxy/") else {
            return Response::error(404, "not found");
        };
        let Some(name) = rest.strip_suffix("/config") else {
            return Response::error(404, "not found");
        };
        let name = percent_decode(name);

        // The configured name, not the wire name: this is the one the file uses.
        if !self.config.proxies.iter().any(|proxy| proxy.name == name) {
            return Response::error(404, format!("proxy {name:?} not found"));
        }

        let snapshot = self.snapshot();
        let Some(status) = snapshot.proxies.iter().find(|proxy| proxy.name == name) else {
            return Response::error(404, format!("proxy {name:?} not found"));
        };

        #[derive(serde::Serialize)]
        struct ProxyStatusOut {
            name: String,
            #[serde(rename = "type")]
            proxy_type: String,
            status: String,
            err: String,
            local_addr: String,
            plugin: String,
            remote_addr: String,
        }

        let local_addr = snapshot.local_addrs.get(&name).cloned().unwrap_or_default();
        let plugin = snapshot.plugins.get(&name).cloned().unwrap_or_default();
        let remote_addr = if status.phase == super::control::ProxyPhase::Running {
            if matches!(status.proxy_type, "tcp" | "udp") {
                format!("{}{}", self.config.common.server_addr, status.remote_addr)
            } else {
                status.remote_addr.clone()
            }
        } else {
            String::new()
        };

        Response::json(
            200,
            go_json::to_vec(&ProxyStatusOut {
                name: status.name.clone(),
                proxy_type: status.proxy_type.to_string(),
                status: status.phase.as_str().to_string(),
                err: status.error.clone(),
                local_addr,
                plugin,
                remote_addr,
            })
            .unwrap_or_default(),
        )
    }
}

/// The shape `GET /api/status` returns per proxy: Go's `model.ProxyStatusResp`.
#[derive(serde::Serialize)]
struct ProxyStatusOut {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    err: String,
    local_addr: String,
    plugin: String,
    remote_addr: String,
}

/// Writes a file through a temporary and a rename, so a reader never sees a
/// half-written file.
fn write_atomically(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)
}

/// Minimal percent-decoding, for the escapes a proxy name can contain.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Base64, for the `Authorization: Basic` header.
///
/// Hand-rolled because this is the only base64 in the crate and a dependency for
/// one header would not pay for itself.
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;

    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        let value = ALPHABET.iter().position(|&c| c == byte).ok_or(())? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

/// A comparison whose timing does not depend on where the first difference is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The name a proxy is filed under in the admin API: without the user prefix,
/// which is the name the config file uses.
pub fn admin_name(config: &ClientConfig, wire_name: &str) -> String {
    naming::strip_user_prefix(&config.common.user, wire_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::control::{ProxyPhase, ProxyStatus};
    use std::collections::BTreeMap;

    fn admin() -> Admin {
        let (_, status) = watch::channel(StatusSnapshot::default());
        let (commands, _) = mpsc::channel(4);
        Admin {
            config: Arc::new(ClientConfig::default()),
            user: String::new(),
            password: String::new(),
            status,
            traffic: Arc::new(Traffic::default()),
            commands,
            config_path: std::path::PathBuf::from("frpc.toml"),
        }
    }

    fn snapshot() -> StatusSnapshot {
        let mut local_addrs = BTreeMap::new();
        local_addrs.insert("ssh".to_string(), "127.0.0.1:22".to_string());
        let mut plugins = BTreeMap::new();
        plugins.insert("sock".to_string(), "unix_domain_socket".to_string());

        StatusSnapshot {
            proxies: vec![
                ProxyStatus {
                    name: "ssh".into(),
                    proxy_type: "tcp",
                    phase: ProxyPhase::Running,
                    remote_addr: ":6000".into(),
                    error: String::new(),
                },
                ProxyStatus {
                    name: "sock".into(),
                    proxy_type: "tcp",
                    phase: ProxyPhase::StartError,
                    remote_addr: String::new(),
                    error: "port already used".into(),
                },
            ],
            local_addrs,
            plugins,
            connected: true,
        }
    }

    fn body(response: &Response) -> String {
        String::from_utf8_lossy(&response.body).into_owned()
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("!!!!").is_err());
    }

    #[test]
    fn decoding_is_the_inverse_of_the_clients_encoding() {
        // The two halves are written independently, so one pins the other.
        for value in ["admin:hunter2", "u:p", "a:b:c", ":", ""] {
            let encoded = crate::client::sdk::base64_encode_for_test(value.as_bytes());
            assert_eq!(
                base64_decode(&encoded).unwrap(),
                value.as_bytes(),
                "{value}"
            );
        }
    }

    #[test]
    fn constant_time_comparison_agrees_with_equality() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrez"));
        assert!(!constant_time_eq(b"secret", b"secret "));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn percent_decoding_handles_the_escapes_a_proxy_name_can_contain() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn the_status_response_groups_by_type_and_matches_the_go_field_names() {
        let mut admin = admin();
        let (_, status) = watch::channel(snapshot());
        admin.status = status;
        admin.config = Arc::new({
            let mut config = ClientConfig::default();
            config.common.server_addr = "example.com".into();
            config
        });

        let response = admin.status_response();
        assert_eq!(response.status, 200);
        let json = body(&response);

        // Grouped by type, the way Go's `StatusResp map[string][]...` is.
        assert!(json.starts_with("{\"tcp\":["), "{json}");
        // The `tcp` remote address is absolute, like Go's.
        assert!(
            json.contains("\"remote_addr\":\"example.com:6000\""),
            "{json}"
        );
        // The Go field names, including the underscore ones.
        assert!(json.contains("\"local_addr\":\"127.0.0.1:22\""), "{json}");
        assert!(json.contains("\"status\":\"start error\""), "{json}");
        assert!(json.contains("\"err\":\"port already used\""), "{json}");
        assert!(json.contains("\"plugin\":\"unix_domain_socket\""), "{json}");
    }

    #[test]
    fn a_failed_proxy_reports_no_remote_address() {
        // `buildProxyStatusResp` only fills it when there is no error, because a
        // stale address would be worse than none.
        let mut admin = admin();
        let (_, status) = watch::channel(snapshot());
        admin.status = status;
        let json = body(&admin.status_response());
        let failed = json.split("\"name\":\"sock\"").nth(1).unwrap();
        assert!(failed.contains("\"remote_addr\":\"\""), "{json}");
    }

    #[test]
    fn status_proxies_are_sorted_by_name_within_a_type() {
        let mut admin = admin();
        let mut state = snapshot();
        state.proxies.insert(
            0,
            ProxyStatus {
                name: "aaa".into(),
                proxy_type: "tcp",
                phase: ProxyPhase::New,
                remote_addr: String::new(),
                error: String::new(),
            },
        );
        let (_, status) = watch::channel(state);
        admin.status = status;

        let json = body(&admin.status_response());
        let aaa = json.find("\"aaa\"").unwrap();
        let sock = json.find("\"sock\"").unwrap();
        let ssh = json.find("\"ssh\"").unwrap();
        assert!(aaa < sock && sock < ssh, "{json}");
    }

    #[test]
    fn metrics_are_plain_text_and_count_what_running_means() {
        let mut admin = admin();
        let (_, status) = watch::channel(snapshot());
        admin.status = status;
        // The counters come from the live `Traffic`, so they are recorded here
        // rather than baked into the snapshot.
        admin.traffic.record(12, 34);
        admin.traffic.record(0, 0);

        let response = admin.metrics_response();
        let text = body(&response);
        assert!(text.contains("frpc_connected 1\n"), "{text}");
        assert!(text.contains("frpc_proxies 2\n"), "{text}");
        assert!(text.contains("frpc_proxies_running 1\n"), "{text}");
        assert!(text.contains("frpc_bytes_to_local 12\n"), "{text}");
        assert!(text.contains("frpc_bytes_to_work 34\n"), "{text}");
        assert!(text.contains("frpc_connections_closed 2\n"), "{text}");
        assert!(
            text.contains("frpc_proxy_running{proxy=\"ssh\",type=\"tcp\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("frpc_proxy_running{proxy=\"sock\",type=\"tcp\"} 0\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_open_api_needs_no_credentials_but_a_configured_one_does() {
        let mut admin = admin();
        let request = Request {
            method: "GET".into(),
            path: "/api/status".into(),
            query: String::new(),
            authorization: None,
            body: Vec::new(),
        };
        assert!(admin.authorized(&request));

        admin.user = "admin".into();
        admin.password = "hunter2".into();
        assert!(!admin.authorized(&request));

        let with = |header: &str| Request {
            authorization: Some(header.to_string()),
            ..request.clone()
        };
        // "admin:hunter2"
        assert!(admin.authorized(&with("Basic YWRtaW46aHVudGVyMg==")));
        assert!(!admin.authorized(&with("Basic YWRtaW46d3Jvbmc=")));
        assert!(!admin.authorized(&with("Bearer YWRtaW46aHVudGVyMg==")));
        assert!(!admin.authorized(&with("Basic !!!")));
    }

    #[tokio::test]
    async fn healthz_skips_authentication() {
        let mut admin = admin();
        admin.user = "admin".into();
        admin.password = "hunter2".into();

        let response = admin
            .route(Request {
                method: "GET".into(),
                path: "/healthz".into(),
                query: String::new(),
                authorization: None,
                body: Vec::new(),
            })
            .await;
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn a_reload_carries_the_strict_flag_through() {
        let (commands, mut rx) = mpsc::channel(4);
        let (_, status) = watch::channel(StatusSnapshot::default());
        let admin = Admin {
            config: Arc::new(ClientConfig::default()),
            user: String::new(),
            password: String::new(),
            status,
            traffic: Arc::new(Traffic::default()),
            commands,
            config_path: std::path::PathBuf::from("frpc.toml"),
        };

        let response = admin
            .route(Request {
                method: "GET".into(),
                path: "/api/reload".into(),
                query: "strictConfig=true".into(),
                authorization: None,
                body: Vec::new(),
            })
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(rx.recv().await, Some(AdminCommand::Reload { strict: true }));
    }

    #[tokio::test]
    async fn an_unknown_route_is_a_json_error_like_the_go_envelope() {
        let response = admin()
            .route(Request {
                method: "GET".into(),
                path: "/api/nope".into(),
                query: String::new(),
                authorization: None,
                body: Vec::new(),
            })
            .await;
        assert_eq!(response.status, 404);
        assert_eq!(body(&response), "{\"code\":404,\"msg\":\"not found\"}");
    }

    #[tokio::test]
    async fn the_wrong_method_is_rejected_for_a_known_route() {
        let response = admin()
            .route(Request {
                method: "DELETE".into(),
                path: "/api/status".into(),
                query: String::new(),
                authorization: None,
                body: Vec::new(),
            })
            .await;
        assert_eq!(response.status, 405);
    }

    #[test]
    fn a_response_is_written_with_the_headers_a_client_needs() {
        let encoded = String::from_utf8(Response::text(200, "hello").encode()).unwrap();
        assert!(encoded.starts_with("HTTP/1.1 200 OK\r\n"), "{encoded}");
        assert!(encoded.contains("Content-Length: 5\r\n"), "{encoded}");
        assert!(encoded.ends_with("\r\n\r\nhello"), "{encoded}");
    }

    #[test]
    fn the_admin_name_strips_the_user_prefix() {
        let mut config = ClientConfig::default();
        config.common.user = "alice".into();
        assert_eq!(admin_name(&config, "alice.ssh"), "ssh");
        assert_eq!(admin_name(&config, "ssh"), "ssh");
    }
}
