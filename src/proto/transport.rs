//! Dialing the frps control port.
//!
//! The Go client builds a connection out of a stack of "after dial" hooks, each
//! one wrapping whatever the one before it produced. Which hooks run, and in what
//! order, is decided by their priority — `DefaultAfterHookPriority` is 10,
//! `WithTLSConfig` is `MaxUint64`, and equal priorities keep their registration
//! order:
//!
//! ```text
//! protocol   hooks, in the order they run            what comes out
//! tcp        head byte, tls                          tls(tcp)
//! websocket  websocket, head byte, tls               tls(websocket(tcp))
//! wss        tls, websocket                          websocket(tls(tcp))
//! ```
//!
//! Two of those repay a second look. On a plain `websocket` connection TLS runs
//! **inside** the websocket frames rather than around them — `wss` is the other
//! way round — and the `0x17` head byte is written inside the websocket stream
//! too, because the hook that writes it is registered after the websocket hook.
//! Swap either and the connection handshakes with nobody.
//!
//! `transport.tls.enable` defaults to **true**, so `tls(tcp)` is the default path
//! and not an option most users opt into; a server with `tls.force = true` is
//! unreachable without it.
//!
//! Only the `tcp` row is implemented so far.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// `FRPTLSHeadByte` (`pkg/util/net/tls.go`).
///
/// The client writes this before the TLS records so a server sharing a port with
/// its own HTTPS listener can tell an frp client from a browser. It is only
/// written when `disableCustomTLSFirstByte` is explicitly false — the option
/// defaults to true, which means the byte is *not* sent.
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;

/// `transport.protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Websocket,
    Wss,
    Kcp,
    Quic,
}

impl Protocol {
    /// Parses a protocol name. Unknown names are rejected here rather than at
    /// dial time so a typo reads as a config error, which is what the Go
    /// validation layer makes of it too.
    pub fn parse(name: &str) -> Result<Protocol> {
        match name {
            "tcp" => Ok(Protocol::Tcp),
            "websocket" => Ok(Protocol::Websocket),
            "wss" => Ok(Protocol::Wss),
            "kcp" => Ok(Protocol::Kcp),
            "quic" => Ok(Protocol::Quic),
            other => Err(Error::config(format!(
                "invalid protocol {other:?}, optional values are {:?}",
                crate::config::SUPPORTED_TRANSPORT_PROTOCOLS
            ))),
        }
    }

    /// The name as the config spells it, for messages.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Websocket => "websocket",
            Protocol::Wss => "wss",
            Protocol::Kcp => "kcp",
            Protocol::Quic => "quic",
        }
    }

    /// Whether this client can actually dial it yet.
    ///
    /// `wss` implies TLS whatever `transport.tls.enable` says — the Go client
    /// sets `tlsEnable = true` for it before it reads the option.
    pub fn is_implemented(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Websocket | Protocol::Wss)
    }
}

/// `transport.tls`, resolved into what a handshake needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    /// `serverName`, or `serverAddr` when that is empty — Go's fallback, and the
    /// reason a config that names neither still handshakes.
    pub server_name: String,
    pub cert_file: String,
    pub key_file: String,
    pub trusted_ca_file: String,
    /// `disableCustomTLSFirstByte`: true means do **not** write the `0x17`.
    pub disable_custom_first_byte: bool,
}

/// Everything a dial needs, taken from `transport.*`.
///
/// One struct rather than six parameters because the connector, the plain
/// connector and the retry path all have to carry the same set, and a positional
/// list that long invites a swapped pair that still compiles.
#[derive(Debug, Clone)]
pub struct Dial {
    pub protocol: Protocol,
    /// `None` when TLS is off for the chosen protocol.
    pub tls: Option<Tls>,
    pub addr: String,
    pub timeout: Duration,
    pub local_ip: String,
    pub keepalive: Option<Duration>,
}

impl Dial {
    /// Builds the dial from a completed config.
    ///
    /// A protocol this client cannot dial is an error here rather than at the
    /// first reconnect, so a config that cannot work says so once, at startup.
    pub fn from_config(common: &crate::config::ClientCommonConfig) -> Result<Dial> {
        let transport = common.transport.clone().unwrap_or_default();
        let protocol = Protocol::parse(if transport.protocol.is_empty() {
            "tcp"
        } else {
            &transport.protocol
        })?;
        if !protocol.is_implemented() {
            return Err(Error::config(format!(
                "transport.protocol {:?} is not implemented yet; use \"tcp\", \"websocket\" or \
                 \"wss\"",
                protocol.name()
            )));
        }

        // `tlsEnable` is forced on for `wss` before the option is consulted.
        let tls_on = transport
            .tls
            .as_ref()
            .and_then(|tls| tls.enable)
            .unwrap_or(true)
            || matches!(protocol, Protocol::Wss);
        let tls = if tls_on {
            let configured = transport.tls.clone().unwrap_or_default();
            let server_name = if configured.server_name.is_empty() {
                common.server_addr.clone()
            } else {
                configured.server_name.clone()
            };
            Some(Tls {
                server_name,
                cert_file: configured.cert_file,
                key_file: configured.key_file,
                trusted_ca_file: configured.trusted_ca_file,
                disable_custom_first_byte: configured.disable_custom_tls_first_byte.unwrap_or(true),
            })
        } else {
            None
        };

        let keepalive = match transport.dial_server_keepalive {
            value if value > 0 => Some(Duration::from_secs(value as u64)),
            _ => None,
        };

        Ok(Dial {
            protocol,
            tls,
            addr: join_host_port(&common.server_addr, common.server_port),
            timeout: Duration::from_secs(transport.dial_server_timeout.max(1) as u64),
            local_ip: transport.connect_server_local_ip,
            keepalive,
        })
    }
}

/// The byte stream the frp codec runs over.
///
/// An enum rather than a trait object: the set of layers is closed and known at
/// compile time, it matches the Go client's stack one hook at a time, and a `dyn`
/// here would buy no flexibility this needs while adding a vtable hop to every
/// read of every byte the tunnel carries.
#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    /// The inner `Stream` is boxed because the type would otherwise contain
    /// itself.
    Tls(Box<tokio_rustls::client::TlsStream<Stream>>),
    Websocket(Box<super::websocket::WebSocket<Stream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(socket) => std::pin::Pin::new(socket).poll_read(cx, buf),
            Stream::Tls(tls) => std::pin::Pin::new(tls.as_mut()).poll_read(cx, buf),
            Stream::Websocket(ws) => std::pin::Pin::new(ws.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(socket) => std::pin::Pin::new(socket).poll_write(cx, buf),
            Stream::Tls(tls) => std::pin::Pin::new(tls.as_mut()).poll_write(cx, buf),
            Stream::Websocket(ws) => std::pin::Pin::new(ws.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(socket) => std::pin::Pin::new(socket).poll_flush(cx),
            Stream::Tls(tls) => std::pin::Pin::new(tls.as_mut()).poll_flush(cx),
            Stream::Websocket(ws) => std::pin::Pin::new(ws.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(socket) => std::pin::Pin::new(socket).poll_shutdown(cx),
            Stream::Tls(tls) => std::pin::Pin::new(tls.as_mut()).poll_shutdown(cx),
            Stream::Websocket(ws) => std::pin::Pin::new(ws.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Dials, then applies the transport's layers in the order the Go hooks do.
///
/// The order is not the order the hooks are registered in, and it is not the
/// same for every protocol. `wss` is the odd one: its TLS hook is registered at
/// priority 100 and its websocket hook at 110, so TLS is the outer layer and the
/// websocket handshake happens inside it. For plain `websocket` both hooks sit at
/// `DefaultAfterHookPriority`, the websocket one was registered first, and so
/// TLS ends up inside the websocket — which is the arrangement that surprises
/// people, and the one that has to be right for the handshake to complete at all.
pub async fn connect(dial: &Dial) -> Result<Stream> {
    let socket = dial_tcp(&dial.addr, dial.timeout, &dial.local_ip, dial.keepalive).await?;
    let mut stream = Stream::Tcp(socket);

    // `wss`: TLS first, then the websocket handshake over the encrypted stream,
    // with the TLS server name standing in for the host in the handshake.
    if dial.protocol == Protocol::Wss {
        let tls = dial
            .tls
            .as_ref()
            .expect("`wss` implies TLS, and `Dial::from_config` sets it");
        stream = tls_over(stream, tls).await?;
        stream = websocket_over(stream, &tls.server_name).await?;
        return Ok(stream);
    }

    // `websocket`: the handshake runs in the clear, and everything after it goes
    // inside the frames.
    if dial.protocol == Protocol::Websocket {
        stream = websocket_over(stream, &dial.addr).await?;
    }

    if let Some(tls) = dial.tls.as_ref() {
        // Registered before the TLS hook, so it runs before it — and on a
        // `websocket` connection that means inside the websocket stream, which
        // is what the module comment describes.
        if !tls.disable_custom_first_byte {
            use tokio::io::AsyncWriteExt;
            stream
                .write_all(&[FRP_TLS_HEAD_BYTE])
                .await
                .map_err(|err| Error::other(format!("writing the frp tls head byte: {err}")))?;
            stream
                .flush()
                .await
                .map_err(|err| Error::other(format!("flushing the frp tls head byte: {err}")))?;
        }
        stream = tls_over(stream, tls).await?;
    }

    Ok(stream)
}

/// Runs the websocket handshake over `inner`.
async fn websocket_over(inner: Stream, host: &str) -> Result<Stream> {
    let ws = super::websocket::connect(inner, host).await?;
    Ok(Stream::Websocket(Box::new(ws)))
}

/// Wraps `inner` in a TLS client session.
async fn tls_over(inner: Stream, tls: &Tls) -> Result<Stream> {
    let config = client_config(tls)?;
    let name = rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|_| {
        Error::config(format!(
            "transport.tls.serverName {:?} is neither a DNS name nor an IP address",
            tls.server_name
        ))
    })?;

    let stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, inner)
        .await
        .map_err(|err| {
            // `Error::Tls` is not retryable, and that is the right call: a
            // handshake that failed once fails the same way next time, so a
            // retry loop would only delay the report. A *connection* failure is,
            // and that one is an `Io` error from the dial above.
            Error::Tls(format!("tls handshake with {}: {err}", tls.server_name))
        })?;

    Ok(Stream::Tls(Box::new(stream)))
}

/// Builds the rustls client config, mirroring `NewClientTLSConfig`.
fn client_config(tls: &Tls) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(format!("tls versions: {err}")))?;

    // Go: `if caPath != "" { RootCAs = pool; InsecureSkipVerify = false } else
    // { InsecureSkipVerify = true }`. So the default is *no* verification at
    // all, and a CA file is the only thing that turns it on.
    let wants_cert = if tls.trusted_ca_file.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new(provider)))
    } else {
        let pem = std::fs::read(&tls.trusted_ca_file).map_err(|err| {
            Error::Tls(format!(
                "reading transport.tls.trustedCaFile {:?}: {err}",
                tls.trusted_ca_file
            ))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(parse_certificates(&pem));
        if added == 0 {
            return Err(Error::Tls(format!(
                "transport.tls.trustedCaFile {:?} holds no usable certificate",
                tls.trusted_ca_file
            )));
        }
        if ignored > 0 {
            crate::logging::warn(format!(
                "transport.tls.trustedCaFile {:?}: ignored {ignored} entry/entries that are \
                 not certificates",
                tls.trusted_ca_file
            ));
        }
        builder.with_root_certificates(roots)
    };

    let config = if tls.cert_file.is_empty() || tls.key_file.is_empty() {
        wants_cert.with_no_client_auth()
    } else {
        let certs = parse_certificates(&std::fs::read(&tls.cert_file).map_err(|err| {
            Error::Tls(format!(
                "reading transport.tls.certFile {:?}: {err}",
                tls.cert_file
            ))
        })?);
        if certs.is_empty() {
            return Err(Error::Tls(format!(
                "transport.tls.certFile {:?} holds no certificate",
                tls.cert_file
            )));
        }
        let key = parse_private_key(&std::fs::read(&tls.key_file).map_err(|err| {
            Error::Tls(format!(
                "reading transport.tls.keyFile {:?}: {err}",
                tls.key_file
            ))
        })?)?;
        wants_cert
            .with_client_auth_cert(certs, key)
            .map_err(|err| Error::Tls(format!("transport.tls client certificate: {err}")))?
    };

    Ok(Arc::new(config))
}

/// Every certificate in a PEM bundle, skipping anything that is not one.
///
/// `filter_map` rather than `collect::<Result<_, _>>()`: `pem_slice_iter` yields
/// a `Result` per section, and a bundle with a stray key or comment in it should
/// still give up its certificates — Go's `AppendCertsFromPEM` skips the same way.
fn parse_certificates(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .filter_map(std::result::Result::ok)
        .collect()
}

/// The first private key in a PEM bundle.
fn parse_private_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_slice(pem).map_err(|err| {
        Error::Tls(format!(
            "transport.tls.keyFile is not a usable private key: {err}"
        ))
    })
}

/// Accepts any server certificate, which is what `InsecureSkipVerify = true` is.
///
/// This is not a "skip TLS" switch and it does not weaken the record layer: the
/// handshake still runs, the key exchange still happens, and the signature over
/// the transcript is still checked — [`verify_tls12_signature`] and its TLS 1.3
/// twin are delegated to the provider rather than stubbed out, so what is
/// skipped is exactly the chain and the name. That is the same thing Go skips,
/// and it is the **default**: frp only verifies when `trustedCaFile` is set.
///
/// The point of TLS here is to look like nothing in particular to whatever is
/// watching the wire, not to authenticate a server the user has already told the
/// client to trust by configuring its address.
///
/// [`verify_tls12_signature`]: rustls::crypto::verify_tls12_signature
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyServerCert {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Opens a TCP connection to `addr`, applying the configured dial timeout and
/// keepalive.
///
/// `local_ip` is `transport.connectServerLocalIP`: the source address to bind,
/// which is only meaningful for TCP and websocket on the Go side too.
async fn dial_tcp(
    addr: &str,
    timeout: Duration,
    local_ip: &str,
    keepalive: Option<Duration>,
) -> Result<TcpStream> {
    let target = normalize_addr(addr);
    let local: Option<SocketAddr> = if local_ip.is_empty() {
        None
    } else {
        Some(normalize_addr(local_ip).parse().map_err(|err| {
            Error::config(format!("invalid transport.connectServerLocalIP: {err}"))
        })?)
    };

    let future = async {
        // A name is the common case: `frpc` is normally pointed at a DNS name and
        // the port is joined on here, exactly as `net.JoinHostPort` does it. A
        // literal address skips the resolver, which is both faster and the path
        // that works on a host with no resolver configured at all.
        if let Ok(remote) = target.parse::<SocketAddr>() {
            return dial_addr(remote, local).await;
        }
        let mut last = None;
        for remote in tokio::net::lookup_host(&target)
            .await
            .map_err(|err| std::io::Error::other(format!("cannot resolve {target}: {err}")))?
        {
            match dial_addr(remote, local).await {
                Ok(stream) => return Ok(stream),
                // A name can resolve to several addresses and only one of them
                // has to answer — that is precisely what `lookup_host` is for.
                Err(err) => last = Some(err),
            }
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("{target} resolved to no addresses"),
            )
        }))
    };

    let stream = tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| Error::other(format!("dial {target} timed out after {timeout:?}")))??;

    stream.set_nodelay(true)?;

    // `dialServerKeepalive` defaults to 7200 seconds; a negative or zero value
    // disables probes, matching the Go side.
    if let Some(keepalive) = keepalive {
        let socket = socket2::SockRef::from(&stream);
        let keepalive = socket2::TcpKeepalive::new().with_time(keepalive);
        // Best effort: a platform without keepalive support should not stop the
        // connection from working.
        let _ = socket.set_tcp_keepalive(&keepalive);
    }

    Ok(stream)
}

/// One dial, to an address already resolved.
///
/// Binding a source address only makes sense once the family is known, which is
/// why this is separate from the resolution above.
async fn dial_addr(remote: SocketAddr, local: Option<SocketAddr>) -> std::io::Result<TcpStream> {
    match local {
        None => TcpStream::connect(remote).await,
        Some(local) => {
            let socket = if remote.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.bind(local)?;
            socket.connect(remote).await
        }
    }
}

/// Adds a port when the address has none, so `"1.2.3.4"` becomes
/// `"1.2.3.4:7000"`. Matches how the Go client joins `serverAddr` and
/// `serverPort`.
///
/// The colon count is what decides: one colon is a `host:port`, two or more is a
/// bare IPv6 address that needs bracketing before a port can be appended.
/// Matching on "does it end in digits" instead would treat `::1` as having port
/// `1`, which is exactly the address this has to get right.
pub fn normalize_addr(addr: &str) -> String {
    // Already bracketed: either `[::1]` or `[::1]:7000`.
    if let Some(rest) = addr.strip_prefix('[') {
        return match rest.split_once("]:") {
            Some(_) => addr.to_string(),
            None => format!("{addr}:7000"),
        };
    }
    match addr.matches(':').count() {
        0 => format!("{addr}:7000"),
        1 => {
            // `host:port`, unless the port is empty (`host:`).
            if addr.ends_with(':') {
                format!("{addr}7000")
            } else {
                addr.to_string()
            }
        }
        // A bare IPv6 address.
        _ => format!("[{addr}]:7000"),
    }
}

/// Joins a host and a port, bracketing IPv6 hosts.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_without_a_port_gets_one() {
        assert_eq!(normalize_addr("1.2.3.4"), "1.2.3.4:7000");
        assert_eq!(normalize_addr("example.com"), "example.com:7000");
    }

    #[test]
    fn an_address_with_a_port_is_left_alone() {
        assert_eq!(normalize_addr("1.2.3.4:7100"), "1.2.3.4:7100");
        assert_eq!(normalize_addr("example.com:7100"), "example.com:7100");
    }

    #[test]
    fn a_bare_ipv6_address_is_bracketed() {
        assert_eq!(normalize_addr("::1"), "[::1]:7000");
        assert_eq!(normalize_addr("2001:db8::1"), "[2001:db8::1]:7000");
    }

    #[test]
    fn an_already_bracketed_address_is_handled() {
        assert_eq!(normalize_addr("[::1]"), "[::1]:7000");
        assert_eq!(normalize_addr("[::1]:7100"), "[::1]:7100");
    }

    #[test]
    fn a_trailing_colon_gets_the_default_port() {
        assert_eq!(normalize_addr("1.2.3.4:"), "1.2.3.4:7000");
    }

    #[test]
    fn join_host_port_brackets_only_ipv6() {
        assert_eq!(join_host_port("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(join_host_port("example.com", 80), "example.com:80");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
        assert_eq!(join_host_port("[::1]", 80), "[::1]:80");
    }

    /// A dial built from a config, since that is the only way one is built.
    fn dial_for(addr: &str) -> Dial {
        let mut common = crate::config::ClientCommonConfig {
            server_addr: addr.split(':').next().unwrap().to_string(),
            server_port: addr.rsplit(':').next().unwrap().parse().unwrap(),
            ..Default::default()
        };
        // TLS defaults to on, which would make every dial below a handshake. Off
        // explicitly, so these tests are about the dial.
        common
            .transport
            .get_or_insert_with(Default::default)
            .tls
            .get_or_insert_with(Default::default)
            .enable = Some(false);
        Dial::from_config(&common).unwrap()
    }

    /// `protocol` is rejected at dial construction, not at the first reconnect.
    #[test]
    fn an_unimplemented_protocol_is_refused_with_its_name() {
        for name in ["kcp", "quic"] {
            let mut common = crate::config::ClientCommonConfig::default();
            common
                .transport
                .get_or_insert_with(Default::default)
                .protocol = name.into();
            let err = Dial::from_config(&common).unwrap_err();
            assert!(matches!(err, Error::Config(_)), "{name}: {err}");
            assert!(err.to_string().contains(name), "{name}: {err}");
        }
    }

    /// The three that do dial, so a later regression cannot quietly turn one of
    /// them back into a config error.
    #[test]
    fn the_implemented_protocols_all_build_a_dial() {
        for name in ["tcp", "websocket", "wss"] {
            let mut common = crate::config::ClientCommonConfig::default();
            common
                .transport
                .get_or_insert_with(Default::default)
                .protocol = name.into();
            let dial = Dial::from_config(&common).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(dial.protocol.name(), name);
        }
    }

    /// A protocol name that is not one of the five is a different complaint: the
    /// Go validation layer would have rejected it before a dial was ever built.
    #[test]
    fn an_unknown_protocol_name_is_a_config_error() {
        assert!(matches!(
            Protocol::parse("carrier-pigeon").unwrap_err(),
            Error::Config(_)
        ));
    }

    /// `tlsEnable` is forced on for `wss` before the option is read — the Go
    /// client does it in `realConnect`, above the switch that uses it.
    #[test]
    fn wss_turns_tls_on_whatever_the_option_says() {
        let mut common = crate::config::ClientCommonConfig::default();
        let transport = common.transport.get_or_insert_with(Default::default);
        transport.protocol = "wss".into();
        transport.tls.get_or_insert_with(Default::default).enable = Some(false);

        let dial = Dial::from_config(&common).expect("`wss` dials");
        assert!(
            dial.tls.is_some(),
            "`wss` is TLS with a websocket inside it, so `enable = false` cannot turn it off"
        );
    }

    /// TLS defaults to on, and `serverName` falls back to `serverAddr`.
    #[test]
    fn tls_is_on_by_default_and_borrows_the_server_address() {
        let common = crate::config::ClientCommonConfig {
            server_addr: "frps.example.com".into(),
            server_port: 7000,
            ..Default::default()
        };
        let dial = Dial::from_config(&common).unwrap();
        let tls = dial.tls.as_ref().expect("tls is on by default");
        assert_eq!(tls.server_name, "frps.example.com");
        // The option defaults to true, which means the byte is *not* sent.
        assert!(tls.disable_custom_first_byte);
        assert_eq!(dial.addr, "frps.example.com:7000");
    }

    /// An explicit `serverName` wins, which is what makes `tls.force` on a server
    /// behind an address the client does not know work.
    #[test]
    fn an_explicit_server_name_is_used_instead() {
        let mut common = crate::config::ClientCommonConfig {
            server_addr: "10.0.0.1".into(),
            ..Default::default()
        };
        common
            .transport
            .get_or_insert_with(Default::default)
            .tls
            .get_or_insert_with(Default::default)
            .server_name = "frps.example.com".into();
        let dial = Dial::from_config(&common).unwrap();
        assert_eq!(dial.tls.as_ref().unwrap().server_name, "frps.example.com");
    }

    /// The layer order, read off the wire.
    ///
    /// This is the part of the transport that is easiest to get wrong and
    /// hardest to debug: every combination below produces a connection that
    /// *almost* works if two layers are swapped, and the symptom is a peer that
    /// closes without saying why. Dial against a listener that reads a few bytes
    /// and then gives up, and assert what those bytes are.
    ///
    /// The surprising row is `websocket` with TLS on — the default for that
    /// protocol. It starts with `GET`, not with a TLS record, because the
    /// websocket hook runs first: TLS is *inside* the websocket there. `wss` is
    /// the one that starts with a ClientHello.
    #[tokio::test]
    async fn the_layers_go_on_in_the_order_the_go_hooks_run() {
        /// Dials `dial` against a listener that captures what arrives first.
        async fn first_bytes(mut dial: Dial) -> Vec<u8> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let reader = tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut socket = listener.accept().await.unwrap().0;
                let mut buf = [0u8; 16];
                // A TLS handshake stalls here waiting for a ServerHello, and a
                // plain dial sends nothing at all, so both ends have to be
                // bounded. What was written before that is the answer.
                let read = tokio::time::timeout(Duration::from_millis(500), socket.read(&mut buf))
                    .await
                    .ok()
                    .and_then(std::result::Result::ok)
                    .unwrap_or(0);
                buf[..read].to_vec()
            });

            dial.addr = addr.to_string();
            // The dial itself cannot finish — there is no server here — and the
            // error is not what this is about.
            let _ = connect(&dial).await;
            reader.await.unwrap()
        }

        fn dial_for(protocol: &str, tls: Option<bool>) -> Dial {
            let mut common = crate::config::ClientCommonConfig {
                server_addr: "127.0.0.1".into(),
                server_port: 7,
                ..Default::default()
            };
            let transport = common.transport.get_or_insert_with(Default::default);
            transport.protocol = protocol.into();
            transport.tls.get_or_insert_with(Default::default).enable = tls;
            Dial::from_config(&common).unwrap()
        }

        /// A TLS ClientHello record: handshake, version 3.x.
        const CLIENT_HELLO: u8 = 0x16;

        // `tcp` with TLS off: nothing is written until the frp layer has
        // something to say.
        assert!(first_bytes(dial_for("tcp", Some(false))).await.is_empty());

        // `tcp` with TLS on: the ClientHello, and no 0x17 before it because
        // `disableCustomTLSFirstByte` defaults to true.
        assert_eq!(
            first_bytes(dial_for("tcp", None)).await[0],
            CLIENT_HELLO,
            "plain tcp with tls is tls over tcp"
        );

        // `websocket` with TLS off: the handshake request, in the clear.
        assert_eq!(
            &first_bytes(dial_for("websocket", Some(false))).await[..4],
            b"GET ",
            "websocket starts with its own handshake"
        );

        // `websocket` with TLS on — the default: *still* the handshake request,
        // and the ClientHello only appears inside the frames.
        assert_eq!(
            &first_bytes(dial_for("websocket", None)).await[..4],
            b"GET ",
            "tls over websocket puts the websocket handshake outermost"
        );

        // `wss`: the other way round, so the first byte is a TLS record.
        assert_eq!(
            first_bytes(dial_for("wss", None)).await[0],
            CLIENT_HELLO,
            "wss is a websocket handshake inside tls"
        );
        // And even `enable = false` cannot take the TLS out of `wss`.
        assert_eq!(
            first_bytes(dial_for("wss", Some(false))).await[0],
            CLIENT_HELLO,
            "wss implies tls"
        );
    }

    /// A name has to reach the resolver, not the address parser.
    ///
    /// This is the bug that made `serverAddr = "host.example.com"` fail with
    /// "invalid socket address syntax" while the identical config worked under
    /// the Go client: `"host.example.com:7000"` does not parse as a `SocketAddr`,
    /// and Go never asks it to — it hands the joined string to `net.Dial`.
    #[tokio::test]
    async fn a_name_is_resolved_rather_than_parsed_as_an_address() {
        // Nothing is listening, so this cannot succeed. What it proves is the
        // shape of the failure: a resolved-and-refused dial, not a config error.
        let err = connect(&dial_for("localhost:1")).await.unwrap_err();
        assert!(
            !matches!(err, Error::Config(_)),
            "a hostname must be resolved, not rejected as a bad address: {err}"
        );
    }

    /// An address literal still has to work, and has to skip the resolver.
    ///
    /// `127.0.0.1` is a name to `lookup_host` but a literal to `parse`, and the
    /// literal path is what keeps a host with no resolver configured working.
    #[tokio::test]
    async fn a_literal_address_still_dials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let stream = connect(&dial_for(&addr.to_string())).await.unwrap();
        assert!(matches!(stream, Stream::Tcp(_)));
        accepted.await.unwrap().unwrap();
    }

    /// The `0x17` byte is written before the handshake, and only when
    /// `disableCustomTLSFirstByte` is explicitly false.
    ///
    /// A server sharing its port with an HTTPS listener is the case this exists
    /// for, and it is the one case that is silently wrong if the flag is read
    /// backwards.
    #[tokio::test]
    async fn the_tls_head_byte_is_written_only_when_asked_for() {
        async fn first_bytes(disable: bool) -> Vec<u8> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let reader = tokio::spawn(async move {
                let mut socket = listener.accept().await.unwrap().0;
                let mut buf = [0u8; 1];
                // The TLS ClientHello follows, so one byte is enough to tell
                // whether the marker is there.
                use tokio::io::AsyncReadExt;
                let _ = socket.read_exact(&mut buf).await;
                buf.to_vec()
            });

            let mut dial = dial_for(&addr.to_string());
            dial.tls = Some(Tls {
                server_name: "127.0.0.1".into(),
                cert_file: String::new(),
                key_file: String::new(),
                trusted_ca_file: String::new(),
                disable_custom_first_byte: disable,
            });
            // The handshake itself cannot finish — nothing here speaks TLS — so
            // the error is expected and irrelevant; the byte has already been
            // written by then.
            let _ = connect(&dial).await;
            reader.await.unwrap()
        }

        assert_eq!(first_bytes(false).await, vec![FRP_TLS_HEAD_BYTE]);
        // A TLS record starts with 0x16 (handshake), so the marker is absent.
        assert_eq!(first_bytes(true).await, vec![0x16]);
    }
}
