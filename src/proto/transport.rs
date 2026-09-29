//! Dialing the frps control port.
//!
//! Only `tcp` for now. `tls`, `websocket` and `kcp` plug in here later; the
//! shape they will take is already visible in [`connect`] — a dial, then a
//! transport-specific handshake, then the frp crypto layer on top.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// Whether to reuse one connection for many logical streams.
///
/// This is `transport.tcpMux`. The flag lives in the config; it is mirrored here
/// because the connection path needs to know whether to wrap in yamux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// One connection per logical stream.
    Tcp,
    /// A single connection multiplexed with yamux.
    TcpMux,
}

impl Transport {
    /// Picks the transport from a completed config.
    pub fn from_config(transport: &crate::config::ClientTransportConfig) -> Result<Transport> {
        match transport.protocol.as_str() {
            "tcp" => Ok(if transport.tcp_mux.unwrap_or(true) {
                Transport::TcpMux
            } else {
                Transport::Tcp
            }),
            other => Err(Error::config(format!(
                "transport protocol {other:?} is not implemented yet; use \"tcp\""
            ))),
        }
    }
}

/// Opens a TCP connection to `addr`, applying the configured dial timeout and
/// keepalive.
///
/// `local_ip` is `transport.connectServerLocalIP`: the source address to bind,
/// which is only meaningful for TCP and websocket on the Go side too.
pub async fn connect(
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
    let remote: SocketAddr = target
        .parse()
        .map_err(|err| Error::config(format!("invalid server address {target}: {err}")))?;

    let future = async {
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

    #[test]
    fn the_transport_follows_tcp_mux() {
        let mut transport = crate::config::ClientTransportConfig {
            protocol: "tcp".into(),
            tcp_mux: Some(true),
            ..Default::default()
        };
        assert_eq!(
            Transport::from_config(&transport).unwrap(),
            Transport::TcpMux
        );

        transport.tcp_mux = Some(false);
        assert_eq!(Transport::from_config(&transport).unwrap(), Transport::Tcp);

        transport.protocol = "kcp".into();
        assert!(Transport::from_config(&transport).is_err());
    }
}
