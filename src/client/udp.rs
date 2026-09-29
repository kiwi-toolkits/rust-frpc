//! The UDP forwarder behind a `udp` proxy.
//!
//! A TCP proxy is a byte pipe: one user connection, one local connection, bytes
//! both ways. UDP is not. A datagram is the unit, the server multiplexes every
//! user's traffic onto a single work connection, and a local socket is only opened
//! when the first datagram from a particular user arrives:
//!
//! ```text
//! user → [frps udp listener] → UDPPacket{content, remote_addr} → work conn
//! work conn → UDPPacket → [one socket per user] → local service
//! ```
//!
//! Three things are load-bearing:
//!
//! * **A reply goes back to the user whose socket produced it.** The server puts
//!   the user's address in `remote_addr`; the answer carries it back. Mixing that
//!   up sends one user's reply to another, which is why each entry in the table
//!   below *is* the mapping, rather than a lookup done twice.
//! * **`local_addr` is ours to fill in, and the Go client leaves it out.** Empty
//!   here too: whether the server reads it is untested, so it is not guessed at.
//! * **Idle sockets are dropped after 30 seconds**, matching the read deadline the
//!   Go forwarder sets. Without it the table grows with every user ever seen.
//!
//! Frames on the work connection are ordinary v1 or v2 ones: a `UDPPacket` is a
//! registered message type. (v2 additionally offers a `binary-v1` packet codec, but
//! the server only negotiates that after a v2 hello, and this client does not
//! implement the v2 hello exchange — so the plain JSON form is what both ends are
//! using.)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::logging;
use crate::msg::{Message, UdpAddr, UdpPacket};
use crate::proto::{Codec, LogicalConn};

use super::control::{self, Traffic};

/// How long a user's local socket is kept after its last datagram.
///
/// Matches the Go forwarder's 30-second read deadline (`pkg/proto/udp/udp.go`), so
/// the socket count is bounded by *recently active* users. The `sudp` visitor uses
/// the same window as its session timeout, which is the same rule seen from the
/// other side.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest datagram accepted from a local service.
///
/// A UDP payload over IPv4 cannot exceed 65507 bytes, so this is the ceiling
/// rather than a tuning knob. `udpPacketSize` is the buffer the *server* reads
/// into and is deliberately not mirrored: a datagram larger than it has already
/// been dropped by the time it matters here.
pub const MAX_DATAGRAM: usize = 65_507;

/// How often the local sockets are polled for a reply.
///
/// The forwarding loop is otherwise parked on the work connection, and a datagram
/// the local service answers does not wake it. Four times a millisecond is well
/// below what a UDP round trip costs and far above what a human notices.
const POLL_LOCAL: Duration = Duration::from_millis(4);

/// How many outgoing messages may be queued before the reader waits.
///
/// The one case that fills this is a local service emitting faster than the work
/// connection drains. Waiting is the right answer: dropping would corrupt the
/// stream silently, and the queue is a datagram per user at most.
const SEND_QUEUE: usize = 256;

/// Serves a UDP proxy's work connection until it dies or the proxy stops.
///
/// Runs for the life of the work connection rather than per datagram: UDP has no
/// connection to serve one of, and the server replaces the work connection when it
/// goes quiet.
pub async fn serve(
    conn: LogicalConn,
    codec: Codec,
    name: &str,
    upstream: Upstream,
    traffic: Arc<Traffic>,
) {
    if let Err(err) = run(conn, codec, name, upstream, traffic).await {
        logging::debug(format!("proxy {name}: udp work connection ended: {err}"));
    }
}

/// Where a UDP proxy's datagrams go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub local_ip: String,
    pub local_port: u16,
}

async fn run(
    conn: LogicalConn,
    codec: Codec,
    name: &str,
    upstream: Upstream,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(conn);
    let (send_tx, mut send_rx) = mpsc::channel::<Message>(SEND_QUEUE);

    // One task does the writing, so a write that blocks on a full socket cannot
    // stop us reading the next datagram — or noticing that the connection died.
    let mut sender = tokio::spawn(async move {
        while let Some(message) = send_rx.recv().await {
            codec.write(&mut writer, &message).await?;
        }
        Ok::<(), Error>(())
    });

    let mut heartbeat = tokio::time::interval(control::UDP_WORK_CONN_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate; the server has just handed us the connection,
    // so there is nothing to keep alive yet.
    heartbeat.tick().await;

    // A local service's reply has to be picked up promptly, and the select below
    // is otherwise parked on the work connection. Polling the socket table on a
    // timer is what makes an idle-but-answered datagram come back: a `recv` future
    // per socket would have to be rebuilt every time a user appears, and the table
    // is small and changes rarely.
    let mut drain = tokio::time::interval(POLL_LOCAL);
    drain.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    drain.tick().await;

    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let mut datagram = vec![0u8; MAX_DATAGRAM];

    loop {
        peers.retain(|addr, peer| {
            let alive = peer.touched.elapsed() < IDLE_TIMEOUT;
            if !alive {
                logging::debug(format!(
                    "proxy {name}: dropping the local socket for {addr}"
                ));
            }
            alive
        });

        // The shortest time until any socket goes idle, so the reap above happens
        // on time even while nothing is arriving.
        let until_reap = peers
            .values()
            .map(|peer| IDLE_TIMEOUT.saturating_sub(peer.touched.elapsed()))
            .min();
        let reap = tokio::time::sleep(until_reap.unwrap_or(IDLE_TIMEOUT));
        tokio::pin!(reap);

        tokio::select! {
            // The writer task ending means the work connection failed.
            finished = &mut sender => {
                return match finished {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(Error::other(format!("udp writer task failed: {err}"))),
                };
            }

            read = codec.read(&mut reader) => {
                match read? {
                    Message::UdpPacket(packet) => {
                        let Some(remote) = packet.remote_addr.as_ref().and_then(to_socket_addr)
                        else {
                            logging::debug(format!(
                                "proxy {name}: a udp datagram arrived without a usable remote \
                                 address; dropping it"
                            ));
                            continue;
                        };
                        let socket = match peers.get(&remote) {
                            Some(peer) => Arc::clone(&peer.socket),
                            None => match open_upstream(&upstream) {
                                Ok(socket) => {
                                    logging::debug(format!("proxy {name}: new udp peer {remote}"));
                                    let socket = Arc::new(socket);
                                    peers.insert(
                                        remote,
                                        Peer {
                                            socket: Arc::clone(&socket),
                                            touched: Instant::now(),
                                        },
                                    );
                                    socket
                                }
                                Err(err) => {
                                    logging::warn(format!(
                                        "proxy {name}: cannot open a local udp socket for \
                                         {remote}: {err}"
                                    ));
                                    continue;
                                }
                            },
                        };

                        // The work connection carries the datagram count; the
                        // bytes are the server's to report as traffic in, and
                        // this side as bytes leaving for the local service.
                        traffic.record(packet.content.len() as u64, 0);
                        socket.send(packet.content.as_slice()).await.map_err(|err| {
                            Error::other(format!("send to the local udp service: {err}"))
                        })?;
                    }
                    // The server pings an idle UDP work connection, and tears it
                    // down after 60 seconds without an answer.
                    Message::Ping(_) => {
                        if send_tx.send(Message::Pong(Box::default())).await.is_err() {
                            return Err(Error::protocol("the udp writer is gone"));
                        }
                    }
                    other => {
                        logging::debug(format!(
                            "proxy {name}: ignoring {} on a udp work connection",
                            control::describe(&other)
                        ));
                    }
                }
            }

            _ = heartbeat.tick() => {
                if send_tx
                    .send(Message::Ping(Box::default()))
                    .await
                    .is_err()
                {
                    return Err(Error::protocol("the udp writer is gone"));
                }
            }

            // Whatever a local service has answered goes back to its own user.
            _ = drain.tick() => {
                for (remote, peer) in peers.iter_mut() {
                    loop {
                        match peer.socket.try_recv(&mut datagram) {
                            Ok(read) => {
                                peer.touched = Instant::now();
                                let content = datagram[..read].to_vec();
                                traffic.record(0, content.len() as u64);
                                let packet = Message::UdpPacket(Box::new(UdpPacket {
                                    content: content.into(),
                                    local_addr: None,
                                    remote_addr: Some(from_socket_addr(remote)),
                                }));
                                if send_tx.send(packet).await.is_err() {
                                    return Err(Error::protocol("the udp writer is gone"));
                                }
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(err) => {
                                return Err(Error::other(format!(
                                    "read from a local udp socket: {err}"
                                )))
                            }
                        }
                    }
                }
            }

            // Nothing to reap yet; the timers above bound how long this waits.
            _ = &mut reap => {}
        }
    }
}

/// One user's local socket, and when it was last used.
struct Peer {
    socket: Arc<UdpSocket>,
    touched: Instant,
}

/// Opens an ephemeral local socket connected to the service behind the proxy.
///
/// `connect` rather than `send_to` per datagram: it fixes the destination, which
/// is what makes one socket per user meaningful, and it lets the OS discard
/// replies from anywhere else.
fn open_upstream(upstream: &Upstream) -> std::io::Result<UdpSocket> {
    let target = crate::proto::transport::join_host_port(&upstream.local_ip, upstream.local_port);
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// The wire form of a socket address, as `net.UDPAddr` serializes.
///
/// The zone is left empty for IPv4 because `net.UDPAddr` never carries one there,
/// and a client that invented one would not match what the server expects back.
pub fn from_socket_addr(addr: &SocketAddr) -> UdpAddr {
    UdpAddr {
        ip: Some(crate::msg::go_types::GoIp(addr.ip())),
        port: addr.port(),
        zone: String::new(),
    }
}

/// Reads back an address the server sent.
///
/// An address with no IP is not a peer — the server always fills one in for a user
/// datagram — so it is refused rather than defaulted to `0.0.0.0`, which would
/// answer the wrong user.
pub fn to_socket_addr(addr: &UdpAddr) -> Option<SocketAddr> {
    let ip = addr.ip.as_ref()?.0;
    Some(SocketAddr::new(ip, addr.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_address_round_trips_through_the_wire_form() {
        let addr: SocketAddr = "192.0.2.10:5000".parse().unwrap();
        let wire = from_socket_addr(&addr);
        assert_eq!(wire.ip.as_ref().unwrap().0.to_string(), "192.0.2.10");
        assert_eq!(wire.port, 5000);
        assert_eq!(wire.zone, "");
        assert_eq!(to_socket_addr(&wire), Some(addr));
    }

    #[test]
    fn an_ipv6_address_keeps_its_address_and_port_separate() {
        let addr: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        let wire = from_socket_addr(&addr);
        assert_eq!(wire.ip.as_ref().unwrap().0.to_string(), "2001:db8::1");
        assert_eq!(to_socket_addr(&wire), Some(addr));
    }

    #[test]
    fn the_wire_form_serializes_the_way_go_does() {
        // Pinned against what `encoding/json` actually produced for this struct,
        // because both encodings here are wrong-by-default in serde: an IP is
        // text rather than bytes, and a byte slice is base64 rather than an array
        // of numbers. Either mistake is silent.
        let packet = UdpPacket {
            content: b"hi".to_vec().into(),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: Some(crate::msg::go_types::GoIp("192.0.2.10".parse().unwrap())),
                port: 5000,
                zone: String::new(),
            }),
        };
        let json = String::from_utf8(crate::msg::go_json::to_vec(&packet).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"c":"aGk=","r":{"IP":"192.0.2.10","Port":5000,"Zone":""}}"#
        );
    }

    #[test]
    fn an_address_without_an_ip_is_refused_rather_than_defaulted() {
        assert_eq!(
            to_socket_addr(&UdpAddr {
                ip: None,
                port: 5000,
                zone: String::new()
            }),
            None
        );
    }

    #[test]
    fn a_hostname_is_not_accepted_as_an_address() {
        // It deserializes as far as the string, then fails to parse — the point
        // being that it never silently becomes `0.0.0.0`, which would answer the
        // wrong user.
        let json = r#"{"IP":"example.com","Port":5000,"Zone":""}"#;
        assert!(serde_json::from_str::<UdpAddr>(json).is_err());
    }
}
