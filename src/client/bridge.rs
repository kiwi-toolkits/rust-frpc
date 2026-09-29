//! Bridging a work connection to the local service behind a proxy.
//!
//! This is the whole point of the client: `frps` hands over a connection that
//! arrived from the internet, and the client joins it to whatever is listening
//! on `localIP:localPort`.
//!
//! Written for the memory budget rather than for throughput. The buffer is
//! 16 KiB to match `golib`'s `io.Join`, which is what the server uses at the
//! other end, and the two directions are driven from a single task so a
//! connection costs one task rather than two.
//!
//! The cost of that choice is real and worth stating: a stalled write in one
//! direction pauses the other, because there is one task. For a proxy carrying a
//! single request/response stream that is invisible, and the Go side accepts the
//! same coupling by drawing its buffers from a shared pool.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Result;
use crate::logging;

/// The copy buffer size, matching `golib`'s `io.Join`.
pub const BRIDGE_BUFFER_SIZE: usize = 16 * 1024;

/// How long to wait for the local service to accept a connection.
///
/// The Go client uses 10 seconds (`client/proxy/proxy.go`).
pub const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How a work connection's payload is wrapped, per proxy.
///
/// `useEncryption` and `useCompression` are per proxy, and the wrapping order is
/// load-bearing: encryption first, then compression, so the bytes on the wire are
/// `snappy(aes_cfb(plaintext))`. Getting it the other way round produces a stream
/// the server cannot read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkConnTransport {
    pub use_encryption: bool,
    pub use_compression: bool,
}

impl WorkConnTransport {
    /// Whether the connection needs any wrapping at all.
    pub fn is_plain(&self) -> bool {
        !self.use_encryption && !self.use_compression
    }
}

/// Copies bytes both ways until either side closes.
///
/// Returns `(work connection → local, local → work connection)` in bytes, which
/// is what the admin API reports as traffic in and out.
pub async fn join<A, B>(work: A, local: B, proxy_name: &str) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut work_read, mut work_write) = tokio::io::split(work);
    let (mut local_read, mut local_write) = tokio::io::split(local);

    // Two buffers rather than one, because `select!` keeps both reads in flight
    // and a single buffer cannot be borrowed by both. 32 KiB per live connection
    // still fits the budget: the target is about idle and light load, and a
    // connection carrying a bridged stream is where a second buffer earns it.
    let mut to_local_buffer = vec![0u8; BRIDGE_BUFFER_SIZE];
    let mut to_work_buffer = vec![0u8; BRIDGE_BUFFER_SIZE];
    let mut to_local = 0u64;
    let mut to_work = 0u64;

    loop {
        tokio::select! {
            read = work_read.read(&mut to_local_buffer) => {
                let read = read?;
                if read == 0 {
                    // The server is done. Half-close the local end, so a service
                    // that reads to EOF sees it, and stop.
                    let _ = local_write.shutdown().await;
                    break;
                }
                local_write.write_all(&to_local_buffer[..read]).await?;
                local_write.flush().await?;
                to_local += read as u64;
            }
            read = local_read.read(&mut to_work_buffer) => {
                let read = read?;
                if read == 0 {
                    let _ = work_write.shutdown().await;
                    break;
                }
                work_write.write_all(&to_work_buffer[..read]).await?;
                work_write.flush().await?;
                to_work += read as u64;
            }
        }
    }

    let _ = work_write.shutdown().await;
    let _ = local_write.shutdown().await;
    logging::debug(format!(
        "proxy {proxy_name}: connection closed, {to_local} bytes in, {to_work} bytes out"
    ));
    Ok((to_local, to_work))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn bytes_flow_both_ways_and_are_counted() {
        let (mut client_side, server_side) = tokio::io::duplex(4096);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A local service that echoes one message and then waits to be closed.
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
            socket.flush().await.unwrap();
            let mut drain = Vec::new();
            let _ = socket.read_to_end(&mut drain).await;
        });

        let local = TcpStream::connect(addr).await.unwrap();
        let bridge = tokio::spawn(async move { join(server_side, local, "test").await });

        client_side.write_all(b"ping").await.unwrap();
        client_side.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client_side.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");

        drop(client_side);
        let (to_local, to_work) = bridge.await.unwrap().unwrap();
        assert_eq!(to_local, 4);
        assert_eq!(to_work, 4);
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn a_payload_larger_than_the_buffer_arrives_whole() {
        let (mut client_side, server_side) = tokio::io::duplex(1 << 20);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let payload: Vec<u8> = (0..BRIDGE_BUFFER_SIZE * 3 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();

        let want = expected.len();
        let sink = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; want];
            socket.read_exact(&mut got).await.unwrap();
            got
        });

        let local = TcpStream::connect(addr).await.unwrap();
        let bridge = tokio::spawn(async move { join(server_side, local, "test").await });

        client_side.write_all(&payload).await.unwrap();
        client_side.flush().await.unwrap();
        drop(client_side);

        assert_eq!(sink.await.unwrap(), expected);
        let (to_local, _) = bridge.await.unwrap().unwrap();
        assert_eq!(to_local, expected.len() as u64);
    }

    /// A closed local port must surface as an error rather than a hang, so the
    /// work connection can be dropped and the client can carry on.
    #[tokio::test]
    async fn a_local_service_that_is_not_listening_fails_to_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);

        let result =
            tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(dead_addr)).await;
        assert!(matches!(result, Ok(Err(_))), "expected a refusal");
    }

    #[test]
    fn a_plain_transport_needs_no_wrapping() {
        assert!(WorkConnTransport::default().is_plain());
        assert!(!WorkConnTransport {
            use_encryption: true,
            use_compression: false,
        }
        .is_plain());
        assert!(!WorkConnTransport {
            use_encryption: false,
            use_compression: true,
        }
        .is_plain());
    }

    #[test]
    fn the_buffer_size_matches_golib() {
        // golib's io.Join uses 16 KiB; matching it keeps the two ends' memory
        // profiles symmetric.
        assert_eq!(BRIDGE_BUFFER_SIZE, 16 * 1024);
    }
}
