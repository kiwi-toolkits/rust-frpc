#[cfg(test)]
mod tests {
    use super::super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Two sessions over a real loopback socket. `Session` needs a `TcpStream`,
    /// and a real socket is the honest thing to test a byte protocol against
    /// anyway.
    async fn pair() -> (Session, Session) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_socket = TcpStream::connect(addr).await.unwrap();
        let server_socket = accept.await.unwrap();
        (
            Session::client(client_socket, Config::default()),
            Session::server(server_socket, Config::default()),
        )
    }

    /// Reads exactly `n` bytes, failing rather than hanging if the stream dies.
    async fn read_exact(stream: &mut Stream, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
        Ok(buf)
    }

    #[tokio::test]
    async fn a_stream_carries_bytes_in_one_direction() {
        let (client, server) = pair().await;
        let acceptor =
            tokio::spawn(async move { read_exact(&mut server.accept().await.unwrap(), 5).await });

        let mut stream = client.open_stream().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        assert_eq!(acceptor.await.unwrap().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn a_stream_carries_bytes_in_both_directions() {
        let (client, server) = pair().await;
        let echo = tokio::spawn(async move {
            let mut stream = server.accept().await.unwrap();
            let payload = read_exact(&mut stream, 4).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut stream = client.open_stream().await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        assert_eq!(read_exact(&mut stream, 4).await.unwrap(), b"ping");
        echo.await.unwrap();
    }

    /// Streams must not block each other, which is the entire point of the
    /// multiplexer: the acceptor stays live while new streams are opened.
    #[tokio::test]
    async fn several_streams_are_independent() {
        let (client, server) = pair().await;

        let acceptor = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..3 {
                let mut stream = server.accept().await.unwrap();
                seen.push(read_exact(&mut stream, 3).await.unwrap());
            }
            seen.sort();
            seen
        });

        for payload in [b"aaa", b"bbb", b"ccc"] {
            let mut stream = client.open_stream().await.unwrap();
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
        }

        assert_eq!(
            acceptor.await.unwrap(),
            vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec()]
        );
    }

    /// A session must survive a keepalive cycle.
    ///
    /// This is the regression test for a liveness bug that made every session die
    /// one keepalive interval after it was established: the ping was enqueued and
    /// then waited on inside the same `select` arm that is the only consumer of the
    /// outbound queue, so it was never actually written and the reply it was
    /// waiting for could not arrive. Both ends ping here, so a ping left unsent is
    /// fatal.
    ///
    /// Both timeouts are shortened, and both are needed: the write timeout is what
    /// makes the broken version fail inside this test's lifetime rather than after
    /// the default ten seconds.
    #[tokio::test]
    async fn a_session_survives_a_keepalive_cycle() {
        let keepalive = Duration::from_millis(50);
        let config = Config {
            keepalive_interval: keepalive,
            connection_write_timeout: keepalive,
            ..Config::default()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_socket = TcpStream::connect(addr).await.unwrap();
        let server_socket = accept.await.unwrap();
        let client = Session::client(client_socket, config);
        let _server = Session::server(server_socket, config);

        // Several intervals, so a ping that never leaves the queue has had every
        // chance to tear the session down.
        tokio::time::sleep(keepalive * 6).await;

        let mut stream = client
            .open_stream()
            .await
            .expect("the session should still be alive after its keepalives");
        stream.write_all(b"alive").await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn client_stream_ids_are_odd_and_increase() {
        let (client, _server) = pair().await;
        let first = client.open_stream().await.unwrap();
        assert_eq!(first.id() % 2, 1);
        assert!(first.id() >= 1);
    }

    /// A payload far larger than one window has to be paced by the peer's window
    /// updates rather than dropped or truncated.
    #[tokio::test]
    async fn a_transfer_larger_than_the_window_completes() {
        let (client, server) = pair().await;
        let size = (INITIAL_STREAM_WINDOW as usize) * 3 + 1234;

        let acceptor = tokio::spawn(async move {
            read_exact(&mut server.accept().await.unwrap(), size)
                .await
                .unwrap()
        });

        let mut stream = client.open_stream().await.unwrap();
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        assert_eq!(acceptor.await.unwrap(), expected);
    }

    /// Shutting a session down must wake a stream parked on an empty buffer, or
    /// the reader task leaks.
    #[tokio::test]
    async fn closing_the_session_wakes_a_blocked_reader() {
        let (client, server) = pair().await;
        let mut stream = client.open_stream().await.unwrap();
        let _accepted = server.accept().await.unwrap();

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            stream.read_exact(&mut buf).await
        });
        // Give the reader a moment to park on the empty buffer.
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.close().await;

        let result = tokio::time::timeout(Duration::from_secs(2), reader).await;
        assert!(result.is_ok(), "the reader should have been woken");
    }

    /// A FIN ends the peer's read with an EOF rather than an error.
    #[tokio::test]
    async fn a_fin_ends_the_peers_read() {
        let (client, server) = pair().await;
        let mut stream = client.open_stream().await.unwrap();

        let peer = tokio::spawn(async move {
            let mut accepted = server.accept().await.unwrap();
            let mut buf = Vec::new();
            accepted.read_to_end(&mut buf).await.unwrap();
            buf
        });

        stream.write_all(b"before fin").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        assert_eq!(peer.await.unwrap(), b"before fin");
    }

    #[test]
    fn the_flag_values_match_the_go_fork() {
        assert_eq!(flags::SYN, 1);
        assert_eq!(flags::ACK, 2);
        assert_eq!(flags::FIN, 4);
        assert_eq!(flags::RST, 8);
    }

    #[test]
    fn the_window_constants_match_the_go_fork() {
        assert_eq!(INITIAL_STREAM_WINDOW, 256 * 1024);
        assert_eq!(MAX_STREAM_WINDOW, 6 * 1024 * 1024);
        assert_eq!(HEADER_SIZE, 12);
        assert_eq!(PROTO_VERSION, 0);
        assert_eq!(GO_AWAY_NORMAL, 0);
    }
}
