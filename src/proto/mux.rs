//! A yamux client, matching `github.com/fatedier/yamux` v0.2.0.
//!
//! `transport.tcpMux` defaults to **on**, so this is on the default path: every
//! logical connection the client makes — the control session, each work
//! connection, each visitor connection — is a stream over one TCP connection
//! instead of its own socket.
//!
//! It is written rather than taken from a crate because frp uses a fork with its
//! own defaults (`fatedier/yamux`), and a multiplexer that disagrees with the
//! peer about a window or a flag does not degrade — it corrupts the stream. The
//! pieces that matter, all pinned against that fork:
//!
//! * a 12-byte header, `version ‖ type ‖ flags ‖ streamID ‖ length`, all
//!   big-endian after the first two bytes;
//! * `initialStreamWindow` of 256 KiB per stream, updated by
//!   `(max - buffered) - current` once that reaches half the window;
//! * a stream is opened with a zero-length `WindowUpdate` carrying `SYN`, and
//!   acknowledged by one carrying `ACK`;
//! * the **client** takes odd stream ids, the server even ones;
//! * `KeepAliveInterval` decides the ping period, and a missed ping tears the
//!   session down rather than being retried.
//!
//! One deliberate difference: Go's `sendWindowUpdate` folds its own state
//! transitions into the flags of whatever frame it is sending, which can let a
//! zero-delta update through. Here the transitions are explicit, so the frames
//! on the wire are the same but the code does not depend on that subtlety.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

use crate::error::{Error, Result};

/// The only protocol version either side implements.
pub const PROTO_VERSION: u8 = 0;

/// Header size: version + type + flags + stream id + length.
pub const HEADER_SIZE: usize = 12;

/// `initialStreamWindow` from the Go fork, in bytes.
pub const INITIAL_STREAM_WINDOW: u32 = 256 * 1024;

/// `Config.MaxStreamWindowSize` as frp sets it, in bytes.
pub const MAX_STREAM_WINDOW: u32 = 6 * 1024 * 1024;

/// Frame types. `Data` and `WindowUpdate` share a handler on the Go side,
/// because both carry a stream id and a length.
pub mod frame_type {
    pub const DATA: u8 = 0;
    pub const WINDOW_UPDATE: u8 = 1;
    pub const PING: u8 = 2;
    pub const GO_AWAY: u8 = 3;
}

pub mod flags {
    pub const SYN: u16 = 1;
    pub const ACK: u16 = 2;
    pub const FIN: u16 = 4;
    pub const RST: u16 = 8;
}

/// `goAwayNormal`, the only code the client ever sends.
pub const GO_AWAY_NORMAL: u32 = 0;

/// Session tuning, mirroring `yamux.Config` as frp fills it in.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// How often to ping. `transport.tcpMuxKeepaliveInterval`, default 30s.
    pub keepalive_interval: Duration,
    /// How long a ping waits for its reply. `ConnectionWriteTimeout` in the Go
    /// fork, whose default is 10s — deliberately *not* the keepalive interval.
    pub connection_write_timeout: Duration,
    /// The per-stream receive window ceiling.
    pub max_stream_window: u32,
    /// How long to wait for an `ACK` before giving up on a stream open.
    pub stream_open_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            connection_write_timeout: Duration::from_secs(10),
            max_stream_window: MAX_STREAM_WINDOW,
            stream_open_timeout: Duration::from_secs(10),
        }
    }
}

/// A yamux session: one TCP connection carrying many streams.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl Session {
    /// Starts a client session over `socket`.
    ///
    /// Returns as soon as the background reader and writer are running; the
    /// first `OpenStream` or `accept` is what actually talks to the peer.
    pub fn client(socket: TcpStream, config: Config) -> Session {
        Self::new(socket, config, Role::Client)
    }

    /// A server session takes even stream ids, which is how the two ends avoid
    /// colliding. frp only ever uses this side inside tests.
    pub fn server(socket: TcpStream, config: Config) -> Session {
        Self::new(socket, config, Role::Server)
    }

    fn new(socket: TcpStream, config: Config, role: Role) -> Session {
        // The socket is split so the reader and writer never contend for it: the
        // reader only reads and the writer only writes, which is the whole point
        // of a multiplexer.
        let (read_half, write_half) = socket.into_split();
        let (send_tx, send_rx) = mpsc::channel::<Outbound>(64);
        let (accept_tx, accept_rx) = mpsc::channel::<Arc<StreamState>>(16);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let inner = Arc::new(Inner {
            send_tx,
            config,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(match role {
                Role::Client => 1,
                Role::Server => 2,
            }),
            shutdown: AtomicBool::new(false),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            shutdown_tx,
            next_ping_id: AtomicU32::new(0),
            pending_pings: Mutex::new(HashMap::new()),
        });

        let reader_inner = inner.clone();
        let reader = tokio::spawn(read_loop(reader_inner.clone(), read_half));
        let writer = tokio::spawn(write_loop(inner.clone(), write_half, send_rx, shutdown_rx));

        // Tie the tasks together: when the reader stops, for any reason, the
        // session is over and the writer has to stop too.
        tokio::spawn(async move {
            let _ = reader.await;
            reader_inner.shutdown();
            let _ = writer.await;
        });

        Session { inner }
    }

    /// Opens a new stream. Resolves once the peer acknowledges it.
    pub async fn open_stream(&self) -> Result<Stream> {
        if self.inner.shutdown.load(Ordering::Relaxed) {
            return Err(Error::protocol("yamux session is closed"));
        }

        let id = self.inner.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let state = Arc::new(StreamState::new(id, self.inner.clone()));

        self.inner
            .streams
            .lock()
            .expect("stream map poisoned")
            .insert(id, state.clone());

        // A new stream is announced by a zero-length window update carrying SYN.
        self.inner
            .send_frame(frame_type::WINDOW_UPDATE, flags::SYN, id, 0, &[])
            .await?;

        // Wait for the ACK. A peer that never replies is a dead peer, and the Go
        // side closes the session rather than waiting forever.
        let acked = tokio::time::timeout(
            self.inner.config.stream_open_timeout,
            state.established.notified(),
        )
        .await;
        match acked {
            Ok(()) => Ok(Stream { state }),
            Err(_) => {
                state.mark_reset();
                self.inner.forget_stream(id);
                Err(Error::protocol(format!(
                    "yamux stream {id} was not acknowledged within {:?}",
                    self.inner.config.stream_open_timeout
                )))
            }
        }
    }

    /// Waits for the peer to open a stream.
    pub async fn accept(&self) -> Result<Stream> {
        let mut rx = self.inner.accept_rx.lock().await;
        match rx.recv().await {
            Some(state) => Ok(Stream { state }),
            None => Err(Error::protocol("yamux session is closed")),
        }
    }

    /// Sends a `GoAway` and closes the underlying connection.
    pub async fn close(&self) {
        let _ = self
            .inner
            .send_frame(frame_type::GO_AWAY, 0, 0, GO_AWAY_NORMAL, &[])
            .await;
        self.inner.shutdown();
    }

    /// Whether the session has been torn down.
    pub fn is_closed(&self) -> bool {
        self.inner.shutdown.load(Ordering::Relaxed)
    }

    /// The number of streams currently open. Used by the low-memory tests.
    pub fn num_streams(&self) -> usize {
        self.inner
            .streams
            .lock()
            .expect("stream map poisoned")
            .len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// One frame queued for the writer task.
#[derive(Debug)]
struct Outbound {
    header: [u8; HEADER_SIZE],
    body: Vec<u8>,
}

impl Outbound {
    fn new(frame_type: u8, flags: u16, stream_id: u32, length: u32, body: Vec<u8>) -> Self {
        let mut header = [0u8; HEADER_SIZE];
        header[0] = PROTO_VERSION;
        header[1] = frame_type;
        header[2..4].copy_from_slice(&flags.to_be_bytes());
        header[4..8].copy_from_slice(&stream_id.to_be_bytes());
        header[8..12].copy_from_slice(&length.to_be_bytes());
        Self { header, body }
    }
}

/// State shared by a session and all of its streams.
struct Inner {
    send_tx: mpsc::Sender<Outbound>,
    config: Config,
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
    /// Client ids are odd, server ids even, so the two ends never collide.
    next_stream_id: AtomicU32,
    shutdown: AtomicBool,
    accept_tx: mpsc::Sender<Arc<StreamState>>,
    /// An async mutex, because `accept` holds it across the await on `recv` and
    /// a `std::sync::MutexGuard` cannot cross an await point.
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Arc<StreamState>>>,
    /// Notifies the writer task to stop.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Outgoing keepalive pings, keyed by the id echoed in the reply.
    next_ping_id: AtomicU32,
    pending_pings: Mutex<HashMap<u32, Arc<Notify>>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("yamux::Inner")
            .field("streams", &self.num_streams())
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Inner {
    async fn send_frame(
        &self,
        frame_type: u8,
        flags: u16,
        stream_id: u32,
        length: u32,
        body: &[u8],
    ) -> Result<()> {
        if self.shutdown.load(Ordering::Relaxed) && frame_type != frame_type::GO_AWAY {
            return Err(Error::protocol("yamux session is closed"));
        }
        self.send_tx
            .send(Outbound::new(
                frame_type,
                flags,
                stream_id,
                length,
                body.to_vec(),
            ))
            .await
            .map_err(|_| Error::protocol("yamux writer has stopped"))
    }

    fn num_streams(&self) -> usize {
        self.streams.lock().map(|s| s.len()).unwrap_or(0)
    }

    fn forget_stream(&self, id: u32) {
        self.streams
            .lock()
            .expect("stream map poisoned")
            .remove(&id);
    }

    /// Reserves an id for a keepalive ping.
    fn next_ping_id(&self) -> u32 {
        self.next_ping_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Waits for the reply to ping `id`. Callers race this against a timeout.
    async fn wait_for_ping(&self, id: u32) {
        let notify = {
            let mut pings = self.pending_pings.lock().expect("ping map poisoned");
            pings.entry(id).or_default().clone()
        };
        notify.notified().await;
    }

    /// Notes a ping reply, waking whoever is waiting on it.
    fn ping_received(&self, id: u32) {
        let notify = self
            .pending_pings
            .lock()
            .expect("ping map poisoned")
            .remove(&id);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    /// Tears the session down and wakes everything waiting on it.
    fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.shutdown_tx.send(true);
        // Wake every stream so no reader or writer blocks forever on a session
        // that will never deliver anything again.
        let streams: Vec<Arc<StreamState>> = self
            .streams
            .lock()
            .expect("stream map poisoned")
            .values()
            .cloned()
            .collect();
        for stream in streams {
            stream.mark_reset();
        }
        self.streams.lock().expect("stream map poisoned").clear();

        let pings: Vec<Arc<Notify>> = self
            .pending_pings
            .lock()
            .expect("ping map poisoned")
            .drain()
            .map(|(_, notify)| notify)
            .collect();
        for notify in pings {
            notify.notify_waiters();
        }
    }
}

/// Per-stream state.
#[derive(Debug)]
struct StreamState {
    id: u32,
    session: Arc<Inner>,
    /// Bytes received but not yet read. Bounded by the receive window, which is
    /// what stops a fast peer from growing it without limit.
    recv_buf: Mutex<VecDeque<u8>>,
    /// Signalled once the peer's ACK arrives.
    established: Notify,
    /// Receive window still advertised to the peer.
    recv_window: AtomicU32,
    /// Send window the peer has granted us.
    send_window: AtomicU32,
    /// The peer sent FIN.
    remote_closed: AtomicBool,
    /// We sent FIN.
    local_closed: AtomicBool,
    /// Either side reset, or the session died.
    reset: AtomicBool,
    /// The peer's SYN has been acknowledged.
    ack_sent: AtomicBool,
    /// The single reader task. One `Stream` is owned by one reader, so a waker
    /// for one consumer is enough, and it avoids the race a `Notify` would have
    /// between registering and checking the buffer.
    read_waker: Mutex<Option<Waker>>,
    /// The single writer task, woken when a window update grants credit.
    write_waker: Mutex<Option<Waker>>,
}

impl StreamState {
    fn new(id: u32, session: Arc<Inner>) -> Self {
        Self {
            id,
            session,
            recv_buf: Mutex::new(VecDeque::new()),
            established: Notify::new(),
            recv_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            send_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            remote_closed: AtomicBool::new(false),
            local_closed: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            ack_sent: AtomicBool::new(false),
            read_waker: Mutex::new(None),
            write_waker: Mutex::new(None),
        }
    }

    /// Registers the reader so `push_data` can wake it.
    fn register_read_waker(&self, waker: &Waker) {
        *self.read_waker.lock().expect("read waker poisoned") = Some(waker.clone());
    }

    /// Registers the writer so a window update can wake it.
    fn register_write_waker(&self, waker: &Waker) {
        *self.write_waker.lock().expect("write waker poisoned") = Some(waker.clone());
    }

    fn mark_reset(&self) {
        self.reset.store(true, Ordering::SeqCst);
        self.wake_reader();
        self.wake_writer();
        self.established.notify_waiters();
    }

    fn wake_reader(&self) {
        let waker = self.read_waker.lock().expect("read waker poisoned").take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn wake_writer(&self) {
        let waker = self
            .write_waker
            .lock()
            .expect("write waker poisoned")
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn mark_established(&self) {
        self.established.notify_waiters();
    }

    /// Queues received bytes, respecting the window the peer was promised.
    fn push_data(&self, data: &[u8]) -> Result<()> {
        let remaining = self.recv_window.load(Ordering::SeqCst);
        if data.len() as u32 > remaining {
            return Err(Error::protocol(format!(
                "yamux receive window exceeded on stream {} ({} left, {} sent)",
                self.id,
                remaining,
                data.len()
            )));
        }
        {
            let mut buf = self.recv_buf.lock().expect("recv buffer poisoned");
            buf.extend(data);
        }
        self.recv_window
            .fetch_sub(data.len() as u32, Ordering::SeqCst);
        self.wake_reader();
        Ok(())
    }

    fn grant_send_window(&self, delta: u32) {
        self.send_window.fetch_add(delta, Ordering::SeqCst);
        self.wake_writer();
    }

    /// Sends a window update if the peer is close to running out of credit.
    ///
    /// The threshold is Go's: an update only goes out once the delta reaches
    /// half the window, so a chatty stream does not emit one per read. The
    /// acknowledgement of an incoming stream is piggybacked onto the first such
    /// update, which is why `ack_sent` exists.
    async fn send_window_update_if_needed(&self) -> Result<()> {
        let buffered = self.recv_buf.lock().expect("recv buffer poisoned").len() as u32;
        let current = self.recv_window.load(Ordering::SeqCst);
        let max = self.session.config.max_stream_window;
        let delta = (max - buffered).saturating_sub(current);

        let needs_ack = !self.ack_sent.swap(true, Ordering::SeqCst);
        if delta < max / 2 && !needs_ack {
            return Ok(());
        }
        self.recv_window.fetch_add(delta, Ordering::SeqCst);
        let flags = if needs_ack { flags::ACK } else { 0 };
        self.session
            .send_frame(frame_type::WINDOW_UPDATE, flags, self.id, delta, &[])
            .await
    }
}

/// A bidirectional byte stream over a yamux session.
#[derive(Debug)]
pub struct Stream {
    state: Arc<StreamState>,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.state.id
    }

    /// Whether the peer or the session has torn this stream down.
    pub fn is_reset(&self) -> bool {
        self.state.reset.load(Ordering::SeqCst)
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let state = &self.state;

        if state.reset.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "yamux stream reset",
            )));
        }

        let drained = {
            let mut queue = state.recv_buf.lock().expect("recv buffer poisoned");
            if queue.is_empty() {
                false
            } else {
                let take = buf.remaining().min(queue.len());
                let chunk: Vec<u8> = queue.drain(..take).collect();
                drop(queue);
                buf.put_slice(&chunk);
                true
            }
        };

        if drained {
            return Poll::Ready(Ok(()));
        }

        // Nothing buffered. A closed peer means end of stream; otherwise park
        // until `push_data` or a reset wakes us.
        if state.remote_closed.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }

        state.register_read_waker(cx.waker());
        // Re-check after registering: data may have landed in between, and the
        // waker would otherwise never fire for it.
        let ready = state.reset.load(Ordering::SeqCst)
            || state.remote_closed.load(Ordering::SeqCst)
            || !state
                .recv_buf
                .lock()
                .expect("recv buffer poisoned")
                .is_empty();
        if ready {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let state = self.state.clone();

        if state.reset.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "yamux stream reset",
            )));
        }
        if state.local_closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "yamux stream is closed for writing",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let window = state.send_window.load(Ordering::SeqCst);
        if window == 0 {
            // Wait for the peer to extend the window.
            state.register_write_waker(cx.waker());
            if state.send_window.load(Ordering::SeqCst) > 0 {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }

        let take = (window as usize).min(buf.len());
        // The frame queue is bounded, so a full queue means the socket is the
        // bottleneck. Back-pressure the caller rather than growing the queue.
        match state.session.send_tx.try_send(Outbound::new(
            frame_type::DATA,
            0,
            state.id,
            take as u32,
            buf[..take].to_vec(),
        )) {
            Ok(()) => {
                state.send_window.fetch_sub(take as u32, Ordering::SeqCst);
                Poll::Ready(Ok(take))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "yamux session is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writer task flushes as it drains the queue; there is nothing
        // stream-local to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let state = self.state.clone();
        if state.local_closed.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        // Queue the FIN directly rather than awaiting the writer task, which may
        // itself be blocked on this stream.
        match state.session.send_tx.try_send(Outbound::new(
            frame_type::WINDOW_UPDATE,
            flags::FIN,
            state.id,
            0,
            Vec::new(),
        )) {
            Ok(()) => {
                state.local_closed.store(true, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "yamux session is closed",
            ))),
        }
    }
}

/// Reads frames off the socket and dispatches them.
async fn read_loop(inner: Arc<Inner>, mut socket: tokio::net::tcp::OwnedReadHalf) {
    let mut header = [0u8; HEADER_SIZE];
    // Subscribed once rather than per frame. `changed()` is level-triggered for
    // this purpose: before the session dies it never completes, and once it has
    // died it completes every time it is polled.
    let mut shutdown_rx = inner.shutdown_tx.subscribe();
    loop {
        if inner.shutdown.load(Ordering::Relaxed) {
            return;
        }
        if let Err(err) = socket.read_exact(&mut header).await {
            if err.kind() != io::ErrorKind::UnexpectedEof {
                crate::logging::debug(format!("yamux: read failed: {err}"));
            }
            inner.shutdown();
            return;
        }

        if header[0] != PROTO_VERSION {
            crate::logging::warn(format!("yamux: peer sent protocol version {}", header[0]));
            inner.shutdown();
            return;
        }

        let frame_type = header[1];
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let stream_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);

        // Everything below can park the reader — the frame queue is bounded, so
        // `send_frame` waits when the socket is the bottleneck, and a data frame
        // reads its body off the socket. A session that dies while this is parked
        // cannot make the read return on its own, so the shutdown has to win the
        // race from the outside; otherwise the reader is left holding the write
        // half it will never use again.
        let step = async {
            match frame_type {
                frame_type::DATA | frame_type::WINDOW_UPDATE => {
                    handle_stream_frame(&inner, &mut socket, frame_type, flags, stream_id, length)
                        .await
                }
                frame_type::PING => {
                    // A SYN is a query that must be echoed; an ACK answers ours.
                    if flags & flags::SYN != 0 {
                        inner
                            .send_frame(frame_type::PING, flags::ACK, 0, length, &[])
                            .await
                    } else {
                        inner.ping_received(length);
                        Ok(())
                    }
                }
                frame_type::GO_AWAY => {
                    crate::logging::info("yamux: peer went away");
                    Err(Error::protocol("yamux: peer went away"))
                }
                other => Err(Error::protocol(format!(
                    "yamux: unknown frame type {other}"
                ))),
            }
        };

        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => return,
            result = step => {
                if let Err(err) = result {
                    crate::logging::warn(format!("yamux: {err}"));
                    inner.shutdown();
                    return;
                }
            }
        }
    }
}

async fn handle_stream_frame(
    inner: &Arc<Inner>,
    socket: &mut tokio::net::tcp::OwnedReadHalf,
    frame_type: u8,
    frame_flags: u16,
    stream_id: u32,
    length: u32,
) -> Result<()> {
    // A SYN opens a stream we did not ask for. The map lock is released before
    // the await below: holding a `MutexGuard` across an await would make the
    // reader task non-`Send`.
    let opened = if frame_flags & flags::SYN != 0 {
        let state = Arc::new(StreamState::new(stream_id, inner.clone()));
        let duplicate = {
            let mut streams = inner.streams.lock().expect("stream map poisoned");
            streams.insert(stream_id, state.clone()).is_some()
        };
        if duplicate {
            return Err(Error::protocol(format!(
                "yamux: duplicate stream id {stream_id}"
            )));
        }
        Some(state)
    } else {
        None
    };

    if let Some(state) = opened {
        // Acknowledge the stream before handing it to the application: the peer
        // is waiting on that ACK to consider its `OpenStream` finished.
        let ack = state.clone();
        if inner.accept_tx.send(state).await.is_err() {
            return Err(Error::protocol("yamux: accept queue closed"));
        }
        ack.send_window_update_if_needed().await?;
    }

    let state = inner
        .streams
        .lock()
        .expect("stream map poisoned")
        .get(&stream_id)
        .cloned();

    let Some(state) = state else {
        // Not a stream we know about: drain the payload so the stream stays in
        // sync, and carry on. The Go side behaves the same way.
        if frame_type == frame_type::DATA && length > 0 {
            let mut discard = vec![0u8; length as usize];
            socket.read_exact(&mut discard).await?;
        }
        return Ok(());
    };

    if frame_flags & flags::RST != 0 {
        state.mark_reset();
        inner.forget_stream(stream_id);
        return Ok(());
    }

    if frame_type == frame_type::WINDOW_UPDATE {
        state.grant_send_window(length);
        // A window update with no data can still carry the ACK for our SYN.
        if frame_flags & flags::ACK != 0 {
            state.mark_established();
        }
        if frame_flags & flags::FIN != 0 {
            state.remote_closed.store(true, Ordering::SeqCst);
            state.wake_reader();
        }
        return Ok(());
    }

    // Data. The payload has to be read whatever else the frame says, or the
    // byte stream desynchronizes.
    let mut body = vec![0u8; length as usize];
    if length > 0 {
        socket.read_exact(&mut body).await?;
    }

    if frame_flags & flags::ACK != 0 {
        state.mark_established();
    }
    if length > 0 {
        state.push_data(&body)?;
    }
    if frame_flags & flags::FIN != 0 {
        state.remote_closed.store(true, Ordering::SeqCst);
        state.wake_reader();
    }

    // Replenish the peer's credit once we are far enough along.
    state.send_window_update_if_needed().await?;

    Ok(())
}

/// Drains the outbound queue onto the socket.
async fn write_loop(
    inner: Arc<Inner>,
    mut socket: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Outbound>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut ping_timer = tokio::time::interval(inner.config.keepalive_interval);
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately; the session is not established yet, so
    // skip it.
    ping_timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.changed() => {
                // Best effort: flush whatever is queued before closing, so a
                // GoAway the caller just sent actually reaches the peer.
                while let Ok(frame) = rx.try_recv() {
                    if write_frame(&mut socket, &frame).await.is_err() {
                        break;
                    }
                }
                let _ = socket.shutdown().await;
                return;
            }

            frame = rx.recv() => {
                let Some(frame) = frame else {
                    let _ = socket.shutdown().await;
                    return;
                };
                if let Err(err) = write_frame(&mut socket, &frame).await {
                    crate::logging::debug(format!("yamux: write failed: {err}"));
                    inner.shutdown();
                    return;
                }
            }

            _ = ping_timer.tick() => {
                // `KeepAliveInterval` decides how often to ping;
                // `ConnectionWriteTimeout` decides how long to wait for the
                // reply before treating the peer as gone. Conflating the two
                // would make the timeout depend on the ping period, which is not
                // what the Go fork does — and the failure mode is a session that
                // dies exactly one interval after it comes up.
                //
                // The wait happens in a task of its own, and that is not a style
                // choice. Awaiting the reply here would park this loop, and this
                // loop is the only thing that ever consumes the outbound queue —
                // so the ping would sit in the queue unsent and wait for a reply
                // to something the peer never received. It has to be written
                // before anything can be waited on.
                let id = inner.next_ping_id();
                let sent = inner
                    .send_frame(frame_type::PING, flags::SYN, 0, id, &[])
                    .await;
                if sent.is_err() {
                    inner.shutdown();
                    return;
                }
                let waiter = inner.clone();
                let timeout = inner.config.connection_write_timeout;
                tokio::spawn(async move {
                    if tokio::time::timeout(timeout, waiter.wait_for_ping(id))
                        .await
                        .is_err()
                    {
                        crate::logging::warn(format!(
                            "yamux: keepalive ping {id} went unanswered; closing the session"
                        ));
                        waiter.shutdown();
                    }
                });
            }
        }
    }
}

async fn write_frame(
    socket: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &Outbound,
) -> io::Result<()> {
    socket.write_all(&frame.header).await?;
    if !frame.body.is_empty() {
        socket.write_all(&frame.body).await?;
    }
    socket.flush().await
}

#[cfg(test)]
#[path = "mux_tests.rs"]
mod mux_tests;
