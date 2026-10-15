//! The control loop: registering proxies, serving work connections, heartbeats.
//!
//! This is where the client becomes useful. After the login the conversation
//! runs in both directions at once and neither side waits for the other:
//!
//! * the client announces every enabled proxy with `NewProxy` and matches the
//!   `NewProxyResp` that comes back;
//! * `frps` sends `ReqWorkConn` whenever it has a user connection waiting, and
//!   the client answers by opening a fresh *logical* connection, sending
//!   `NewWorkConn` on it, and reading back the `StartWorkConn` that names the
//!   proxy it belongs to;
//! * the client sends `Ping` on its own timer and expects `Pong`.
//!
//! That is why the session is split into a read half and a write half, and why the
//! read half lives in its own task: a loop that only reads cannot send a
//! heartbeat, and a loop parked in a read cannot answer a work-connection request
//! either. Nothing here waits on the server if it can help it — `StartWorkConn`
//! in particular arrives only when a user connection takes the pooled connection,
//! so the whole work-connection exchange runs detached.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::config::{ClientConfig, ProxyConfig};
use crate::crypto::auth_key;
use crate::error::{Error, Result};
use crate::logging;
use crate::msg::{CloseProxy, Message, NewProxyResp, NewWorkConn, Ping};
use crate::naming;
use crate::proto::connector::is_retryable;
use crate::proto::{Connector, LogicalConn};

use super::bridge::{self, WorkConnTransport};
use super::login::{signs_heartbeats, signs_new_work_conns};
use super::proxy::to_new_proxy;
use super::rename::{self, Candidate};
use super::session::{SessionControl, SessionEvents};

/// How long to wait for a `NewProxyResp` before announcing the proxy again.
///
/// The Go client uses 20 seconds (`client/proxy/proxy_wrapper.go`).
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(20);

/// How often unacknowledged proxies are re-announced.
///
/// The Go client uses 3 seconds (`client/proxy/proxy_wrapper.go`).
pub const STATUS_CHECK_INTERVAL: Duration = Duration::from_secs(3);

/// How many messages the reader task may have read but not yet handled.
///
/// Deep enough that the reader keeps the socket drained while the loop is busy
/// with a work connection, shallow enough that a stalled loop stops reading
/// rather than buffering without bound.
const READ_QUEUE: usize = 32;

/// How often the admin API's snapshot is refreshed.
///
/// The proxy phases change on a message and are published immediately, so this
/// timer only exists so a session that stops answering cannot leave a stale
/// "running" in the admin API forever. The traffic counters are read live rather
/// than through the snapshot.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(1);

/// How often a UDP work connection tells the server it is still wanted.
///
/// The server closes a UDP work connection after 60 seconds without a message, so
/// the Go client pings every 30 (`client/proxy/udp.go`). A UDP tunnel is idle
/// whenever nobody is using it, which is most of the time.
pub(crate) const UDP_WORK_CONN_HEARTBEAT: Duration = Duration::from_secs(30);

/// The lifecycle of a proxy, matching the Go wrapper's phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPhase {
    /// Configured, not yet announced.
    New,
    /// Announced, waiting for the server's answer.
    WaitStart,
    /// Registered and serving.
    Running,
    /// The server refused it. Re-announced after [`REGISTER_TIMEOUT`].
    StartError,
}

impl ProxyPhase {
    /// The string the admin API reports.
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyPhase::New => "new",
            ProxyPhase::WaitStart => "wait start",
            ProxyPhase::Running => "running",
            ProxyPhase::StartError => "start error",
        }
    }
}

/// What the client knows about one proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyStatus {
    /// The configured name, without the user prefix.
    pub name: String,
    pub proxy_type: &'static str,
    pub phase: ProxyPhase,
    /// Filled in from `NewProxyResp`.
    pub remote_addr: String,
    /// Why the last attempt failed, if it did.
    pub error: String,
}

/// The snapshot the admin API builds `/api/status` from.
///
/// A deliberate copy rather than a borrow: the control loop owns the live state
/// and is not reachable from the admin server's task, so the two talk through a
/// `watch` channel carrying whole snapshots. The state is a handful of small
/// strings per proxy, so a copy per change is cheaper than the locking the
/// alternative would need.
///
/// The traffic counters are deliberately *not* here. They move in the
/// per-connection tasks, and reading them through a snapshot would mean a poll
/// could report a connection that had already closed — see [`Traffic`], which the
/// admin API holds directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// The proxies that should be running, in config order.
    pub proxies: Vec<ProxyStatus>,
    /// The `localIP:localPort` each one targets.
    pub local_addrs: BTreeMap<String, String>,
    /// The plugin type each one uses, empty when there is none.
    pub plugins: BTreeMap<String, String>,
    /// Whether the control session is currently established.
    pub connected: bool,
}

/// Something the loop reports to whoever is observing it.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// One bridged connection finished.
    ConnectionClosed {
        proxy_name: String,
        bytes_to_local: u64,
        bytes_to_work: u64,
    },
}

/// The live traffic counters, shared with the per-connection tasks.
///
/// Behind atomics rather than sent through the event channel because the admin
/// API wants a running total: an event per closed connection is fine for a log
/// line, but a status poll that had to drain a queue to get a number would report
/// whatever happened to be in it.
#[derive(Debug, Default)]
pub struct Traffic {
    to_local: AtomicU64,
    to_work: AtomicU64,
    closed: AtomicU64,
}

impl Traffic {
    /// Records one finished connection.
    pub fn record(&self, to_local: u64, to_work: u64) {
        self.to_local.fetch_add(to_local, Ordering::Relaxed);
        self.to_work.fetch_add(to_work, Ordering::Relaxed);
        self.closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_local(&self) -> u64 {
        self.to_local.load(Ordering::Relaxed)
    }

    pub fn to_work(&self) -> u64 {
        self.to_work.load(Ordering::Relaxed)
    }

    pub fn closed(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }
}

/// The task that reads the control connection, and the queue it feeds.
///
/// Dropping this aborts the read. That matters on the shutdown path: a read
/// parked on a live connection would otherwise keep the task — and the session
/// it borrows — alive after the loop has finished with it.
struct ReaderTask {
    rx: mpsc::Receiver<Result<Message>>,
    task: tokio::task::JoinHandle<()>,
}

impl ReaderTask {
    /// The next message, or `None` once the connection has ended.
    async fn recv(&mut self) -> Option<Result<Message>> {
        self.rx.recv().await
    }
}

impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What a proxy is registered as, which is not always what the config says.
///
/// The configured name is the key everywhere an operator looks — the status map,
/// the admin API, the log prefix. The *candidate* is what `NewProxy` carries, and
/// the rename-retry strategy moves it. They differ only after a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Registered {
    configured: String,
    candidate: Candidate,
    /// How many times the current candidate has been tried and refused.
    tries: u32,
    /// The name `frps` last confirmed, if any. Only this can be closed.
    acked: Option<String>,
    /// When the conflict path may send again, or `None` to use the ordinary
    /// [`REGISTER_TIMEOUT`].
    ///
    /// Conflicts pace themselves: three seconds a step, sixty before a new
    /// cycle. An ordinary start error waits twenty. Keeping the two in one field
    /// is what stops either from delaying the other.
    retry_at: Option<Instant>,
}

impl Registered {
    /// Whether `local_name` is a name this proxy has answered to.
    ///
    /// Three of them, because a response can be in flight while the name
    /// changes: the candidate being tried now, the configured name, and whatever
    /// the server last confirmed.
    fn answers_to(&self, local_name: &str) -> bool {
        local_name == self.candidate.name(&self.configured)
            || local_name == self.configured
            || self.acked.as_deref() == Some(local_name)
    }
}

/// What a failed registration asks the loop to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictAction {
    /// Nothing of its own: the ordinary retry timer owns this proxy.
    Leave,
    /// Try the same name again after `delay`.
    RetrySame { delay: Duration },
    /// Try under a new candidate after `delay`.
    RetryAs {
        candidate: Candidate,
        delay: Duration,
    },
}

/// Whether a failed registration is really this client's own duplicate coming
/// back.
///
/// `frps` refuses a name that is in use **without checking who holds it**
/// (`PxyManager.Exist`), so a second `NewProxy` for a name that already succeeded
/// is answered with `already exists`. The retry timer can produce exactly that,
/// because it fires on a three-second tick and the answer to the first attempt
/// may still be queued. Treating it as a conflict would rename a tunnel that is
/// working, which is the worst answer available — hence a predicate of its own,
/// named after what it is for.
fn is_our_own_duplicate(phase: ProxyPhase, error: &str) -> bool {
    phase == ProxyPhase::Running && rename::conflicts(error)
}

/// Decides whether a failed registration should be retried, and under what name.
///
/// Pulled out of the loop so it can be tested: `Control` cannot be built without
/// a live session, and this is the part with the sequence in it.
///
/// `running` is the phase *before* this failure was recorded. A conflict on a
/// proxy that is already running is the client's own duplicate registration
/// coming back — `frps` refuses a name that is in use without checking who owns
/// it — and renaming a working tunnel because of it would be the worst possible
/// response. See the caller, which drops that case before getting here.
fn on_start_error(
    registered: &mut Registered,
    rename_enabled: bool,
    error: &str,
) -> ConflictAction {
    if !rename_enabled || !rename::conflicts(error) {
        return ConflictAction::Leave;
    }

    registered.tries += 1;
    if registered.tries < registered.candidate.tries_allowed() {
        return ConflictAction::RetrySame {
            delay: rename::CONFLICT_RETRY_DELAY,
        };
    }

    registered.tries = 0;
    registered.candidate = rename::advance(registered.candidate);
    ConflictAction::RetryAs {
        candidate: registered.candidate,
        delay: rename::delay_after_advancing(registered.candidate),
    }
}

/// The control loop.
pub struct Control {
    config: ClientConfig,
    control: SessionControl,
    /// The read half of the session, until [`Control::spawn_reader`] moves it
    /// into the reader task.
    events: Option<SessionEvents>,
    /// Cloned out of the session, because the read half is borrowed for the whole
    /// of `recv` and a work connection has to be opened while it is.
    connector: Connector,
    /// The framing work connections must match.
    codec: crate::proto::Codec,
    /// The session's run id, which every `NewWorkConn` has to carry.
    run_id: String,
    /// Per-proxy state, keyed by the configured name.
    statuses: BTreeMap<String, ProxyStatus>,
    /// The proxies that should run, in config order.
    ///
    /// Behind an `Arc` so the per-connection task can look its own proxy up
    /// without copying the whole list.
    proxies: Arc<[ProxyConfig]>,
    /// What each proxy is currently registered as, parallel to `proxies`.
    names: Vec<Registered>,
    /// The same list, published for the work-connection tasks.
    ///
    /// A `watch` rather than a copy handed over at spawn time, because a work
    /// connection is not used when it is opened. `frps` pools it — `poolCount`
    /// of them are held ready — and the `StartWorkConn` that names a proxy comes
    /// back only when a user takes one out of that pool, which can be minutes
    /// later and after a rename. A task that resolved against the list it was
    /// spawned with would look up a name that is no longer current and drop the
    /// connection, leaving the user hanging with a warning to show for it.
    ///
    /// The task reads this once, when the answer arrives, and the guard is a
    /// `Ref` held for a clone of an `Arc` — never across an `.await`. That
    /// restraint matters more here than elsewhere: `run` is awaited rather than
    /// spawned and so carries no `Send` bound, which means a guard held across
    /// an await would stall the executor instead of failing to compile.
    names_tx: watch::Sender<Arc<[Registered]>>,
    /// When each proxy was last announced, for the retry timer.
    announced_at: BTreeMap<String, Instant>,
    /// Set by the read half when a `Pong` arrives.
    last_pong: Option<Instant>,
    /// Where to publish the state the admin API serves, if anyone is listening.
    status_tx: Option<watch::Sender<StatusSnapshot>>,
    /// The running traffic totals.
    traffic: Arc<Traffic>,
}

impl Control {
    /// Builds the loop from a split session.
    pub fn new(config: ClientConfig, control: SessionControl, events: SessionEvents) -> Self {
        Self::with_observer(config, control, events, None, Arc::new(Traffic::default()))
    }

    /// The same, publishing state to an admin API.
    pub fn with_observer(
        config: ClientConfig,
        control: SessionControl,
        events: SessionEvents,
        status_tx: Option<watch::Sender<StatusSnapshot>>,
        traffic: Arc<Traffic>,
    ) -> Self {
        // `Connector` is cheap to clone: the multiplexed variant shares one
        // session behind an `Arc`.
        let connector = events.connector().clone();
        let codec = control.codec();
        let run_id = events.run_id().to_string();
        let proxies: Vec<ProxyConfig> = config
            .proxies
            .iter()
            .filter(|proxy| proxy.is_enabled(&config.common.start))
            .filter(|proxy| {
                // A proxy whose local side this client cannot run is reported and
                // left out, rather than taking the whole config down with it. One
                // unimplemented plugin should not cost an operator every other
                // tunnel in the file — and `--check-config` stays the way to find
                // out about it before deploying.
                let runnable = proxy.is_runnable();
                if !runnable {
                    logging::warn(format!(
                        "proxy {} is skipped: {}",
                        proxy.name,
                        proxy.unsupported_reason()
                    ));
                }
                runnable
            })
            .cloned()
            .collect();

        let statuses = proxies
            .iter()
            .map(|proxy| {
                (
                    proxy.name.clone(),
                    ProxyStatus {
                        name: proxy.name.clone(),
                        proxy_type: proxy.type_name(),
                        phase: ProxyPhase::New,
                        remote_addr: String::new(),
                        error: String::new(),
                    },
                )
            })
            .collect();

        let names: Vec<Registered> = proxies
            .iter()
            .map(|proxy| Registered {
                configured: proxy.name.clone(),
                candidate: Candidate::Original,
                tries: 0,
                acked: None,
                retry_at: None,
            })
            .collect();
        let (names_tx, _names_rx) = watch::channel::<Arc<[Registered]>>(names.clone().into());

        Self {
            config,
            control,
            events: Some(events),
            connector,
            codec,
            run_id,
            statuses,
            proxies: proxies.into(),
            names,
            names_tx,
            announced_at: BTreeMap::new(),
            last_pong: None,
            status_tx,
            traffic,
        }
    }

    /// The current state of every proxy, for the admin API.
    pub fn statuses(&self) -> &BTreeMap<String, ProxyStatus> {
        &self.statuses
    }

    /// One proxy's status, for `/api/proxy/{name}/config` and friends.
    pub fn status_of(&self, name: &str) -> Option<&ProxyStatus> {
        self.statuses.get(name)
    }

    /// Registers every enabled proxy, then serves until the control connection
    /// ends, the client is asked to stop, or the session is asked to restart.
    ///
    /// Two shutdown channels rather than one because they mean different things
    /// to the caller: `shutdown` ends the client, `restart` ends only this session
    /// so the operator's config change can be applied over a fresh one. Both leave
    /// through the same door, where the proxies are deregistered.
    pub async fn run(
        mut self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        mut restart: tokio::sync::watch::Receiver<bool>,
        events: Option<mpsc::Sender<ControlEvent>>,
    ) -> Result<()> {
        logging::info(format!(
            "proxy added: {}",
            self.proxies
                .iter()
                .map(|proxy| proxy.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));

        for index in 0..self.proxies.len() {
            if let Err(err) = self.announce(index).await {
                logging::warn(format!(
                    "could not announce proxy {}: {err}",
                    self.proxies[index].name
                ));
            }
        }
        // The admin API can be polled before a proxy's answer arrives, so the
        // first snapshot goes out as soon as the announcements are on the wire.
        self.publish();

        let mut status_tick = tokio::time::interval(STATUS_CHECK_INTERVAL);
        status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut publish_tick = tokio::time::interval(PUBLISH_INTERVAL);
        publish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // The application-level heartbeat is off by default because yamux does
        // its own. A non-positive value means exactly that, and the timer is then
        // a future that never completes.
        let heartbeat_interval = self.heartbeat_interval();
        let mut heartbeat = heartbeat_interval.map(tokio::time::interval);
        if let Some(tick) = heartbeat.as_mut() {
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        }
        let heartbeat_timeout = self.heartbeat_timeout();
        let mut last_pong = Instant::now();

        // The read half runs in its own task and feeds a queue.
        //
        // The reason is a borrow, and it is the whole shape of this loop: a single
        // `recv` on the session borrows the session for the duration of the await,
        // so a loop parked in it could not also send a heartbeat. The Go client
        // sidesteps this by running its dispatcher in its own goroutine and
        // posting to handlers; this queue is the same idea with a bound.
        let mut incoming = self.spawn_reader();

        // Visitors run for the life of the session. A visitor's local listener and
        // its handshake have nothing to do with the work-connection pool, so they
        // are started here and dropped when the session ends — which is also what
        // closes their ports on a shutdown.
        let _visitors = super::visitor::start_all(
            &self.config,
            self.connector.clone(),
            self.codec,
            &self.run_id,
            self.traffic.clone(),
        )
        .await;

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }

                changed = restart.changed() => {
                    if changed.is_err() || *restart.borrow() {
                        break;
                    }
                }

                read = incoming.recv() => {
                    let Some(read) = read else {
                        return Err(Error::protocol("the control connection was closed"));
                    };
                    let message = read?;
                    self.handle(message, &events).await?;
                    if let Some(at) = self.last_pong.take() {
                        last_pong = at;
                    }
                }

                _ = async {
                    match heartbeat.as_mut() {
                        Some(tick) => { tick.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(timeout) = heartbeat_timeout {
                        if last_pong.elapsed() > timeout {
                            return Err(Error::protocol(format!(
                                "the server sent no Pong for {timeout:?}; the control connection is dead"
                            )));
                        }
                    }
                    self.send_ping().await?;
                }

                _ = status_tick.tick() => {
                    self.retry_pending().await;
                }

                // The traffic counters move outside this loop, so the snapshot
                // is refreshed on a timer rather than only on a message.
                _ = publish_tick.tick() => {
                    self.publish();
                }
            }
        }

        self.deregister_all().await;
        Ok(())
    }

    /// Publishes the current state to the admin API, if one is attached.
    fn publish(&self) {
        let Some(status_tx) = self.status_tx.as_ref() else {
            return;
        };
        status_tx.send_replace(self.snapshot());
    }

    /// Builds the snapshot the admin API serves.
    fn snapshot(&self) -> StatusSnapshot {
        let mut local_addrs = BTreeMap::new();
        let mut plugins = BTreeMap::new();
        for proxy in self.proxies.iter() {
            let local = crate::proto::transport::join_host_port(
                &proxy.qos().local_ip,
                proxy.qos().local_port,
            );
            if !local.is_empty() {
                local_addrs.insert(proxy.name.clone(), local);
            }
            if let Some(plugin) = proxy.plugin() {
                plugins.insert(proxy.name.clone(), plugin.type_name().to_string());
            }
        }

        StatusSnapshot {
            proxies: self.statuses.values().cloned().collect(),
            local_addrs,
            plugins,
            connected: true,
        }
    }

    /// Moves the read half into its own task.
    ///
    /// The returned handle aborts the task when it is dropped, so the task cannot
    /// outlive the loop and keep the session alive behind the reconnect.
    fn spawn_reader(&mut self) -> ReaderTask {
        let mut events = self
            .events
            .take()
            .expect("the reader task is started once, before the loop");
        let (tx, rx) = mpsc::channel(READ_QUEUE);
        let task = tokio::spawn(async move {
            loop {
                let message = events.recv().await;
                let failed = message.is_err();
                if tx.send(message).await.is_err() || failed {
                    return;
                }
            }
        });
        ReaderTask { rx, task }
    }

    /// Announces the proxy at `index`, recording the phase change.
    async fn announce(&mut self, index: usize) -> Result<()> {
        let proxy = self.proxies[index].clone();
        let candidate = self.names[index].candidate;
        let message = to_new_proxy(&self.config, &proxy, candidate);

        if let Some(status) = self.statuses.get_mut(&proxy.name) {
            status.phase = ProxyPhase::WaitStart;
            status.error.clear();
        }
        // Keyed by the configured name, which never changes. Keying it by the
        // wire name would make `retry_pending`'s lookup below miss forever, and
        // nothing would ever be re-announced again.
        self.announced_at.insert(proxy.name.clone(), Instant::now());
        self.names[index].retry_at = None;

        self.control
            .send(&Message::NewProxy(Box::new(message)))
            .await
    }

    /// Republishes the names the work-connection tasks resolve against.
    ///
    /// Called whenever one changes — a candidate advancing, or a registration
    /// being acknowledged. `send_replace` rather than `send`, because between
    /// two work connections there may be no receiver at all and `send` would
    /// then silently do nothing.
    fn publish_names(&self) {
        self.names_tx.send_replace(self.names.clone().into());
    }

    /// Re-announces anything the server has not acknowledged, which is how a
    /// proxy recovers from a `start error`.
    async fn retry_pending(&mut self) {
        let now = Instant::now();
        let stale: Vec<usize> = self
            .proxies
            .iter()
            .enumerate()
            .filter(|(index, proxy)| match self.statuses.get(&proxy.name) {
                Some(status) => match status.phase {
                    ProxyPhase::New => true,
                    ProxyPhase::WaitStart | ProxyPhase::StartError => {
                        match self.names[*index].retry_at {
                            // The conflict path paces itself — three seconds a
                            // step, sixty before a new cycle — and that schedule
                            // is the whole point of the field.
                            Some(at) => now >= at,
                            None => self
                                .announced_at
                                .get(&proxy.name)
                                .is_some_and(|at| now.duration_since(*at) > REGISTER_TIMEOUT),
                        }
                    }
                    ProxyPhase::Running => false,
                },
                None => false,
            })
            .map(|(index, _)| index)
            .collect();

        let any_stale = !stale.is_empty();
        for index in stale {
            let name = self.proxies[index].name.clone();
            logging::debug(format!("re-announcing proxy {name}"));
            if let Err(err) = self.announce(index).await {
                logging::warn(format!("could not re-announce proxy {name}: {err}"));
            }
        }
        if any_stale {
            self.publish();
        }
    }

    /// Sends `CloseProxy` for every proxy, so the server releases ports promptly
    /// instead of waiting for the control connection to time out.
    async fn deregister_all(&mut self) {
        for registered in self.names.iter() {
            // Only a name the server confirmed. `frps` resolves `CloseProxy`
            // against this control connection's own proxies, so a name that was
            // never registered is a no-op — and a proxy that never came up has
            // nothing to release. The server reaps a control connection's
            // proxies when it ends anyway.
            let Some(acked) = registered.acked.as_deref() else {
                continue;
            };
            let message = CloseProxy {
                proxy_name: naming::add_user_prefix(&self.config.common.user, acked),
            };
            if let Err(err) = self
                .control
                .send(&Message::CloseProxy(Box::new(message)))
                .await
            {
                logging::debug(format!(
                    "could not close proxy {}: {err}",
                    registered.configured
                ));
                return;
            }
        }
    }

    /// Handles one message from the server.
    async fn handle(
        &mut self,
        message: Message,
        events: &Option<mpsc::Sender<ControlEvent>>,
    ) -> Result<()> {
        match message {
            Message::ReqWorkConn(_) => {
                self.serve_work_conn(events);
                Ok(())
            }
            Message::NewProxyResp(resp) => {
                self.handle_new_proxy_resp(*resp);
                self.publish();
                Ok(())
            }
            Message::Pong(pong) => {
                if !pong.error.is_empty() {
                    return Err(Error::Rejected(format!(
                        "the server rejected a heartbeat: {}",
                        pong.error
                    )));
                }
                self.last_pong = Some(Instant::now());
                Ok(())
            }
            Message::Ping(_) => {
                // frps does not send these, but a peer that does gets a reply.
                self.control.send(&Message::Pong(Box::default())).await
            }
            other => {
                logging::debug(format!("ignoring {} from the server", describe(&other)));
                Ok(())
            }
        }
    }

    fn handle_new_proxy_resp(&mut self, resp: NewProxyResp) {
        let local = naming::strip_user_prefix(&self.config.common.user, &resp.proxy_name);
        // Matched on the wire name rather than the configured one: after a
        // rename the server answers for `r1_hq1925369`, which is no proxy's
        // configured name.
        let Some(index) = self
            .names
            .iter()
            .position(|registered| registered.answers_to(&local))
        else {
            logging::warn(format!("the server answered for unknown proxy {local}"));
            return;
        };
        let configured = self.names[index].configured.clone();
        let log = logging::Prefixed::new(&configured);

        if resp.error.is_empty() {
            // The remote address is this client's addition: frp's own line is
            // just the success, and the address is what an operator has to run
            // `frpc status` to find.
            log.info(format!(
                "start proxy success, remote address: {}",
                resp.remote_addr
            ));
            self.names[index].acked = Some(local);
            self.names[index].retry_at = None;
            self.publish_names();
            if let Some(status) = self.statuses.get_mut(&configured) {
                status.phase = ProxyPhase::Running;
                status.remote_addr = resp.remote_addr;
                status.error.clear();
            }
            return;
        }

        // A conflict reported against a proxy that is already running is this
        // client's own duplicate registration coming back. `frps` refuses a name
        // that is in use without checking who holds it, so a second `NewProxy`
        // for a name that already succeeded is answered with `already exists` —
        // and there is a window for exactly that, because the retry timer can
        // fire again while the first answer is still queued. Treating it as a
        // real conflict would rename a tunnel that is working.
        let phase_before = self
            .statuses
            .get(&configured)
            .map_or(ProxyPhase::New, |status| status.phase);
        if is_our_own_duplicate(phase_before, &resp.error) {
            logging::debug(format!(
                "ignoring a duplicate registration answer for {configured}"
            ));
            return;
        }

        log.warn(format!("start error: {}", resp.error));
        if let Some(status) = self.statuses.get_mut(&configured) {
            status.phase = ProxyPhase::StartError;
            status.error = resp.error.clone();
        }

        let rename_enabled = self.config.rename_on_conflict();
        let action = on_start_error(&mut self.names[index], rename_enabled, &resp.error);
        match action {
            ConflictAction::Leave => {}
            ConflictAction::RetrySame { delay } => {
                logging::debug(format!(
                    "{configured} is taken; trying the same name again in {delay:?}"
                ));
                self.names[index].retry_at = Some(Instant::now() + delay);
            }
            ConflictAction::RetryAs { candidate, delay } => {
                log.warn(format!(
                    "proxy [{configured}] already exists; retrying as [{}] in {delay:?}",
                    candidate.name(&configured)
                ));
                self.names[index].retry_at = Some(Instant::now() + delay);
                self.publish_names();
            }
        }
    }

    /// Opens one work connection and hands it to the proxy the server names.
    ///
    /// The whole exchange runs in its own task, and that is not an optimisation.
    /// `frps` answers `NewWorkConn` with `StartWorkConn` only once a user
    /// connection actually takes that pooled connection, which may be minutes
    /// later — so awaiting it here would park the control loop and stop every
    /// other proxy dead. Go gets the same behaviour by registering the handler
    /// with `msg.AsyncHandler`, which runs it in its own goroutine.
    fn serve_work_conn(&self, events: &Option<mpsc::Sender<ControlEvent>>) {
        let codec = self.codec;
        let connector = self.connector.clone();
        let run_id = self.run_id.clone();
        let proxies = self.proxies.clone();
        let names = self.names_tx.subscribe();
        let user = self.config.common.user.clone();
        let signed = signs_new_work_conns(&self.config);
        let secret = self.token();
        let packet_size = self.packet_size();
        let events = events.clone();
        let traffic = self.traffic.clone();

        tokio::spawn(async move {
            let result = open_work_conn(
                codec,
                connector,
                run_id,
                proxies,
                names,
                &user,
                signed,
                secret,
                packet_size,
                events,
                traffic,
            )
            .await;
            if let Err(err) = result {
                // A work connection that cannot be opened is a per-connection
                // problem, not a reason to tear the session down. The server asks
                // again when it needs one.
                logging::warn(format!("could not serve a work connection: {err}"));
            }
        });
    }

    async fn send_ping(&mut self) -> Result<()> {
        let (privilege_key, timestamp) = if signs_heartbeats(&self.config) {
            let timestamp = chrono::Utc::now().timestamp();
            (auth_key(&self.token(), timestamp), timestamp)
        } else {
            (String::new(), 0)
        };
        self.control
            .send(&Message::Ping(Box::new(Ping {
                privilege_key,
                timestamp,
            })))
            .await
    }

    fn heartbeat_interval(&self) -> Option<Duration> {
        self.config
            .common
            .transport
            .as_ref()
            .map(|transport| transport.heartbeat_interval)
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(seconds as u64))
    }

    fn heartbeat_timeout(&self) -> Option<Duration> {
        self.config
            .common
            .transport
            .as_ref()
            .map(|transport| transport.heartbeat_timeout)
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(seconds as u64))
    }

    /// `udpPacketSize`, clamped to a length that can actually read a datagram.
    ///
    /// Clamped here rather than trusted because Go does not clamp and a zero
    /// from the config file gives a zero-length read buffer there — every
    /// datagram reads as empty, so the tunnel looks healthy and carries nothing.
    fn packet_size(&self) -> crate::client::udp::PacketSize {
        crate::client::udp::PacketSize::from_config(self.config.common.udp_packet_size)
    }

    fn token(&self) -> String {
        self.config
            .common
            .auth
            .as_ref()
            .map(|auth| auth.token.clone())
            .unwrap_or_default()
    }
}

/// The wrapping a proxy asked for.
fn transport_of(proxy: &ProxyConfig) -> WorkConnTransport {
    let transport = proxy.qos().transport.as_ref();
    WorkConnTransport {
        use_encryption: transport.is_some_and(|transport| transport.use_encryption),
        use_compression: transport.is_some_and(|transport| transport.use_compression),
    }
}

/// Opens one work connection, reads the `StartWorkConn` that names its proxy, and
/// bridges it.
///
/// Free rather than a method because it runs detached from the control loop: it
/// can block on `StartWorkConn` for as long as the server leaves the connection
/// pooled, which is exactly why it must not hold the loop up.
#[allow(clippy::too_many_arguments)]
async fn open_work_conn(
    codec: crate::proto::Codec,
    connector: Connector,
    run_id: String,
    proxies: Arc<[ProxyConfig]>,
    names: watch::Receiver<Arc<[Registered]>>,
    user: &str,
    signed: bool,
    secret: String,
    packet_size: crate::client::udp::PacketSize,
    events: Option<mpsc::Sender<ControlEvent>>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let mut conn = connector.connect().await?;
    codec.write_handshake_prefix(&mut conn).await?;

    // The signature only rides along when the scope asks for it, matching the
    // Go client: an unsigned NewWorkConn is the default wire shape.
    let (privilege_key, timestamp) = if signed {
        let timestamp = chrono::Utc::now().timestamp();
        (auth_key(&secret, timestamp), timestamp)
    } else {
        (String::new(), 0)
    };

    codec
        .write(
            &mut conn,
            &Message::NewWorkConn(Box::new(NewWorkConn {
                run_id,
                privilege_key,
                timestamp,
            })),
        )
        .await?;

    let start = match codec.read(&mut conn).await? {
        Message::StartWorkConn(start) => *start,
        other => {
            return Err(Error::protocol(format!(
                "expected StartWorkConn, got {}",
                describe(&other)
            )))
        }
    };

    if !start.error.is_empty() {
        return Err(Error::Rejected(start.error));
    }

    let local = naming::strip_user_prefix(user, &start.proxy_name);
    // Read now, not when the task was spawned: this connection may have been
    // sitting in the server's pool since before a rename.
    let names = names.borrow().clone();
    // Matched against every name the proxy answers to, not just the one it is
    // registered under now: the server may hand over a connection for a name that
    // was current when it queued the request, and the rename can have happened
    // since. Getting this wrong drops the work connection, so the user's own
    // connection hangs until it times out with only a warning to show for it.
    let Some((proxy, registered)) = proxies
        .iter()
        .zip(names.iter())
        .find(|(_, registered)| registered.answers_to(&local))
    else {
        logging::warn(format!(
            "the server sent a connection for unknown proxy {}",
            start.proxy_name
        ));
        return Ok(());
    };
    // Reported under the configured name, which is what the admin API and the
    // status list use, so a rename does not make a proxy's events change identity.
    let name = registered.configured.clone();

    let transport = transport_of(proxy);

    // UDP-shaped proxies serve one long-lived work connection rather than one per
    // user connection, so they take a different path from here.
    //
    // `udp` and `sudp` are the *same* code on this side: `BaseProxy.startVisitorListener`
    // appends an internal listener to the `sudp` proxy's listener list, and the
    // handler behind it asks for a work connection exactly as a `udp` proxy does.
    // The only difference is who can reach it, which is the server's business. The
    // Go client's two `InWorkConn` methods are line-for-line identical.
    if matches!(proxy.type_name(), "udp" | "sudp") {
        if transport.use_compression || transport.use_encryption {
            // The wrapping applies to the packet stream itself, and is the same
            // code path the server uses; it is not wired up for UDP yet, and
            // guessing at it would corrupt the stream rather than fail loudly.
            logging::warn(format!(
                "proxy {name}: useEncryption/useCompression on a udp proxy is not implemented; \
                 refusing the work connection"
            ));
            return Ok(());
        }
        let upstream = crate::client::udp::Upstream {
            local_ip: proxy.qos().local_ip.clone(),
            local_port: proxy.qos().local_port,
        };
        tokio::spawn(async move {
            crate::client::udp::serve(conn, codec, &name, upstream, packet_size, traffic).await;
        });
        return Ok(());
    }

    // An `xtcp` proxy is the one type left with no local side: it needs NAT hole
    // punching. `serve_one` can already dial `localIP:localPort` for anything TCP
    // shaped, but the server will not hand over a work connection the way it does
    // for `tcp`, so bridging it would silently drop every user connection.
    if proxy.type_name() == "xtcp" {
        logging::warn(format!(
            "proxy {name}: xtcp needs NAT hole punching, which is not implemented; \
             refusing the work connection"
        ));
        return Ok(());
    }

    // An `stcp` proxy looks different from the outside but is served the same
    // way: the server still asks for a work connection and then joins it to the
    // visitor connection on its side. Verified against a real `frps` — the first
    // version of this special-cased `stcp` and silently dropped every work
    // connection, which is exactly the failure a "no public port" proxy is
    // expected to have.
    serve_one(
        conn,
        &name,
        &proxy.qos().local_ip,
        proxy.qos().local_port,
        transport,
        secret,
        events,
        traffic,
    )
    .await;
    Ok(())
}

/// Serves one work connection: dial the local service and bridge the two.
///
/// `secret` is the auth token: frp keys a work connection's encryption on the
/// same token the control connection uses. The per-proxy `secretKey` is only for
/// visitor connections, which are a different direction.
#[allow(clippy::too_many_arguments)]
async fn serve_one(
    conn: LogicalConn,
    name: &str,
    local_ip: &str,
    local_port: u16,
    transport: WorkConnTransport,
    secret: String,
    events: Option<mpsc::Sender<ControlEvent>>,
    traffic: Arc<Traffic>,
) {
    let addr = crate::proto::transport::join_host_port(local_ip, local_port);
    let local = match tokio::time::timeout(
        bridge::LOCAL_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(socket)) => socket,
        Ok(Err(err)) => {
            logging::warn(format!("proxy {name}: cannot reach {addr}: {err}"));
            return;
        }
        Err(_) => {
            logging::warn(format!(
                "proxy {name}: connecting to {addr} timed out after {:?}",
                bridge::LOCAL_CONNECT_TIMEOUT
            ));
            return;
        }
    };

    // The wrapping order is frp's: encryption inside, compression outside, so
    // the bytes on the wire are `snappy(aes_cfb(plaintext))`.
    let result = match (transport.use_encryption, transport.use_compression) {
        (false, false) => bridge::join(conn, local, name).await,
        (true, false) => {
            let work = crate::proto::CryptoStream::encrypted(conn, secret.as_bytes());
            bridge::join(work, local, name).await
        }
        // Compression is not wired up yet; the registration tells the server it
        // is, so this must be reported rather than silently bridged in the clear.
        (_, true) => {
            logging::warn(format!(
                "proxy {name}: useCompression is not implemented; refusing the connection \
                 rather than sending it uncompressed"
            ));
            return;
        }
    };

    match result {
        Ok((bytes_to_local, bytes_to_work)) => {
            traffic.record(bytes_to_local, bytes_to_work);
            report(events, name, bytes_to_local, bytes_to_work).await
        }
        Err(err) => logging::debug(format!("proxy {name}: bridge ended: {err}")),
    }
}

async fn report(
    events: Option<mpsc::Sender<ControlEvent>>,
    name: &str,
    bytes_to_local: u64,
    bytes_to_work: u64,
) {
    if let Some(events) = events {
        let _ = events
            .send(ControlEvent::ConnectionClosed {
                proxy_name: name.to_string(),
                bytes_to_local,
                bytes_to_work,
            })
            .await;
    }
}

/// A message's name, for error text.
pub(crate) fn describe(message: &Message) -> &'static str {
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

/// Whether a control-loop failure should be retried or reported.
pub fn should_reconnect(error: &Error) -> bool {
    is_retryable(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered() -> Registered {
        Registered {
            configured: "web".to_string(),
            candidate: Candidate::Original,
            tries: 0,
            acked: None,
            retry_at: None,
        }
    }

    /// One refused registration, as the loop would see it: run the decision, then
    /// report the name that will be sent next and the wait in front of it.
    fn refused(reg: &mut Registered) -> (String, Duration) {
        match on_start_error(reg, true, "proxy [web] already exists") {
            ConflictAction::Leave => panic!("a conflict must not be left alone"),
            ConflictAction::RetrySame { delay } => (reg.candidate.name(&reg.configured), delay),
            ConflictAction::RetryAs { candidate, delay } => {
                assert_eq!(
                    candidate, reg.candidate,
                    "the action must describe the new state"
                );
                (candidate.name(&reg.configured), delay)
            }
        }
    }

    /// The sequence, and the pacing, are the feature — so both are asserted.
    ///
    /// Each entry is **the name of the next attempt and the wait in front of
    /// it**, so the original appears once per cycle rather than twice: the first
    /// attempt is the starting state, and its refusal is what produces the second
    /// attempt's entry. Read as attempts the walk is
    /// `original, original, r1_, r2_, r3_` — two tries for the configured name,
    /// one for each candidate — and only the step that returns to the original
    /// waits a minute.
    #[test]
    fn the_conflict_walk_matches_the_agreed_sequence() {
        let mut reg = registered();
        let seen: Vec<(String, Duration)> = (0..15).map(|_| refused(&mut reg)).collect();

        let short = rename::CONFLICT_RETRY_DELAY;
        let long = rename::CYCLE_RESTART_DELAY;
        let cycle = vec![
            ("web".to_string(), short),
            ("r1_web".to_string(), short),
            ("r2_web".to_string(), short),
            ("r3_web".to_string(), short),
            ("web".to_string(), long),
        ];
        let mut expected = cycle.clone();
        expected.extend(cycle.clone());
        expected.extend(cycle);
        assert_eq!(seen, expected);
    }

    /// Each candidate really does get only the attempts it is allowed, counted
    /// from the state rather than from the shape of the list above.
    #[test]
    fn each_candidate_gets_exactly_its_attempts() {
        let mut reg = registered();
        // Two refusals of the configured name before the first rename: the first
        // keeps it, the second advances.
        refused(&mut reg);
        assert_eq!(reg.candidate, Candidate::Original);
        refused(&mut reg);
        assert_eq!(reg.candidate, Candidate::Renamed(1));

        // And one refusal per candidate after that.
        for expected in [2, 3] {
            refused(&mut reg);
            assert_eq!(reg.candidate, Candidate::Renamed(expected));
        }
        refused(&mut reg);
        assert_eq!(
            reg.candidate,
            Candidate::Original,
            "r3_ hands back to the original"
        );
    }

    /// The configured name is what an operator sees; only the candidate moves.
    #[test]
    fn the_configured_name_never_changes() {
        let mut reg = registered();
        for _ in 0..12 {
            refused(&mut reg);
        }
        assert_eq!(reg.configured, "web");
    }

    /// A renamed proxy still answers to its configured name, and to what the
    /// server confirmed — a work connection can arrive for either while a rename
    /// is in flight.
    #[test]
    fn a_proxy_answers_to_every_name_it_has_used() {
        let mut reg = registered();
        assert!(reg.answers_to("web"));
        assert!(!reg.answers_to("r1_web"));

        reg.candidate = Candidate::Renamed(1);
        assert!(reg.answers_to("r1_web"), "the candidate being tried");
        assert!(reg.answers_to("web"), "and still the configured name");

        reg.acked = Some("r2_web".to_string());
        assert!(reg.answers_to("r2_web"), "and whatever was confirmed");
    }

    #[test]
    fn turning_the_strategy_off_leaves_everything_alone() {
        let mut reg = registered();
        assert_eq!(
            on_start_error(&mut reg, false, "proxy [web] already exists"),
            ConflictAction::Leave
        );
        assert_eq!(reg.candidate, Candidate::Original);
        assert_eq!(reg.tries, 0, "a disabled strategy must not use up tries");
    }

    /// A start failure that is not a conflict must keep the twenty-second path.
    /// Renaming because a local service is down would trade one fault for a
    /// stranger one.
    #[test]
    fn other_failures_are_left_to_the_ordinary_retry() {
        for error in ["port already used", "connect to local service error", ""] {
            let mut reg = registered();
            assert_eq!(
                on_start_error(&mut reg, true, error),
                ConflictAction::Leave,
                "{error:?}"
            );
        }
    }

    /// A success stops the walk: the candidate stays where it landed.
    #[test]
    fn a_candidate_that_works_stays() {
        let mut reg = registered();
        refused(&mut reg);
        refused(&mut reg);
        assert_eq!(reg.candidate, Candidate::Renamed(1));
        // Nothing else calls `on_start_error`, so the state is simply left here.
        assert_eq!(reg.tries, 0);
    }

    /// Our own duplicate registration must not be mistaken for a conflict.
    #[test]
    fn a_running_proxy_ignores_its_own_duplicate() {
        assert!(is_our_own_duplicate(
            ProxyPhase::Running,
            "proxy [web] already exists"
        ));
        assert!(is_our_own_duplicate(
            ProxyPhase::Running,
            "router config conflict"
        ));
        // Before the name is ours, the same message is a real conflict.
        assert!(!is_our_own_duplicate(
            ProxyPhase::WaitStart,
            "proxy [web] already exists"
        ));
        // And a running proxy's other failures are real failures.
        assert!(!is_our_own_duplicate(
            ProxyPhase::Running,
            "port already used"
        ));
    }
}
