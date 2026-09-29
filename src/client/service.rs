//! Runs the client: login, register proxies, serve connections, reconnect.
//!
//! The top-level loop. It owns the reconnect policy, which is the part that has
//! to be right for an unattended device: a dropped connection should come back
//! quickly, and a server that refuses the login should not be hammered.
//!
//! It also owns the admin API's lifetime and the two commands that arrive through
//! it. A reload and a stop both need to reach the code that owns the session, and
//! that is this loop and nothing else, so the command channel is read here rather
//! than threaded down into the control loop.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::config::{ClientConfig, ProxyConfig};
use crate::error::{Error, Result};
use crate::logging;
use crate::util::backoff::Backoff;

use super::admin::{self, AdminCommand, AdminServer};
use super::control::{Control, ControlEvent, StatusSnapshot, Traffic};
use super::login;
use super::session::Session;

/// How long to wait before the very first login attempt is repeated.
///
/// The Go client retries the initial login every 10 seconds
/// (`client/service.go`), and unlike the reconnect path it does not give up.
pub const FIRST_LOGIN_RETRY: Duration = Duration::from_secs(10);

/// How long a session has to survive before the backoff is considered fresh.
///
/// Without this, a server that accepts a login and then immediately drops the
/// connection would be reconnected to at the fast-retry rate forever.
const HEALTHY_SESSION: Duration = Duration::from_secs(30);

/// Runs the client until `shutdown` fires.
///
/// `login_fail_exit` decides what happens when the first login fails: the Go
/// default is to exit, because an unattended client that cannot reach its server
/// is usually a configuration mistake rather than a blip.
pub async fn run(
    config: ClientConfig,
    shutdown: watch::Receiver<bool>,
    events: Option<mpsc::Sender<ControlEvent>>,
) -> Result<()> {
    run_with_path(config, shutdown, events, None).await
}

/// The same, with the config file's path so the admin API can read and rewrite it.
pub async fn run_with_path(
    config: ClientConfig,
    shutdown: watch::Receiver<bool>,
    events: Option<mpsc::Sender<ControlEvent>>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    let traffic = Arc::new(Traffic::default());

    // A `stop` through the admin API and a signal both end the client, so they
    // share one flag; a `reload` only ends the *session*, which is why it gets
    // its own. Conflating them would make a reload look like a shutdown to the
    // reconnect logic.
    let (stop_tx, stop_rx) = watch::channel(false);
    let (restart_tx, restart_rx) = watch::channel(false);
    tokio::spawn(forward_shutdown(shutdown, stop_tx.clone()));

    let (status_tx, status_rx) = watch::channel(StatusSnapshot::default());
    let (commands_tx, commands_rx) = mpsc::channel(4);

    let admin = match start_admin(
        &config,
        &config_path,
        status_rx,
        traffic.clone(),
        commands_tx,
        stop_rx.clone(),
    )
    .await
    {
        Ok(admin) => admin,
        Err(err) => {
            // A port clash on the admin API is a configuration mistake and is
            // worth failing on: the operator asked for a management endpoint and
            // would otherwise get a client they cannot manage.
            logging::error(format!("{err}"));
            return Err(err);
        }
    };

    let result = serve(
        config,
        config_path,
        AdminSides {
            stop_tx,
            stop_rx,
            restart_tx,
            restart_rx,
            commands_live: admin.is_some(),
        },
        events,
        status_tx,
        commands_rx,
        traffic,
    )
    .await;

    if let Some(admin) = admin {
        admin.stop();
    }
    result
}

/// The flags and channels the session loop and the admin API share.
struct AdminSides {
    /// Set to end the whole client.
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    /// Set to end the current session and reconnect with a new config.
    restart_tx: watch::Sender<bool>,
    restart_rx: watch::Receiver<bool>,
    /// Whether anything can still send a command.
    ///
    /// False when no admin server was started, in which case the sender is
    /// already dropped — and a `recv` on a closed channel returns `None` at once,
    /// which must not be read as "stop".
    commands_live: bool,
}

/// Starts the admin API when `webServer.port` is set.
async fn start_admin(
    config: &ClientConfig,
    config_path: &Option<PathBuf>,
    status: watch::Receiver<StatusSnapshot>,
    traffic: Arc<Traffic>,
    commands: mpsc::Sender<AdminCommand>,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<AdminServer>> {
    let Some(web) = config.common.web_server.as_ref() else {
        return Ok(None);
    };
    if web.port == 0 {
        return Ok(None);
    }

    // The admin API's `/api/config` reads and rewrites the file it came from, so
    // it needs a path. Without one it still starts; those two routes then say
    // there is no file to work with.
    let path = config_path.clone().unwrap_or_default();
    let server = admin::start(
        Arc::new(config.clone()),
        web,
        status,
        traffic,
        commands,
        path,
        shutdown,
    )
    .await?;

    if let Some(server) = server.as_ref() {
        logging::info(format!("admin server started on {}", server.addr()));
    }
    Ok(server)
}

/// Copies the caller's shutdown into the client's own stop flag.
async fn forward_shutdown(mut external: watch::Receiver<bool>, stop: watch::Sender<bool>) {
    loop {
        if *external.borrow() {
            let _ = stop.send(true);
            return;
        }
        if external.changed().await.is_err() {
            return;
        }
    }
}

/// How one control session ended.
enum SessionEnd {
    /// The client was asked to stop.
    Stopped,
    /// A reload: reconnect with the freshly loaded config.
    Reload,
    /// The session failed.
    Failed(Error),
}

async fn serve(
    mut config: ClientConfig,
    config_path: Option<PathBuf>,
    sides: AdminSides,
    events: Option<mpsc::Sender<ControlEvent>>,
    status_tx: watch::Sender<StatusSnapshot>,
    mut commands: mpsc::Receiver<AdminCommand>,
    traffic: Arc<Traffic>,
) -> Result<()> {
    let AdminSides {
        stop_tx,
        mut stop_rx,
        restart_tx,
        restart_rx,
        commands_live,
    } = sides;
    let login_fail_exit = config.common.login_fail_exit.unwrap_or(true);

    // The first login: retried on a fixed interval, because nothing is running
    // yet and there is no session to preserve.
    let session = loop {
        if *stop_rx.borrow() {
            return Ok(());
        }
        match login(&config, "").await {
            Ok(session) => break session,
            Err(err) => {
                if !super::control::should_reconnect(&err) {
                    return Err(err);
                }
                if login_fail_exit {
                    logging::error(format!("login failed, exiting: {err}"));
                    return Err(err);
                }
                logging::warn(format!(
                    "login failed ({err}), retrying in {FIRST_LOGIN_RETRY:?}"
                ));
                tokio::select! {
                    _ = tokio::time::sleep(FIRST_LOGIN_RETRY) => {}
                    _ = stop_rx.changed() => return Ok(()),
                }
            }
        }
    };

    let mut backoff = Backoff::default();
    let mut run_id = session.run_id().to_string();
    let mut pending: Option<Session> = Some(session);

    loop {
        // The session is taken rather than borrowed, because `split` consumes it
        // and the loop may have to reconnect before there is a new one.
        let Some(current) = pending.take() else {
            unreachable!("the loop always reconnects before taking a session");
        };

        let (control_half, events_half) = current.split();
        let control = Control::with_observer(
            config.clone(),
            control_half,
            events_half,
            Some(status_tx.clone()),
            traffic.clone(),
        );

        // What the operator asked for, if a command arrives while the session is
        // running. The control loop is left to notice on its own so that its
        // graceful exit — the `CloseProxy` messages — still happens.
        let mut intent: Option<SessionEnd> = None;
        let mut commands_open = commands_live;
        let started = std::time::Instant::now();
        let session_future = control.run(stop_rx.clone(), restart_rx.clone(), events.clone());
        tokio::pin!(session_future);

        let outcome = loop {
            tokio::select! {
                outcome = &mut session_future => {
                    break match outcome {
                        Ok(()) => intent.unwrap_or(SessionEnd::Stopped),
                        Err(err) => SessionEnd::Failed(err),
                    };
                }
                command = commands.recv(), if commands_open => {
                    match command {
                        // The admin server went away; there is nothing left to
                        // listen to, but the session carries on.
                        None => commands_open = false,
                        Some(AdminCommand::Stop) => {
                            logging::info("stopping at the request of the admin API");
                            intent = Some(SessionEnd::Stopped);
                            let _ = stop_tx.send(true);
                        }
                        Some(AdminCommand::Reload { strict }) => {
                            if let Some(reloaded) = reload_command(&config_path) {
                                let (changed, removed) = changed_proxies(&config, &reloaded);
                                logging::info(format!(
                                    "reload: reconnecting with the new config (strict={strict}), \
                                     {changed} proxy(s) added or changed, {removed} removed"
                                ));
                                config = reloaded;
                                intent = Some(SessionEnd::Reload);
                                let _ = restart_tx.send(true);
                            }
                        }
                    }
                }
            }
        };

        match outcome {
            SessionEnd::Stopped => {
                logging::info("client stopped");
                return Ok(());
            }
            SessionEnd::Reload => {
                // A reload is not a failure, so it leaves the backoff alone. The
                // run id is replayed so the server hands the proxies back; the
                // ones the new config dropped were just closed explicitly by the
                // control loop's own deregistration.
                logging::debug("reload: reconnecting");
                // Cleared before the next session starts, or it would see the
                // flag still set and stop again immediately.
                let _ = restart_tx.send(false);
                login_again(
                    &config,
                    &mut run_id,
                    &mut pending,
                    &mut backoff,
                    &mut stop_rx,
                )
                .await?;
                continue;
            }
            SessionEnd::Failed(error) => {
                if !super::control::should_reconnect(&error) {
                    logging::error(format!("control session failed: {error}"));
                    return Err(error);
                }

                let healthy = started.elapsed() > HEALTHY_SESSION;
                if healthy {
                    backoff.reset();
                }
                let delay = backoff.next(!healthy);
                logging::warn(format!(
                    "control session ended ({error}), reconnecting in {delay:?}"
                ));
                if !sleep_or_shutdown(delay, &mut stop_rx).await {
                    return Ok(());
                }
                login_again(
                    &config,
                    &mut run_id,
                    &mut pending,
                    &mut backoff,
                    &mut stop_rx,
                )
                .await?;
            }
        }
    }
}

/// Reconnects, replaying the run id so the server hands the proxies back.
///
/// A failed attempt keeps the old run id: the server never saw the new session,
/// so the id it knows is still the useful one.
async fn login_again(
    config: &ClientConfig,
    run_id: &mut String,
    pending: &mut Option<Session>,
    backoff: &mut Backoff,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    loop {
        match login(config, run_id).await {
            Ok(reconnected) => {
                *run_id = reconnected.run_id().to_string();
                *pending = Some(reconnected);
                return Ok(());
            }
            Err(err) => {
                // A refused login — a token that no longer works, say — is not
                // made acceptable by waiting, so it is reported rather than
                // retried.
                if !super::control::should_reconnect(&err) {
                    return Err(err);
                }
                logging::warn(format!("reconnect failed: {err}"));
                let delay = backoff.next(true);
                if !sleep_or_shutdown(delay, shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

/// Re-reads the config file, or explains why it could not be applied.
///
/// A reload that fails leaves the running config untouched: the Go client behaves
/// the same way, and the alternative — falling back to a half-parsed file — is
/// worse than ignoring the request.
fn reload_command(config_path: &Option<PathBuf>) -> Option<ClientConfig> {
    let path = config_path.clone().unwrap_or_default();
    if path.as_os_str().is_empty() {
        logging::warn("reload ignored: no config file was named on the command line");
        return None;
    }
    match crate::config::load_file(&path) {
        Ok(loaded) => Some(loaded.config),
        Err(message) => {
            logging::warn(format!(
                "reload ignored: {} cannot be loaded: {message}",
                path.display()
            ));
            None
        }
    }
}

/// How many proxies a reload adds or changes, and how many it removes.
///
/// Worth reporting because "0 added, 0 removed" is the common case for a comment
/// edit, and it tells the operator nothing actually happened.
fn changed_proxies(old: &ClientConfig, new: &ClientConfig) -> (usize, usize) {
    let old_by_name: BTreeMap<&str, &ProxyConfig> =
        old.proxies.iter().map(|p| (p.name.as_str(), p)).collect();
    let new_by_name: BTreeMap<&str, &ProxyConfig> =
        new.proxies.iter().map(|p| (p.name.as_str(), p)).collect();

    let changed = new_by_name
        .iter()
        .filter(|(name, proxy)| old_by_name.get(*name) != Some(proxy))
        .count();
    let removed = old_by_name
        .keys()
        .filter(|name| !new_by_name.contains_key(*name))
        .count();
    (changed, removed)
}

/// Sleeps, returning `false` if the client was asked to stop first.
async fn sleep_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => !*shutdown.borrow(),
        _ = shutdown.changed() => false,
    }
}

/// Whether an error should stop the client outright.
pub fn is_fatal(error: &Error) -> bool {
    !super::control::should_reconnect(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyKind, Qos};

    fn config_with(proxies: &[(&str, u16)]) -> ClientConfig {
        let mut config = ClientConfig::default();
        for (name, port) in proxies {
            config.proxies.push(ProxyConfig::new(
                *name,
                None,
                ProxyKind::Tcp { remote_port: *port },
                Qos {
                    local_port: 22,
                    ..Qos::default()
                },
                None,
            ));
        }
        config.complete();
        config
    }

    #[test]
    fn a_rejected_login_is_fatal_and_a_transport_failure_is_not() {
        assert!(is_fatal(&Error::Login("bad token".into())));
        assert!(is_fatal(&Error::Rejected("already exists".into())));
        assert!(is_fatal(&Error::config("bad config")));
        assert!(!is_fatal(&Error::other("connection refused")));
        assert!(!is_fatal(&Error::protocol("session closed")));
    }

    #[test]
    fn the_first_login_retry_interval_matches_the_go_client() {
        assert_eq!(FIRST_LOGIN_RETRY, Duration::from_secs(10));
    }

    #[test]
    fn a_reload_counts_the_proxies_it_changed() {
        let old = config_with(&[("ssh", 6000), ("web", 6001)]);
        let same = config_with(&[("ssh", 6000), ("web", 6001)]);
        assert_eq!(changed_proxies(&old, &same), (0, 0));

        let changed = config_with(&[("ssh", 6000), ("web", 6002)]);
        assert_eq!(changed_proxies(&old, &changed), (1, 0));

        let removed = config_with(&[("ssh", 6000)]);
        assert_eq!(changed_proxies(&old, &removed), (0, 1));

        let added = config_with(&[("ssh", 6000), ("web", 6001), ("db", 6002)]);
        assert_eq!(changed_proxies(&old, &added), (1, 0));
    }
}
