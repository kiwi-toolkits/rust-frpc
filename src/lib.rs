//! A memory-frugal Rust implementation of the frp client.
//!
//! `rust-frpc` speaks the frp protocol to a stock Go `frps`, so the two can be
//! mixed freely: a Go server never learns that the client is not the Go one. The
//! wire format, the crypto, the configuration surface and the admin API are all
//! matched against `fatedier/frp` rather than invented here.
//!
//! The layers, bottom-up:
//!
//! * [`crypto`] — frp's application-layer crypto: `PBKDF2-HMAC-SHA1(token, "frp")`
//!   into AES-128-CFB, plus snappy framed compression.
//! * [`msg`] — the 18 message types, and the v1 (`type byte ‖ len ‖ JSON`) and
//!   v2 (`magic ‖ frame header`) framings.
//! * [`proto`] — connections that stack framing, crypto and compression, plus the
//!   transports (tcp/tls/websocket/kcp) and the yamux session multiplexer.
//! * [`config`] — TOML, YAML/JSON and legacy INI parsing into one model that
//!   mirrors `pkg/config/v1`.
//! * [`client`] — the login loop, control session, proxy wrappers and visitors.

pub mod cli;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod logging;
pub mod msg;
pub mod naming;
pub mod proto;
pub mod util;
pub mod version;

pub use error::{Error, Result};

use std::process::ExitCode;

use cli::Command;
use config::Severity;

/// Entry point shared by both binaries.
pub fn run() -> ExitCode {
    match cli::parse(std::env::args().skip(1)) {
        Ok(Command::Version) => {
            println!("{}", version::full());
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            print!("{}", cli::usage());
            ExitCode::SUCCESS
        }
        Ok(Command::CheckConfig(args)) => check_config(&args),
        Ok(Command::Verify(args)) => client::verify::run(&args),
        Ok(Command::Admin(args)) => client::manage::run(&args),
        Ok(Command::Run(args)) => run_client(&args),
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            eprint!("{}", cli::usage());
            ExitCode::from(2)
        }
    }
}

/// Whether the user asked for strict config parsing.
fn strictness_of(args: &cli::Args) -> config::Strictness {
    if args.strict_config {
        config::Strictness::Strict
    } else {
        config::Strictness::Lenient
    }
}

/// `--check-config`: validate and print the normalized config, then exit.
///
/// The normalized form is the point: it shows what the defaults resolved to,
/// including the ones that are easy to get wrong (a disabled heartbeat because
/// `tcpMux` is on, for instance).
fn check_config(args: &cli::Args) -> ExitCode {
    let strictness = strictness_of(args);
    let loaded = match config::load_file_with(&args.config, strictness) {
        Ok(loaded) => loaded,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    for warning in &loaded.warnings {
        println!("warning: {warning}");
    }

    let issues = match config::validate(&loaded.config) {
        Ok(issues) => issues,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let mut failed = false;
    for issue in &issues {
        match issue.severity {
            Severity::Error => {
                failed = true;
                println!("{issue}");
            }
            Severity::Warning => println!("{issue}"),
        }
    }
    if failed {
        return ExitCode::from(1);
    }

    match toml::to_string_pretty(&loaded.config) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: could not render the normalized config: {message}");
            ExitCode::from(2)
        }
    }
}

/// How long the client may take to deregister its proxies after a signal.
///
/// Without a bound, a server that has stopped reading would make Ctrl+C appear
/// to hang, and a user's second Ctrl+C should not be the only way out.
const GRACEFUL_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(5);

/// Runs the client until interrupted.
///
/// A single-threaded runtime on purpose: the client is I/O-bound, almost all of
/// its work is copying bytes between two sockets, and each extra worker thread
/// costs a stack plus its own task queue against a memory budget that is the
/// reason this crate exists.
fn run_client(args: &cli::Args) -> ExitCode {
    let strictness = strictness_of(args);
    let loaded = match config::load_file_with(&args.config, strictness) {
        Ok(loaded) => loaded,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let config = loaded.config;
    let level = args
        .log_level
        .clone()
        .or_else(|| config.common.log.as_ref().map(|log| log.level.clone()))
        .and_then(|level| logging::Level::parse(&level))
        .unwrap_or(logging::Level::Info);
    let format = match config
        .common
        .log
        .as_ref()
        .and_then(|log| log.format.as_deref())
    {
        Some("json") => logging::Format::Json,
        _ => logging::Format::Text,
    };
    logging::init(level, format);

    for warning in &loaded.warnings {
        logging::warn(warning);
    }

    let issues = match config::validate(&config) {
        Ok(issues) => issues,
        Err(message) => {
            logging::error(message.to_string());
            return ExitCode::from(2);
        }
    };
    let mut failed = false;
    for issue in issues {
        match issue.severity {
            Severity::Error => {
                failed = true;
                logging::error(issue.to_string());
            }
            Severity::Warning => logging::warn(issue.to_string()),
        }
    }
    if failed {
        return ExitCode::from(1);
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            logging::error(format!("build runtime: {err}"));
            return ExitCode::from(2);
        }
    };

    runtime.block_on(async {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let client =
            client::service::run_with_path(config, shutdown_rx, None, Some(args.config.clone()));
        tokio::pin!(client);

        // The first signal asks the client to stop cleanly, which is what
        // deregisters the proxies server-side; the deadline is only a backstop
        // for a server that has stopped reading.
        tokio::select! {
            result = &mut client => exit_code_of(result),
            _ = shutdown_signal() => {
                logging::info("shutting down");
                let _ = shutdown_tx.send(true);
                match tokio::time::timeout(GRACEFUL_SHUTDOWN, &mut client).await {
                    Ok(result) => exit_code_of(result),
                    Err(_) => {
                        logging::warn("shutdown took too long; exiting anyway");
                        ExitCode::SUCCESS
                    }
                }
            }
        }
    })
}

/// Turns the client's result into a process exit code.
fn exit_code_of(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            logging::error(format!("{err}"));
            ExitCode::from(1)
        }
    }
}

/// Resolves when the process is asked to stop.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            // Falling back is better than never resolving: a client that
            // ignored SIGTERM could not be stopped by an init system.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
