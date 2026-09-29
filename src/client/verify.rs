//! `frpc verify [--server]`.
//!
//! The offline half checks that a config parses and validates. The `--server`
//! half is the one that matters for this project's central claim: it actually
//! dials the configured `frps`, completes a login, and reports what the server
//! said. If that succeeds, the wire protocol, the crypto layer and the login
//! signature are all correct against a real server — which no unit test can
//! establish on its own.

use std::path::Path;
use std::process::ExitCode;

use crate::config::{self, Severity, Strictness};
use crate::error::Result;
use crate::logging;

/// What `verify` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    pub config: std::path::PathBuf,
    pub strict_config: bool,
    /// Also connect to the configured server.
    pub server: bool,
    /// How long to wait for the login exchange.
    pub timeout: std::time::Duration,
}

/// Runs `verify` and returns the process exit code.
pub fn run(args: &VerifyArgs) -> ExitCode {
    let strictness = if args.strict_config {
        Strictness::Strict
    } else {
        Strictness::Lenient
    };

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
        println!("config: invalid");
        return ExitCode::from(1);
    }
    println!(
        "config: ok ({} proxies, {} visitors)",
        loaded.config.proxies.len(),
        loaded.config.visitors.len()
    );

    if !args.server {
        return ExitCode::SUCCESS;
    }

    match probe(&loaded.config, args.timeout) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            println!("server: unreachable");
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

/// Logs in to the configured server and reports what it said.
///
/// Deliberately stops at the login: registering a proxy would create a public
/// port on somebody's server, which is not what a health check should do as a
/// side effect. The `Login` exchange already proves the framing, the crypto and
/// the signature, which is the whole point.
fn probe(config: &config::ClientConfig, timeout: std::time::Duration) -> Result<String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| crate::error::Error::other(format!("build runtime: {err}")))?;

    runtime.block_on(async {
        let session = tokio::time::timeout(timeout, crate::client::login(config, ""))
            .await
            .map_err(|_| {
                crate::error::Error::Login(format!("login timed out after {timeout:?}"))
            })??;

        let line = format!(
            "server: ok (version {}, run id {}, wire protocol {})",
            session.server_version(),
            session.run_id(),
            session.codec().protocol().as_str()
        );
        let _ = session.close().await;
        Ok(line)
    })
}

/// Parses the flags `verify` accepts, on top of the global ones.
pub fn parse_args(
    config: &Path,
    strict_config: bool,
    server: bool,
    timeout_secs: Option<u64>,
) -> VerifyArgs {
    VerifyArgs {
        config: config.to_path_buf(),
        strict_config,
        server,
        timeout: std::time::Duration::from_secs(timeout_secs.unwrap_or(10)),
    }
}

/// Emits the probe result through the logger as well, so a run with
/// `log.format = "json"` produces a machine-readable line.
pub fn report(line: &str) {
    logging::info(line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults_to_a_ten_second_timeout() {
        let args = parse_args(Path::new("frpc.toml"), true, true, None);
        assert_eq!(args.timeout, std::time::Duration::from_secs(10));
        assert!(args.server);
    }

    #[test]
    fn an_explicit_timeout_wins() {
        let args = parse_args(Path::new("frpc.toml"), true, false, Some(3));
        assert_eq!(args.timeout, std::time::Duration::from_secs(3));
        assert!(!args.server);
    }
}
