//! Command-line parsing.
//!
//! Hand-written rather than via `clap`, for two reasons. The flag names have to
//! match the Go client's exactly, including its quirk that every `_` in a flag
//! name is normalized to `-` (so `--server_addr` and `--server-addr` are the same
//! flag); and this is a size- and memory-sensitive binary, so a parser with no
//! dependency is worth a little more code.
//!
//! Only the flags that exist so far are here. The proxy-flag table that the Go
//! client uses for `frpc <type> ...` one-shot runs arrives with the client.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// What the process was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the client with the given config.
    Run(Args),
    /// Validate the config and print the normalized result, then exit.
    CheckConfig(Args),
    /// `verify [--server]`: check the config, optionally against a live server.
    Verify(crate::client::verify::VerifyArgs),
    /// `reload|status|stop`: talk to a running client's admin API.
    Admin(AdminArgs),
    /// Print the version and exit.
    Version,
    /// Print usage and exit.
    Help,
}

/// Which admin-API call to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    Reload,
    Status,
    Stop,
}

/// Parsed arguments for an admin subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminArgs {
    pub action: AdminAction,
    /// Path to the config file, which is where the admin address comes from.
    pub config: PathBuf,
    pub strict_config: bool,
    /// `--api-timeout`, in seconds. Defaults to the Go client's 30.
    pub api_timeout: Option<u64>,
}

/// Parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Path to the config file.
    pub config: PathBuf,
    /// Whether unknown config keys are an error. On by default, matching
    /// `--strict_config`.
    pub strict_config: bool,
    /// Overrides `log.level` when set.
    pub log_level: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            // The Go default, so an unqualified `frpc` finds an `frpc.ini` left
            // over from a previous installation.
            config: PathBuf::from("./frpc.ini"),
            strict_config: true,
            log_level: None,
        }
    }
}

/// The usage text.
pub fn usage() -> String {
    format!(
        "\
{name} {version}
A memory-frugal frp client.

Usage:
  frpc [options]

Options:
  -c, --config <path>       config file path (default ./frpc.ini)
      --strict-config       treat unknown config keys as errors (default true)
      --no-strict-config    ignore unknown config keys
      --log-level <level>   override log.level (trace|debug|info|warn|error)
      --check-config        validate the config, print it normalized, then exit
  -v, --version             print the version and exit

Subcommands:
  frpc verify [options]     check the config, and with --server also log in to
                            the configured frps and report what it says.
                            Options: --server, --api-timeout <seconds>
  frpc reload [options]     re-read the config of a running frpc
  frpc status [options]     print the proxies of a running frpc
  frpc stop [options]       stop a running frpc
                            Options: -c/--config, --api-timeout <seconds>
  -h, --help                print this help and exit

Environment:
  http_proxy is read as the default for transport.proxyURL, as frpc does.

Config files may be TOML or the legacy [common] INI format. The format is
decided by content, not by file extension, so an existing frpc.ini keeps
working when renamed.
",
        name = crate::version::NAME,
        version = crate::version::VERSION,
    )
}

/// Parses arguments, excluding the program name.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command> {
    let mut parsed = Args::default();
    let mut check_config = false;
    let mut verify: Option<(bool, Option<u64>)> = None;
    let mut admin: Option<AdminAction> = None;
    let mut admin_timeout: Option<u64> = None;
    let mut iter = args.into_iter().peekable();

    while let Some(raw) = iter.next() {
        // A bare `verify` starts the subcommand; everything after it is parsed
        // as its own flags.
        if raw == "verify" {
            verify = Some((false, None));
            continue;
        }
        if let Some(action) = admin_action(&raw) {
            admin = Some(action);
            continue;
        }
        let (flag, inline) = split_inline(&raw);
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-v" | "--version" => return Ok(Command::Version),
            "-c" | "--config" => {
                parsed.config = PathBuf::from(next_value(&flag, inline, &mut iter)?);
            }
            "--strict-config" => parsed.strict_config = bool_value(inline, true)?,
            "--no-strict-config" => parsed.strict_config = !bool_value(inline, true)?,
            "--log-level" => parsed.log_level = Some(next_value(&flag, inline, &mut iter)?),
            "--check-config" => {
                check_config = true;
            }
            // `verify` is a subcommand rather than a flag, so it is matched on
            // the raw token before flag normalization — but only when it is the
            // first non-flag argument.
            "--server" => match verify.as_mut() {
                Some((server, _)) => *server = bool_value(inline, true)?,
                None => {
                    return Err(Error::config(
                        "--server only applies to `frpc verify`".to_string(),
                    ))
                }
            },
            "--api-timeout" => {
                let value = next_value(&flag, inline, &mut iter)?;
                let seconds = value.parse::<u64>().map_err(|_| {
                    Error::config(format!("--api-timeout expects a number, got {value:?}"))
                })?;
                match (verify.as_mut(), admin.is_some()) {
                    (Some((_, timeout)), _) => *timeout = Some(seconds),
                    (None, true) => admin_timeout = Some(seconds),
                    (None, false) => {
                        return Err(Error::config(
                            "--api-timeout only applies to `frpc verify|reload|status|stop`"
                                .to_string(),
                        ))
                    }
                }
            }
            other => {
                return Err(Error::config(format!("unknown flag: {other}")));
            }
        }
    }

    if let Some(action) = admin {
        if verify.is_some() {
            return Err(Error::config(
                "`verify` cannot be combined with an admin subcommand".to_string(),
            ));
        }
        return Ok(Command::Admin(AdminArgs {
            action,
            config: parsed.config,
            strict_config: parsed.strict_config,
            api_timeout: admin_timeout,
        }));
    }
    if let Some((server, timeout)) = verify {
        return Ok(Command::Verify(crate::client::verify::parse_args(
            &parsed.config,
            parsed.strict_config,
            server,
            timeout,
        )));
    }
    Ok(if check_config {
        Command::CheckConfig(parsed)
    } else {
        Command::Run(parsed)
    })
}

/// Recognizes the three admin subcommands.
fn admin_action(raw: &str) -> Option<AdminAction> {
    match raw {
        "reload" => Some(AdminAction::Reload),
        "status" => Some(AdminAction::Status),
        "stop" => Some(AdminAction::Stop),
        _ => None,
    }
}

/// Splits `--flag=value` into its parts, and normalizes `_` to `-` so that the
/// Go client's `--server_addr` spelling keeps working.
///
/// A single leading dash is kept as-is; anything else starting with a dash has
/// its body normalized.
fn split_inline(raw: &str) -> (String, Option<String>) {
    let (flag, value) = match raw.split_once('=') {
        Some((flag, value)) => (flag, Some(value.to_string())),
        None => (raw, None),
    };
    if !flag.starts_with("--") {
        return (flag.to_string(), value);
    }
    let normalized = format!("--{}", flag[2..].replace('_', "-"));
    (normalized, value)
}

/// The value for a flag that needs one, either inline or as the next argument.
fn next_value<I: Iterator<Item = String>>(
    flag: &str,
    inline: Option<String>,
    iter: &mut std::iter::Peekable<I>,
) -> Result<String> {
    if let Some(value) = inline {
        return Ok(value);
    }
    iter.next()
        .ok_or_else(|| Error::config(format!("{flag} requires a value")))
}

/// The value for a flag with an optional boolean, defaulting to `default` when
/// written bare (`--strict-config`).
fn bool_value(inline: Option<String>, default: bool) -> Result<bool> {
    match inline {
        None => Ok(default),
        Some(value) => match value.as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            other => Err(Error::config(format!("expected a boolean, got {other:?}"))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Command {
        parse(args.iter().map(|arg| arg.to_string())).unwrap()
    }

    #[test]
    fn defaults_to_the_go_client_config_path() {
        let Command::Run(args) = parse_ok(&[]) else {
            panic!("expected Run");
        };
        assert_eq!(args.config, PathBuf::from("./frpc.ini"));
        assert!(args.strict_config);
    }

    #[test]
    fn short_and_long_config_flags_agree() {
        for args in [["-c", "a.toml"], ["--config", "a.toml"]] {
            let Command::Run(parsed) = parse_ok(&args) else {
                panic!("expected Run");
            };
            assert_eq!(parsed.config, PathBuf::from("a.toml"));
        }
    }

    #[test]
    fn inline_values_are_accepted() {
        let Command::Run(parsed) = parse_ok(&["--config=a.toml", "--log-level=debug"]) else {
            panic!("expected Run");
        };
        assert_eq!(parsed.config, PathBuf::from("a.toml"));
        assert_eq!(parsed.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn underscores_in_flag_names_are_normalized() {
        // The Go client does this, so `--strict_config` has to work too.
        let Command::Run(parsed) = parse_ok(&["--strict_config=false"]) else {
            panic!("expected Run");
        };
        assert!(!parsed.strict_config);
    }

    #[test]
    fn version_and_help_short_circuit() {
        assert_eq!(parse_ok(&["-v"]), Command::Version);
        assert_eq!(parse_ok(&["--version"]), Command::Version);
        assert_eq!(parse_ok(&["-h"]), Command::Help);
        assert_eq!(parse_ok(&["--help"]), Command::Help);
        // Even alongside other flags, since they exit immediately.
        assert_eq!(parse_ok(&["-c", "a.toml", "-v"]), Command::Version);
    }

    #[test]
    fn check_config_keeps_the_other_flags() {
        let Command::CheckConfig(parsed) = parse_ok(&["--check-config", "-c", "a.toml"]) else {
            panic!("expected CheckConfig");
        };
        assert_eq!(parsed.config, PathBuf::from("a.toml"));
    }

    #[test]
    fn a_flag_without_its_value_is_an_error() {
        assert!(parse(["--config".to_string()]).is_err());
    }

    #[test]
    fn an_unknown_flag_is_an_error() {
        let err = parse(["--nope".to_string()]).unwrap_err();
        assert!(err.to_string().contains("unknown flag"), "{err}");
    }

    #[test]
    fn a_non_boolean_value_is_an_error() {
        assert!(parse(["--strict-config=maybe".to_string()]).is_err());
    }

    #[test]
    fn the_admin_subcommands_are_recognized() {
        for (name, expected) in [
            ("reload", AdminAction::Reload),
            ("status", AdminAction::Status),
            ("stop", AdminAction::Stop),
        ] {
            let Command::Admin(args) = parse_ok(&[name]) else {
                panic!("expected Admin for {name}");
            };
            assert_eq!(args.action, expected);
            // The Go default, so `frpc status` finds the same file `frpc` ran with.
            assert_eq!(args.config, PathBuf::from("./frpc.ini"));
        }
    }

    #[test]
    fn an_admin_subcommand_takes_the_config_and_timeout() {
        let Command::Admin(args) = parse_ok(&["status", "-c", "a.toml", "--api-timeout", "5"])
        else {
            panic!("expected Admin");
        };
        assert_eq!(args.config, PathBuf::from("a.toml"));
        assert_eq!(args.api_timeout, Some(5));
    }

    #[test]
    fn an_api_timeout_without_a_subcommand_is_an_error() {
        let err = parse(["--api-timeout".into(), "5".into()]).unwrap_err();
        assert!(err.to_string().contains("--api-timeout"), "{err}");
    }

    #[test]
    fn verify_and_an_admin_subcommand_cannot_be_combined() {
        let err = parse(["verify".to_string(), "status".to_string()]).unwrap_err();
        assert!(err.to_string().contains("cannot be combined"), "{err}");
    }
}
