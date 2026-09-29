//! Logging.
//!
//! The default format is line-for-line the same as the Go client's
//! (`` [2006-01-02T15:04:05-07:00] [INFO] message ``), because operators read
//! `frpc` output side by side with `frps` output and diffing two formats is
//! needless friction. `log.format = "json"` is this crate's addition, for log
//! pipelines.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use chrono::Local;

/// Log levels, ordered so that `level >= threshold` means "emit".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl Level {
    pub fn parse(value: &str) -> Option<Level> {
        match value.to_ascii_lowercase().as_str() {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);
static JSON: AtomicBool = AtomicBool::new(false);

/// Installs the global logger settings. Call once, before anything logs.
pub fn init(level: Level, format: Format) {
    THRESHOLD.store(level as u8, Ordering::Relaxed);
    JSON.store(format == Format::Json, Ordering::Relaxed);
}

/// The current threshold, for callers that want to skip work entirely.
pub fn enabled(level: Level) -> bool {
    level as u8 >= THRESHOLD.load(Ordering::Relaxed)
}

/// Emits one record. No-op when the level is filtered out.
pub fn log(level: Level, message: impl AsRef<str>) {
    if !enabled(level) {
        return;
    }
    let message = message.as_ref();
    let line = if JSON.load(Ordering::Relaxed) {
        // Hand-rolled rather than via serde: the logger runs on hot paths and
        // this avoids allocating a serializer per record.
        format!(
            "{{\"time\":\"{}\",\"level\":\"{}\",\"msg\":\"{}\"}}",
            Local::now().to_rfc3339(),
            level.as_str().to_ascii_lowercase(),
            escape_json(message),
        )
    } else {
        format!(
            "[{}] [{}] {}",
            Local::now().to_rfc3339(),
            level.as_str(),
            message
        )
    };

    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn trace(message: impl AsRef<str>) {
    log(Level::Trace, message);
}

pub fn debug(message: impl AsRef<str>) {
    log(Level::Debug, message);
}

pub fn info(message: impl AsRef<str>) {
    log(Level::Info, message);
}

pub fn warn(message: impl AsRef<str>) {
    log(Level::Warn, message);
}

pub fn error(message: impl AsRef<str>) {
    log(Level::Error, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_levels_case_insensitively() {
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
    }

    #[test]
    fn json_escaping_covers_quotes_and_control_characters() {
        assert_eq!(escape_json("a\"b"), "a\\\"b");
        assert_eq!(escape_json("a\nb"), "a\\nb");
        assert_eq!(escape_json("a\u{1}b"), "a\\u0001b");
    }
}
