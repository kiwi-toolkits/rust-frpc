//! Logging, matching frp's own logger line for line.
//!
//! Every frp message goes through `golib/log`, and a line there is:
//!
//! ```text
//! 2006-01-02 15:04:05.000 [I] [service.go:332] [runID] login to server success
//! ```
//!
//! Four things about that are load-bearing, and three of them are easy to get
//! wrong by assuming the obvious spelling:
//!
//! * **The timestamp is fixed-width to the millisecond and local.** Not RFC3339:
//!   `golib/log/format.go` builds `2006-01-02 15:04:05.000` by hand. An operator
//!   grepping for `^2006-01-02` or diffing a client log against a server log
//!   depends on the column being in the same place.
//! * **The level is one letter.** `[I]`, not `[INFO]` — `Level.LogPrefix()` in
//!   `golib/log/level.go:52`. Log shippers in the wild key on the bracketed letter.
//! * **The caller is the last two path components of the *Go* source file.**
//!   This is a port, so the honest thing is to print where the behaviour lives
//!   upstream: `[service.go:332]`, not `[service.rs:140]`. The map below is
//!   hand-maintained for that reason, and the point of the field — being
//!   recognisable to someone who knows frp — only survives if it stays that way.
//! * **The prefix is `[runID]`, `[proxyName]`, or both**, set per component the
//!   way `xlog` sets it (`pkg/util/xlog/xlog.go:81` renders `"[" + value + "] "`
//!   for each). The run id and the proxy name are the two an operator actually
//!   greps for.
//!
//! `log.format = "json"` and `log.color` are additions of this crate; see the
//! differences table in `doc/compatibility.md`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use chrono::{Local, NaiveDate};

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

    /// The bracketed one-letter prefix, as `Level.LogPrefix()` renders it.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "[T]",
            Level::Debug => "[D]",
            Level::Info => "[I]",
            Level::Warn => "[W]",
            Level::Error => "[E]",
        }
    }

    /// The full name, which only the JSON format and the threshold parser use.
    pub fn name(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }

    /// The ANSI brush `golib/log/output_console.go` wraps a line in.
    fn brush(self) -> &'static str {
        match self {
            // Trace is deliberately uncoloured upstream.
            Level::Trace => "",
            Level::Debug => "\x1b[1;36m",
            Level::Info => "\x1b[1;34m",
            Level::Warn => "\x1b[1;33m",
            Level::Error => "\x1b[1;31m",
        }
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

/// Where records go, and how they are coloured.
///
/// Mirrors `log.InitLogger`: `console` prints to stdout — coloured unless
/// `disablePrintColor` — and anything else is a path, which becomes a daily
/// rotating file.
#[derive(Debug, Clone)]
pub struct Config {
    pub level: Level,
    pub format: Format,
    /// `log.to`. `"console"` or a file path.
    pub to: String,
    /// `log.maxDays`, used only for a file destination. Zero means keep forever.
    pub max_days: i64,
    /// `log.disablePrintColor`.
    pub disable_print_color: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            level: Level::Info,
            format: Format::Text,
            to: "console".into(),
            max_days: 3,
            disable_print_color: false,
        }
    }
}

/// The process-wide logger. Installed once, from `main`.
static LOGGER: OnceLock<Logger> = OnceLock::new();

/// A fallback threshold for the window between the first log call and `init`.
///
/// Nothing logs that early today, but a library that writes to `log` before the
/// binary has chosen its config should degrade to the Go default rather than
/// panic or drop the record.
static EARLY_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Installs the global logger. Call once, before anything logs.
///
/// Returns the error the file destination failed with, if any. A logger that
/// cannot open its file still logs to stderr — losing the whole run because a
/// directory is missing would be a worse failure than a misplaced log.
pub fn init(config: Config) -> Result<(), String> {
    let mut failure = None;
    let sink = if config.to == "console" {
        Sink::Console {
            color: !config.disable_print_color,
        }
    } else {
        match RotatingFile::open(&config.to, config.max_days) {
            Ok(file) => Sink::File(Mutex::new(file)),
            Err(err) => {
                failure = Some(format!("cannot open log file {}: {err}", config.to));
                Sink::Stderr
            }
        }
    };

    EARLY_LEVEL.store(config.level as u8, Ordering::Relaxed);
    let _ = LOGGER.set(Logger {
        level: config.level,
        format: config.format,
        sink,
    });
    failure.map_or(Ok(()), Err)
}

/// The current threshold, for callers that want to skip work entirely.
pub fn enabled(level: Level) -> bool {
    level as u8
        >= LOGGER
            .get()
            .map(|logger| logger.level as u8)
            .unwrap_or_else(|| EARLY_LEVEL.load(Ordering::Relaxed))
}

struct Logger {
    level: Level,
    format: Format,
    sink: Sink,
}

enum Sink {
    Console {
        color: bool,
    },
    File(Mutex<RotatingFile>),
    /// The configured file could not be opened. Reports go to stderr so they are
    /// still visible, which is more useful than silence.
    Stderr,
}

impl Logger {
    fn write(&self, level: Level, caller: &str, prefix: &str, message: &str) {
        let line = match self.format {
            Format::Text => {
                // `formatTimeHeader` writes the local time padded to the
                // millisecond, so every line's columns line up.
                let when = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                format!("{when} {} {caller} {prefix}{message}\n", level.as_str())
            }
            Format::Json => format!(
                "{{\"time\":\"{}\",\"level\":\"{}\",\"msg\":\"{}\"}}\n",
                Local::now().to_rfc3339(),
                level.name(),
                escape_json(message),
            ),
        };

        match &self.sink {
            Sink::Console { color } => {
                let mut stdout = std::io::stdout().lock();
                if *color {
                    // The whole line is wrapped, matching `ConsoleWriter`.
                    let _ = write!(stdout, "{}{line}\x1b[0m", level.brush());
                } else {
                    let _ = stdout.write_all(line.as_bytes());
                }
            }
            Sink::File(file) => {
                if let Ok(mut file) = file.lock() {
                    let _ = file.write(line.as_bytes());
                }
            }
            Sink::Stderr => {
                let _ = std::io::stderr().lock().write_all(line.as_bytes());
            }
        }
    }
}

/// Emits one record. No-op when the level is filtered out.
///
/// The caller field is filled in from this crate's own source rather than left
/// blank — see [`here`].
#[track_caller]
pub fn log(level: Level, message: impl AsRef<str>) {
    emit(level, &here(), "", message.as_ref());
}

/// Where in *this* implementation a record came from, as `[file.rs:line]`.
///
/// Go's `getCallerPrefix` trims to the last two path components, and the same
/// trim here gives `[client/service.rs:545]`. The column is part of frp's log
/// format, so it stays — but it points at *this* implementation, because a file
/// name that does not exist in this tree is worse than no information at all.
/// An earlier version printed the Go line for messages that reproduced a Go one,
/// which read as a bug to anyone who went looking for `service.go`.
///
/// A blank column would be the other wrong answer: it reads as a logger fault
/// rather than as information.
#[track_caller]
fn here() -> String {
    let location = std::panic::Location::caller();
    // Normalized to `/` so the field reads like a Go path on every platform;
    // rustc spells it with the host separator, which on Windows is `\`.
    let path = trimmed_path(location.file()).replace('\\', "/");
    format!("[{path}:{}]", location.line())
}

/// The last two path components, as `trimmedPath` renders them.
///
/// Both separators are accepted because `Location::file()` is spelled the way
/// rustc was invoked, which on Windows is `src\client\service.rs`. Go only ever
/// sees `/`, so its `LastIndexByte(path, '/')` needs no such care.
fn trimmed_path(path: &str) -> &str {
    let is_separator = |c: char| c == '/' || c == '\\';
    let Some(last) = path.rfind(is_separator) else {
        return path;
    };
    // A file directly under the root keeps both components, matching Go: its
    // `trimmedPath` falls back to the full path when there is no penultimate
    // separator.
    match path[..last].rfind(is_separator) {
        None => path,
        Some(second) => &path[second + 1..],
    }
}

fn emit(level: Level, caller: &str, prefix: &str, message: &str) {
    if !enabled(level) {
        return;
    }
    let Some(logger) = LOGGER.get() else {
        // Before `init`: fall back to the default sink so nothing is lost.
        let _ = writeln!(
            std::io::stderr(),
            "{} {} {}{}",
            Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            level.as_str(),
            prefix,
            message
        );
        return;
    };
    logger.write(level, caller, prefix, message);
}

/// A logger that carries a `[runID]` or `[proxyName]` prefix.
///
/// frp derives these from the request context (`xlog`); there is no context to
/// hang them on here, so components that own a name build one of these and use
/// it for everything they log. Cloneable and cheap: the string is built once.
#[derive(Debug, Clone)]
pub struct Prefixed {
    prefix: String,
}

impl Prefixed {
    pub fn new(name: &str) -> Self {
        Self {
            prefix: format!("[{name}] "),
        }
    }

    #[track_caller]
    pub fn trace(&self, message: impl AsRef<str>) {
        emit(Level::Trace, &here(), &self.prefix, message.as_ref());
    }

    #[track_caller]
    pub fn debug(&self, message: impl AsRef<str>) {
        emit(Level::Debug, &here(), &self.prefix, message.as_ref());
    }

    #[track_caller]
    pub fn info(&self, message: impl AsRef<str>) {
        emit(Level::Info, &here(), &self.prefix, message.as_ref());
    }

    #[track_caller]
    pub fn warn(&self, message: impl AsRef<str>) {
        emit(Level::Warn, &here(), &self.prefix, message.as_ref());
    }

    #[track_caller]
    pub fn error(&self, message: impl AsRef<str>) {
        emit(Level::Error, &here(), &self.prefix, message.as_ref());
    }
}

#[track_caller]
pub fn trace(message: impl AsRef<str>) {
    log(Level::Trace, message);
}

#[track_caller]
pub fn debug(message: impl AsRef<str>) {
    log(Level::Debug, message);
}

#[track_caller]
pub fn info(message: impl AsRef<str>) {
    log(Level::Info, message);
}

#[track_caller]
pub fn warn(message: impl AsRef<str>) {
    log(Level::Warn, message);
}

#[track_caller]
pub fn error(message: impl AsRef<str>) {
    log(Level::Error, message);
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

/// A file that moves aside at midnight and deletes its older backups.
///
/// A port of `golib/log/output_rotatefile.go`, with one deliberate difference:
/// upstream rotates from a goroutine that wakes on the hour, this checks on the
/// way past. The observable result is the same — the first record after midnight
/// lands in a fresh file and yesterday's is named `frpc.20260102-000000.log` —
/// and it costs no timer. The backup name uses the current time, as upstream's
/// does, so it carries the *new* day's date.
struct RotatingFile {
    path: PathBuf,
    max_days: i64,
    file: File,
    /// The day the file was opened, so a write after midnight can notice.
    opened_on: NaiveDate,
}

impl RotatingFile {
    fn open(path: &str, max_days: i64) -> std::io::Result<Self> {
        let path = PathBuf::from(path);
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        // Upstream appends to an existing file rather than rotating on startup.
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            max_days,
            file,
            opened_on: Local::now().date_naive(),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if Local::now().date_naive() != self.opened_on {
            self.rotate()?;
        }
        self.file.write_all(bytes)
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(backup) = self.backup_name() {
            // A rename that fails (another writer, a full disk) must not stop
            // logging; the worst case is that the file keeps growing.
            let _ = std::fs::rename(&self.path, backup);
        }
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.opened_on = Local::now().date_naive();
        self.clear_expired();
        Ok(())
    }

    /// `frpc.log` → `frpc.20260102-000000.log`, as `backupName` builds it.
    fn backup_name(&self) -> Option<PathBuf> {
        let dir = self.path.parent()?.to_path_buf();
        let filename = self.path.file_name()?.to_string_lossy().to_string();
        let (stem, ext) = match filename.rfind('.') {
            Some(index) if index > 0 => filename.split_at(index),
            _ => (filename.as_str(), ""),
        };
        let stamp = Local::now().format("%Y%m%d-%H%M%S");
        Some(dir.join(format!("{stem}.{stamp}{ext}")))
    }

    /// Deletes backups older than `max_days`, matching `clearFiles`.
    fn clear_expired(&self) {
        if self.max_days <= 0 {
            return;
        }
        let Some(dir) = self.path.parent() else {
            return;
        };
        let Some(filename) = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
        else {
            return;
        };
        let (stem, ext) = match filename.rfind('.') {
            Some(index) if index > 0 => filename.split_at(index),
            _ => (filename.as_str(), ""),
        };
        let prefix = format!("{stem}.");

        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let cutoff = Local::now().naive_local() - chrono::Duration::days(self.max_days);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(stamp) = parse_backup_stamp(&name, &prefix, ext) else {
                continue;
            };
            if stamp < cutoff {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// The timestamp inside a backup name, or `None` if it is not one of ours.
///
/// Upstream compares `time.Time`s after parsing in local time; comparing the
/// naive values is the same ordering without the timezone round trip.
fn parse_backup_stamp(name: &str, prefix: &str, ext: &str) -> Option<chrono::NaiveDateTime> {
    let body = name.strip_prefix(prefix)?;
    let body = body.strip_suffix(ext)?;
    chrono::NaiveDateTime::parse_from_str(body, "%Y%m%d-%H%M%S").ok()
}

/// Whether a path looks like a file rather than `console`.
pub fn is_file_destination(to: &str) -> bool {
    !to.is_empty() && to != "console"
}

/// The directory a destination lives in, for the message when it cannot be made.
pub fn parent_of(path: &str) -> Option<&Path> {
    Path::new(path).parent()
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
    fn the_level_prefix_is_one_letter() {
        // `[INFO]` is the obvious spelling and the wrong one; golib uses `[I]`.
        assert_eq!(Level::Info.as_str(), "[I]");
        assert_eq!(Level::Warn.as_str(), "[W]");
        assert_eq!(Level::Error.as_str(), "[E]");
        assert_eq!(Level::Debug.as_str(), "[D]");
        assert_eq!(Level::Trace.as_str(), "[T]");
    }

    #[test]
    fn json_escaping_covers_quotes_and_control_characters() {
        assert_eq!(escape_json("a\"b"), "a\\\"b");
        assert_eq!(escape_json("a\nb"), "a\\nb");
        assert_eq!(escape_json("a\u{1}b"), "a\\u0001b");
    }

    #[test]
    fn a_backup_name_is_parsed_back_to_its_timestamp() {
        let stamp = parse_backup_stamp("frpc.20260102-030405.log", "frpc.", ".log").unwrap();
        assert_eq!(stamp.to_string(), "2026-01-02 03:04:05");
        // Not one of ours: the base file, another extension, a foreign name.
        assert!(parse_backup_stamp("frpc.log", "frpc.", ".log").is_none());
        assert!(parse_backup_stamp("frpc.20260102-030405.txt", "frpc.", ".log").is_none());
        assert!(parse_backup_stamp("other.20260102-030405.log", "frpc.", ".log").is_none());
    }

    #[test]
    fn the_console_writer_matches_the_go_brush_table() {
        // `output_console.go`'s `colors` slice, verbatim.
        assert_eq!(Level::Trace.brush(), "");
        assert_eq!(Level::Debug.brush(), "\x1b[1;36m");
        assert_eq!(Level::Info.brush(), "\x1b[1;34m");
        assert_eq!(Level::Warn.brush(), "\x1b[1;33m");
        assert_eq!(Level::Error.brush(), "\x1b[1;31m");
    }

    /// `trimmedPath` keeps the last two components and no more.
    #[test]
    fn a_caller_path_keeps_the_last_two_components() {
        assert_eq!(trimmed_path("src/client/service.rs"), "client/service.rs");
        assert_eq!(trimmed_path("a/b/c/d/e.rs"), "d/e.rs");
        // One separator or none is already two components or fewer, so Go
        // returns the whole path and so does this.
        assert_eq!(trimmed_path("src/lib.rs"), "src/lib.rs");
        assert_eq!(trimmed_path("lib.rs"), "lib.rs");
    }

    /// rustc spells `file!()` with the host separator, so Windows needs the
    /// same trim; the field is normalized to `/` on the way out.
    #[test]
    fn a_windows_caller_path_trims_the_same_way() {
        assert_eq!(trimmed_path(r"src\client\service.rs"), r"client\service.rs");
        assert_eq!(trimmed_path(r"src\lib.rs"), r"src\lib.rs");
        assert_eq!(
            trimmed_path(r"src\client\service.rs").replace('\\', "/"),
            "client/service.rs"
        );
    }
}
