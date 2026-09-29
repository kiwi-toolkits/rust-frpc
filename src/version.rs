//! Version strings.

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name reported in `-v` output and in logs.
pub const NAME: &str = "rust-frpc";

/// Version reported to `frps` in `Login.version` and printed by `-v`.
///
/// frp never compares this against its own version — the server only records it —
/// so a distinct string costs nothing in compatibility. It also keeps `frps`'s
/// client registry from listing a Rust client as an official Go build with a
/// misleading version number.
pub fn full() -> String {
    format!("{NAME}.{VERSION}")
}
