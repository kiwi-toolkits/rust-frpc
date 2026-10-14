//! Version strings.

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name reported in `-v` output and in logs.
pub const NAME: &str = "rust-frpc";

/// The `frp` release this client implements, from `doc/compatibility.md`.
///
/// It leads the string below because old `frps` parses the version by splitting
/// on `.` and reading fixed positions, and the position that matters is the
/// *second* one.
pub const FRP_COMPAT: &str = "0.71.0";

/// Version reported to `frps` in `Login.version` and printed by `-v`.
///
/// The leading number is not decoration and the prefix must not move back in
/// front of it. Every `frps` up to at least 0.54 calls
/// `version.Compat(loginMsg.Version)` on login, which is:
///
/// ```text
/// getSubVersion(v, n) = ParseInt(strings.Split(v, ".")[n])   // 0 if it fails
/// Compat(client)      = !LessThan(client, "0.18.0")
/// ```
///
/// and `LessThan` compares component by component. So `arr[0]` is compared
/// against `0`, `arr[1]` against `18`, and `arr[2]` against `0`. A string whose
/// first field is not a number — which `rust-frpc.0.1.0` is — makes `arr[0]`
/// zero, which ties; and then the crate's own `0` lands in `arr[1]` and is
/// compared against `18`. **It loses, and the server answers
/// "Please upgrade your frpc version to at least 0.18.0" and closes.**
///
/// This was verified rather than reasoned about: frps 0.44 rejects
/// `rust-frpc.0.1.0`, accepts `0.99.0-rust-frpc`, and the difference is that one
/// comparison. The check was dropped by 0.55, so a modern server never noticed —
/// which is why the old string looked harmless for as long as it did.
///
/// Hence `0.71.0-rust-frpc.0.1.0`: `arr[1]` is the frp version we implement, so
/// it clears the floor, and the suffix still tells an operator reading `frps`'s
/// dashboard which client this is.
pub fn full() -> String {
    format!("{FRP_COMPAT}-{NAME}.{VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape old `frps` requires, spelled out as it parses it.
    ///
    /// This is the test that would have caught the bug: it does not check that
    /// the string looks nice, it reproduces the two comparisons `version.Compat`
    /// actually makes.
    #[test]
    fn the_version_clears_the_floor_old_servers_apply() {
        let full = full();
        let parts: Vec<&str> = full.split('.').collect();
        assert!(
            parts.len() >= 3,
            "{full} must have at least three dot-separated fields"
        );

        // `getSubVersion` returns 0 when ParseInt fails, which is the whole
        // mechanism: a non-numeric field is not an error, it is a zero.
        let sub = |n: usize| {
            parts
                .get(n)
                .and_then(|p| p.parse::<i64>().ok())
                .unwrap_or(0)
        };
        let client = [sub(0), sub(1), sub(2)];
        let floor = [0_i64, 18, 0];

        // `LessThan` walks the components and stops at the first difference.
        let first_difference = client
            .iter()
            .zip(floor.iter())
            .find(|(c, f)| c != f)
            .map(|(c, f)| c.cmp(f));
        assert_ne!(
            first_difference,
            Some(std::cmp::Ordering::Less),
            "{full} parses as {client:?} against {floor:?}, so any frps up to 0.54 would \
             answer \"Please upgrade your frpc version to at least 0.18.0\""
        );
    }

    /// The name has to survive, or a dashboard cannot tell the clients apart —
    /// which is the only reason the string is not simply `FRP_COMPAT`.
    #[test]
    fn the_name_is_still_recognizable() {
        let full = full();
        assert!(full.contains(NAME), "{full}");
        assert!(full.contains(VERSION), "{full}");
    }
}
