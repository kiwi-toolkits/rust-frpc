//! Version strings.

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name reported in `-v` output and in logs.
pub const NAME: &str = "rust-frpc";

/// Version reported to `frps` in `Login.version` and printed by `-v`.
///
/// Short on purpose: it is read by an operator in a dashboard, not parsed.
///
/// **What it costs.** Every `frps` up to at least 0.54 calls
/// `version.Compat(loginMsg.Version)` on login, which splits the string on `.`
/// and compares field *n* against field *n* of `0.18.0`. A string whose fields
/// are not all numbers is read as zeroes, and only the second field decides:
/// `rs-0.1.0` splits to `["rs-0", "1", "0"]`, so the comparison is `1 < 18` and
/// the server answers `Please upgrade your frpc version to at least 0.18.0` and
/// closes. Reaching those servers would need a leading `0.71.0-`, which is what
/// this string used to carry.
///
/// That is a deliberate trade, taken with the cost known: the servers this
/// client is deployed against are 0.62.1 and 0.69.1, the check was dropped in
/// 0.55, and a readable version is worth more here than compatibility with a
/// frp from 2022. If that ever changes, the fix is to put `FRP_COMPAT` back in
/// front — and the test below is what will need rewriting.
pub fn full() -> String {
    format!("rs-{VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape, pinned so a change here is a decision rather than a drift.
    #[test]
    fn the_version_string_is_the_short_form() {
        assert_eq!(full(), format!("rs-{VERSION}"));
        assert_eq!(full(), "rs-0.1.0");
    }

    /// The cost of that shape, spelled out as `frps` computes it.
    ///
    /// This test asserts the *incompatibility*, which looks backwards until you
    /// read why: it is the decision above, encoded. It reproduces
    /// `version.Compat` — `getSubVersion` returns 0 when `ParseInt` fails, and
    /// `LessThan` walks the fields and stops at the first difference — and then
    /// checks that this string loses that comparison, so nobody can quietly
    /// believe old servers are supported.
    ///
    /// If a future version string *does* clear the floor, this test failing is
    /// the signal to update the comment above, not a bug to work around.
    #[test]
    fn the_short_form_is_rejected_by_frps_up_to_0_54() {
        let full = full();
        let parts: Vec<&str> = full.split('.').collect();
        let sub = |n: usize| {
            parts
                .get(n)
                .and_then(|p| p.parse::<i64>().ok())
                .unwrap_or(0)
        };
        let client = [sub(0), sub(1), sub(2)];
        let floor = [0_i64, 18, 0];

        let first_difference = client
            .iter()
            .zip(floor.iter())
            .find(|(c, f)| c != f)
            .map(|(c, f)| c.cmp(f));
        assert_eq!(
            first_difference,
            Some(std::cmp::Ordering::Less),
            "{full} parses as {client:?} against {floor:?}. If that is now Greater, the              string has grown a leading number and the comment on `full` needs updating."
        );
    }
}
