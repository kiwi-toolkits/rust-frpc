//! The rename-retry strategy: what to do when `frps` says a proxy name is taken.
//!
//! Not an frp feature. Upstream's client treats a name conflict as an ordinary
//! start failure and re-sends **the same name** every thirty seconds forever, so
//! a second client on a device that already has one never comes up. This is a
//! deliberate extension: the name gets a `r1_` style prefix and another attempt.
//!
//! The shape it walks, and the pacing, were chosen rather than inherited:
//!
//! ```text
//! original  ✗ (1/2)  →  3s
//! original  ✗ (2/2)  →  3s, becomes r1_
//! r1_orig   ✗ (1/1)  →  3s, becomes r2_      ← each rN_ gets a single shot
//! r2_orig   ✗ (1/1)  →  3s, becomes r3_
//! r3_orig   ✗ (1/1)  →  60s, back to the original
//! ```
//!
//! Two independent knobs: how many times a name is tried ([`ORIGINAL_TRIES`],
//! [`RENAMED_TRIES`]) and how long to wait before the next attempt
//! ([`CONFLICT_RETRY_DELAY`], and [`CYCLE_RESTART_DELAY`] for the one step that
//! starts the cycle over).
//!
//! The pacing is its own, separate from the twenty seconds a proxy waits after
//! an ordinary start error. A conflict is a *certainty* — the server answered
//! immediately — so waiting twenty seconds to try the next name is twenty
//! seconds of a dead tunnel for no information. The sixty seconds at the end is
//! the cooldown after every candidate has been used; without it the cycle would
//! repeat indefinitely at three-second intervals.
//!
//! **Nothing here strips a prefix.** The reference implementation in
//! `rust-tiny-frpc` has to, because it applies prefixes to a command line that
//! may already carry one. Here every candidate is built from the configured
//! name, which is pristine by construction, so stripping would be dead code —
//! and harmful dead code, because a proxy genuinely named `r1_web` would be
//! "stripped" to `web` and never renamed at all. The reference's own comment
//! warns about exactly that.

use std::time::Duration;

use crate::config::ProxyKind;

/// The highest `rN_` in the sequence; past it the walk returns to the original.
pub const MAX_SEQUENCE: u32 = 3;

/// How many times the configured name is tried before the first rename.
pub const ORIGINAL_TRIES: u32 = 2;

/// How many times each `rN_` name is tried. One: the original is the name worth
/// retrying, and a candidate is only a fallback.
pub const RENAMED_TRIES: u32 = 1;

/// The wait between two attempts of a conflict cycle.
pub const CONFLICT_RETRY_DELAY: Duration = Duration::from_secs(3);

/// The wait before starting a new cycle, after `r3_` has failed too.
pub const CYCLE_RESTART_DELAY: Duration = Duration::from_secs(60);

/// Which name a proxy is currently being registered under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// The name from the config file.
    Original,
    /// `r{n}_` in front of the configured name.
    Renamed(u32),
}

impl Candidate {
    /// What this candidate puts in front of the configured name — `"r1_"`, or
    /// empty for the original.
    ///
    /// One place decides the spelling, so a name and the domains that move with
    /// it cannot drift apart.
    pub fn prefix(self) -> String {
        match self {
            Candidate::Original => String::new(),
            Candidate::Renamed(n) => format!("r{n}_"),
        }
    }

    /// The local name to put on the wire for this candidate.
    pub fn name(self, configured: &str) -> String {
        format!("{}{configured}", self.prefix())
    }

    /// How many attempts this candidate is allowed before the walk moves on.
    pub fn tries_allowed(self) -> u32 {
        match self {
            Candidate::Original => ORIGINAL_TRIES,
            Candidate::Renamed(_) => RENAMED_TRIES,
        }
    }
}

/// The next candidate: `original → r1_ → r2_ → r3_ → original`.
pub fn advance(candidate: Candidate) -> Candidate {
    match candidate {
        Candidate::Original => Candidate::Renamed(1),
        Candidate::Renamed(n) if n < MAX_SEQUENCE => Candidate::Renamed(n + 1),
        Candidate::Renamed(_) => Candidate::Original,
    }
}

/// How long to wait before sending the next attempt, given the candidate just
/// advanced to.
///
/// Only the step that starts a new cycle waits; the rest are three seconds. The
/// distinction lives here rather than at the call site so that the pacing is
/// testable on its own.
pub fn delay_after_advancing(to: Candidate) -> Duration {
    match to {
        Candidate::Original => CYCLE_RESTART_DELAY,
        Candidate::Renamed(_) => CONFLICT_RETRY_DELAY,
    }
}

/// `r{n}_` in front of `name` — `hq1925369` → `r1_hq1925369`.
pub fn prefix(n: u32, name: &str) -> String {
    format!("r{n}_{name}")
}

/// Whether a server-side start error means "that name is taken".
///
/// Matched on text because frp has no error code on the wire. Two strings:
///
/// * `already exists` — `Control.RegisterProxy` refusing a name that is in use
///   (`server/control.go`). frps checks `PxyManager.Exist(name)` **without
///   checking who owns it**, so a client re-registering its own name gets this
///   too; the caller has to tell those apart by phase, not by the message.
/// * `router config conflict` — `pkg/util/vhost/router.go` refusing a domain
///   already claimed. This is what an `http`, `https` or `tcpmux` proxy hits
///   *after* its name is free, and ignoring it would leave those types renamed
///   only until they stopped colliding on the name.
///
/// A server with `detailedErrorsToClient = false` sends only
/// `new proxy [x] error`, which is what every other start failure looks like, so
/// nothing is renamed in that case. Being conservative there is deliberate:
/// renaming a proxy because it could not reach its local service would trade one
/// problem for a stranger one.
pub fn conflicts(error: &str) -> bool {
    error.contains("already exists") || error.contains("router config conflict")
}

/// Moves a proxy's domains along with its name.
///
/// `customDomains` and `subdomain` are how an `http`, `https` or `tcpmux` proxy
/// is actually reached, so renaming the proxy without them trades a name
/// conflict for a domain conflict and changes nothing. Types with no domains
/// (`tcp`, `udp`, `stcp`, `sudp`, `xtcp`) are left alone — their public side is
/// a port or a secret key, and `remotePort` is not part of the name.
///
/// A wildcard keeps its `*.` in front: `*.example.com` becomes
/// `*.r1_example.com`, not `r1_*.example.com`. frps's vhost router only matches a
/// wildcard whose host starts with `*.`, so the naive form registers
/// successfully and then routes nothing at all, silently.
pub fn rewrite_domains(kind: &mut ProxyKind, prefix: &str) {
    let Some((custom_domains, subdomain)) = kind.domains_mut() else {
        return;
    };
    for domain in custom_domains.iter_mut() {
        *domain = match domain.strip_prefix("*.") {
            Some(rest) => format!("*.{prefix}{rest}"),
            None => format!("{prefix}{domain}"),
        };
    }
    if !subdomain.is_empty() {
        *subdomain = format!("{prefix}{subdomain}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_proxy(custom_domains: &[&str], subdomain: &str) -> ProxyKind {
        ProxyKind::Http {
            custom_domains: custom_domains.iter().map(|d| d.to_string()).collect(),
            subdomain: subdomain.to_string(),
            locations: Vec::new(),
            http_user: String::new(),
            http_password: String::new(),
            host_header_rewrite: String::new(),
            request_headers: None,
            response_headers: None,
            route_by_http_user: String::new(),
        }
    }

    /// The whole walk, in order. Spelling it out is the point: the sequence and
    /// the pacing are the feature.
    #[test]
    fn the_walk_is_original_then_r1_r2_r3_then_back() {
        let mut candidate = Candidate::Original;
        let mut seen = vec![candidate];
        for _ in 0..4 {
            candidate = advance(candidate);
            seen.push(candidate);
        }
        assert_eq!(
            seen,
            vec![
                Candidate::Original,
                Candidate::Renamed(1),
                Candidate::Renamed(2),
                Candidate::Renamed(3),
                Candidate::Original,
            ]
        );
    }

    /// The original is worth retrying; a candidate is only a fallback.
    #[test]
    fn the_original_gets_more_attempts_than_a_candidate() {
        assert_eq!(Candidate::Original.tries_allowed(), 2);
        for n in 1..=MAX_SEQUENCE {
            assert_eq!(Candidate::Renamed(n).tries_allowed(), 1);
        }
    }

    /// Only the step that starts a new cycle waits; everything else is one tick.
    #[test]
    fn only_the_return_to_the_original_waits_a_minute() {
        assert_eq!(
            delay_after_advancing(advance(Candidate::Renamed(MAX_SEQUENCE))),
            CYCLE_RESTART_DELAY
        );
        for candidate in [
            Candidate::Original,
            Candidate::Renamed(1),
            Candidate::Renamed(2),
        ] {
            assert_eq!(
                delay_after_advancing(advance(candidate)),
                CONFLICT_RETRY_DELAY,
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn a_candidate_name_carries_its_prefix() {
        assert_eq!(Candidate::Original.name("hq1925369"), "hq1925369");
        assert_eq!(Candidate::Renamed(1).name("hq1925369"), "r1_hq1925369");
        assert_eq!(prefix(3, "web"), "r3_web");
    }

    /// A name that already looks like a candidate is not "stripped": there is no
    /// stripping at all, and a proxy genuinely named `r1_web` gets renamed to
    /// `r1_r1_web` rather than staying put. That is the honest outcome — the
    /// prefix is ours, and the configured name is not ours to edit.
    #[test]
    fn a_name_that_looks_like_a_candidate_is_left_to_the_caller() {
        assert_eq!(prefix(1, "r1_web"), "r1_r1_web");
    }

    #[test]
    fn both_conflict_messages_are_recognised() {
        assert!(conflicts("proxy [hq1925369] already exists"));
        assert!(conflicts("new proxy [web] error: router config conflict"));
    }

    /// Anything else must not rename: a proxy whose local service is down would
    /// otherwise move through the whole sequence for no reason.
    #[test]
    fn other_start_errors_are_not_conflicts() {
        for error in [
            "",
            "port already used",
            "new proxy [web] error",
            "connect to local service error",
        ] {
            assert!(!conflicts(error), "{error:?}");
        }
    }

    /// Domains move with the name, which is the whole point for a routed proxy.
    #[test]
    fn the_domains_move_with_the_name() {
        let mut kind = http_proxy(&["hq1925369.frp.iotisyun.com"], "hq1925369");
        rewrite_domains(&mut kind, "r1_");
        let (domains, subdomain) = kind.domains();
        assert_eq!(domains, &vec!["r1_hq1925369.frp.iotisyun.com".to_string()]);
        assert_eq!(subdomain, "r1_hq1925369");
    }

    /// A wildcard has to keep its `*.` in front, or frps's vhost router cannot
    /// match it and the proxy carries nothing while looking healthy.
    #[test]
    fn a_wildcard_keeps_its_star_where_the_router_needs_it() {
        let mut kind = http_proxy(&["*.example.com", "plain.example.com"], "");
        rewrite_domains(&mut kind, "r2_");
        let (domains, _) = kind.domains();
        assert_eq!(
            domains,
            &vec![
                "*.r2_example.com".to_string(),
                "r2_plain.example.com".to_string()
            ]
        );
    }

    #[test]
    fn an_empty_subdomain_stays_empty() {
        let mut kind = http_proxy(&["a.example.com"], "");
        rewrite_domains(&mut kind, "r1_");
        assert_eq!(kind.domains().1, "");
    }

    /// Types with no domains are untouched — their public side is a port.
    #[test]
    fn a_tcp_proxy_has_nothing_to_rewrite() {
        let mut kind = ProxyKind::Tcp { remote_port: 6000 };
        rewrite_domains(&mut kind, "r1_");
        assert_eq!(kind, ProxyKind::Tcp { remote_port: 6000 });
    }

    #[test]
    fn every_routed_type_is_covered() {
        let cases: Vec<(&str, ProxyKind)> = vec![
            ("http", http_proxy(&["a.example.com"], "")),
            (
                "https",
                ProxyKind::Https {
                    custom_domains: vec!["a.example.com".into()],
                    subdomain: String::new(),
                },
            ),
            (
                "tcpmux",
                ProxyKind::Tcpmux {
                    custom_domains: vec!["a.example.com".into()],
                    subdomain: String::new(),
                    multiplexer: String::new(),
                    http_user: String::new(),
                    http_password: String::new(),
                    route_by_http_user: String::new(),
                },
            ),
        ];
        for (name, mut kind) in cases {
            rewrite_domains(&mut kind, "r1_");
            assert_eq!(
                kind.domains().0,
                &vec!["r1_a.example.com".to_string()],
                "{name}"
            );
        }
    }
}
