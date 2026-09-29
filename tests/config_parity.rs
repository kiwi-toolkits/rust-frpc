//! Parses the Go repository's own example configs and asserts the results.
//!
//! These files are the ground truth for the config surface: if `frpc_full_example.toml`
//! stops parsing, it means a key this client does not know about was added
//! upstream, which is exactly the kind of drift a compatibility guarantee has to
//! catch. The fixtures are checked in under `tests/fixtures/` and are copies of
//! `conf/frpc_full_example.toml` and `conf/legacy/frpc_legacy_full.ini` from
//! `fatedier/frp` at `d20a2329` (version 0.71.0).

use std::path::PathBuf;

use rust_frpc::config::{self, ConfigFormat, ProxyKind, Severity};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn the_full_toml_example_parses() {
    let loaded = config::load_file(&fixture("frpc_full_example.toml")).expect("parse full example");
    assert_eq!(loaded.format, ConfigFormat::Toml);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);

    let config = &loaded.config;
    assert_eq!(config.common.user, "your_name");
    assert_eq!(config.common.client_id, "your_client_id");
    assert_eq!(config.common.udp_packet_size, 1500);
    assert_eq!(
        config.common.metadatas.get("var1").map(String::as_str),
        Some("abc")
    );

    // Every proxy type in the file must land on its own variant.
    let types: Vec<&str> = config
        .proxies
        .iter()
        .map(|proxy| proxy.type_name())
        .collect();
    for expected in ["tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp"] {
        assert!(
            types.contains(&expected),
            "no {expected} proxy among {types:?}"
        );
    }

    // The nested keys the examples use must have reached their fields.
    let web01 = config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "web01")
        .expect("web01");
    assert_eq!(web01.qos().local_ip, "127.0.0.1");
    assert_eq!(web01.qos().local_port, 80);
    let health = web01.qos().health_check.as_ref().expect("healthCheck");
    assert_eq!(health.r#type, "http");
    assert_eq!(health.path, "/status");
    assert_eq!(health.http_headers.len(), 1);
    assert_eq!(health.http_headers[0].name, "x-from-where");

    // No validation errors: the upstream example should be a valid config.
    let issues = config::validate(config).expect("validate");
    let errors: Vec<_> = issues
        .iter()
        .filter(|issue| issue.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn the_full_legacy_ini_example_parses() {
    let loaded = config::load_file(&fixture("frpc_legacy_full.ini")).expect("parse legacy ini");
    assert_eq!(loaded.format, ConfigFormat::LegacyIni);

    let config = &loaded.config;
    assert_eq!(config.common.server_addr, "0.0.0.0");
    assert_eq!(config.common.server_port, 7000);
    assert_eq!(config.common.auth.as_ref().unwrap().token, "12345678");

    // `[range:]` sections must have expanded, and the ordinary sections must all
    // be present: 19 sections in the fixture, two with `role = visitor`.
    let names: Vec<&str> = config
        .proxies
        .iter()
        .map(|proxy| proxy.name.as_str())
        .collect();
    for expected in [
        "ssh",
        "ssh_random",
        "dns",
        "web01",
        "web02",
        "secret_tcp",
        "p2p_tcp",
        "tcpmuxhttpconnect",
    ] {
        assert!(
            names.contains(&expected),
            "missing [{expected}] in {names:?}"
        );
    }
    assert!(
        names.iter().any(|name| name.starts_with("tcp_port_")),
        "range:tcp_port did not expand: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.starts_with("udp_port_")),
        "range:udp_port did not expand: {names:?}"
    );

    // The visitors are understood but not implemented, so they must be reported.
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].contains("secret_tcp_visitor"));
    assert!(loaded.warnings[0].contains("p2p_tcp_visitor"));

    // Spot-check that the tricky INI conversions landed.
    let ssh = config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "ssh")
        .expect("ssh");
    let transport = ssh.qos().transport.as_ref().unwrap();
    assert_eq!(transport.bandwidth_limit, "1MB");
    assert_eq!(
        ssh.qos().metadatas.get("var1").map(String::as_str),
        Some("123")
    );
    assert_eq!(
        ssh.qos().load_balancer.as_ref().map(|lb| lb.group.as_str()),
        Some("test_group")
    );
    assert_eq!(
        ssh.qos().health_check.as_ref().map(|h| h.r#type.as_str()),
        Some("tcp")
    );

    // `health_check_url` becomes `path`; `header_` is stripped.
    let web01 = config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "web01")
        .expect("web01");
    assert_eq!(
        web01.qos().health_check.as_ref().map(|h| h.path.as_str()),
        Some("/status")
    );
    match web01.kind() {
        ProxyKind::Http {
            request_headers,
            locations,
            ..
        } => {
            assert_eq!(locations, &vec!["/".to_string(), "/pic".to_string()]);
            assert_eq!(
                request_headers
                    .as_ref()
                    .unwrap()
                    .set
                    .get("X-From-Where")
                    .map(String::as_str),
                Some("frp")
            );
        }
        other => panic!("web01 should be http, got {other:?}"),
    }

    // The legacy plugin keys, where `plugin_` keeps its prefix.
    let plugin_proxy = config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "plugin_socks5")
        .expect("plugin_socks5");
    match plugin_proxy.plugin().expect("plugin") {
        rust_frpc::config::PluginConfig::Socks5 { username, password } => {
            assert_eq!(username, "abc");
            assert_eq!(password, "abc");
        }
        other => panic!("expected socks5, got {other:?}"),
    }
}

/// The minimal example that ships as `conf/frpc.toml`.
#[test]
fn the_minimal_example_parses() {
    let loaded = config::load_file(&fixture("frpc.toml")).expect("parse minimal");
    assert_eq!(loaded.config.proxies.len(), 1);
    assert_eq!(loaded.config.proxies[0].name, "test-tcp");
    assert_eq!(loaded.config.proxies[0].type_name(), "tcp");
    match loaded.config.proxies[0].kind() {
        ProxyKind::Tcp { remote_port } => assert_eq!(*remote_port, 6000),
        other => panic!("expected tcp, got {other:?}"),
    }
}
