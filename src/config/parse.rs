//! Loading a config file into a [`ClientConfig`].
//!
//! The format is chosen by **content**, not by extension, which is what lets an
//! existing `frpc.ini` keep working when it is renamed to `.toml` or left alone.
//! The rule is the Go one (`pkg/config/load.go:65`): try to parse the bytes as
//! INI, and treat the file as legacy INI if that succeeds *and* a `[common]`
//! section exists. Everything else goes to TOML.
//!
//! YAML and JSON are on the Go side's path too, but they are not here yet — a
//! YAML file will fail with a TOML parse error rather than being misread, which
//! is the behaviour that matters for now. See `doc/compatibility.md`.

use std::path::Path;

use crate::error::{Error, Result};

use super::ini;
use super::keys;
use super::model::ClientConfig;

/// Which parser handled a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    LegacyIni,
}

/// A parsed config plus anything the parser wants the caller to know.
///
/// Warnings rather than errors, because they describe parts of the file that
/// were understood but not acted on — most often visitor sections, which this
/// client does not implement yet.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: ClientConfig,
    pub format: ConfigFormat,
    pub warnings: Vec<String>,
}

/// Whether unknown config keys are rejected.
///
/// Strict is the default, matching the Go client's `--strict_config=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    Strict,
    Lenient,
}

impl Strictness {
    pub fn is_strict(self) -> bool {
        self == Strictness::Strict
    }
}

/// Reads and parses a config file, applying defaults.
pub fn load_file(path: &Path) -> Result<LoadedConfig> {
    load_file_with(path, Strictness::Strict)
}

/// Reads and parses a config file with an explicit strictness.
pub fn load_file_with(path: &Path, strictness: Strictness) -> Result<LoadedConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| Error::config(format!("read {}: {err}", path.display())))?;
    let mut loaded = load_from_str_with(&content, strictness).map_err(|err| match err {
        // Carry the path, since the parser only knows about the text.
        Error::Config(message) => Error::Config(format!("{}: {message}", path.display())),
        other => other,
    })?;
    loaded.config.complete();
    Ok(loaded)
}

/// Parses config text, dispatching on its shape.
pub fn load_from_str(content: &str) -> Result<LoadedConfig> {
    load_from_str_with(content, Strictness::Strict)
}

/// Parses config text with an explicit strictness.
pub fn load_from_str_with(content: &str, strictness: Strictness) -> Result<LoadedConfig> {
    if ini::looks_like_legacy_ini(content) {
        let parsed = ini::parse_client_config_detailed(content)?;
        let mut warnings = Vec::new();
        if !parsed.visitors.is_empty() {
            let names: Vec<&str> = parsed
                .visitors
                .iter()
                .filter_map(|visitor| visitor.get("name"))
                .map(String::as_str)
                .collect();
            warnings.push(format!(
                "ignoring {} visitor section(s) [{}]: visitor support is not implemented yet",
                names.len(),
                names.join(", ")
            ));
        }
        return Ok(LoadedConfig {
            config: parsed.config,
            format: ConfigFormat::LegacyIni,
            warnings,
        });
    }

    let config: ClientConfig = match strictness {
        Strictness::Strict => {
            toml::from_str(content).map_err(|err| Error::config(format_toml_error(err)))?
        }
        Strictness::Lenient => {
            let mut value: toml::Value =
                toml::from_str(content).map_err(|err| Error::config(format_toml_error(err)))?;
            prune_unknown_keys(&mut value);
            value
                .try_into()
                .map_err(|err: toml::de::Error| Error::config(format_toml_error(err)))?
        }
    };
    Ok(LoadedConfig {
        config,
        format: ConfigFormat::Toml,
        warnings: Vec::new(),
    })
}

/// Removes keys the model does not know, in place.
///
/// Only needed for lenient mode, and only for TOML: the legacy INI reader has no
/// strictness switch, because its keys are looked up by name rather than decoded
/// against a struct, so an unknown key is already ignored there.
fn prune_unknown_keys(value: &mut toml::Value) {
    let Some(root) = value.as_table_mut() else {
        return;
    };

    retain(root, keys::COMMON_KEYS);
    prune_table(root, "auth", keys::AUTH_KEYS);
    prune_table(root, "log", keys::LOG_KEYS);
    prune_table(root, "webServer", keys::WEB_SERVER_KEYS);
    prune_table(root, "store", keys::STORE_KEYS);
    prune_table(root, "metadatas", &[]); // free-form
    if let Some(transport) = root.get_mut("transport").and_then(|v| v.as_table_mut()) {
        retain(transport, keys::TRANSPORT_KEYS);
        prune_table(transport, "tls", keys::TLS_KEYS);
        prune_table(transport, "quic", keys::QUIC_KEYS);
    }
    if let Some(auth) = root.get_mut("auth").and_then(|v| v.as_table_mut()) {
        prune_table(auth, "oidc", keys::OIDC_KEYS);
    }

    if let Some(proxies) = root.get_mut("proxies").and_then(|v| v.as_array_mut()) {
        for proxy in proxies {
            prune_proxy(proxy);
        }
    }
    if let Some(visitors) = root.get_mut("visitors").and_then(|v| v.as_array_mut()) {
        for visitor in visitors {
            prune_visitor(visitor);
        }
    }
}

fn prune_proxy(value: &mut toml::Value) {
    let Some(proxy) = value.as_table_mut() else {
        return;
    };

    let proxy_type = proxy
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    // The plugin's own keys can be siblings of `type`, so the plugin's key set is
    // folded into the proxy's when a plugin is present.
    let plugin_type = plugin_type_of(proxy);
    let mut allowed: Vec<&str> = keys::PROXY_BASE_KEYS.to_vec();
    allowed.extend_from_slice(keys::QOS_KEYS);
    allowed.extend_from_slice(keys::proxy_type_keys(&proxy_type));
    if let Some(plugin_type) = plugin_type {
        allowed.extend_from_slice(keys::plugin_keys(&plugin_type));
    }
    retain(proxy, &allowed);

    prune_table(proxy, "transport", keys::PROXY_TRANSPORT_KEYS);
    prune_table(proxy, "loadBalancer", keys::LOAD_BALANCER_KEYS);
    prune_table(proxy, "healthCheck", keys::HEALTH_CHECK_KEYS);
    prune_table(proxy, "natTraversal", keys::NAT_TRAVERSAL_KEYS);
    prune_table(proxy, "metadatas", &[]);
    prune_table(proxy, "annotations", &[]);

    // `plugin` is either the name or a table of options.
    if let Some(plugin) = proxy
        .get_mut("plugin")
        .and_then(|value| value.as_table_mut())
    {
        let plugin_type = plugin
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        retain(plugin, keys::plugin_keys(&plugin_type));
    }
}

fn prune_visitor(value: &mut toml::Value) {
    let Some(visitor) = value.as_table_mut() else {
        return;
    };
    let visitor_type = visitor
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let mut allowed: Vec<&str> = keys::VISITOR_BASE_KEYS.to_vec();
    allowed.extend_from_slice(keys::visitor_type_keys(&visitor_type));
    retain(visitor, &allowed);

    prune_table(visitor, "transport", keys::VISITOR_TRANSPORT_KEYS);
    prune_table(visitor, "natTraversal", keys::NAT_TRAVERSAL_KEYS);
}

/// The plugin type named by `plugin`, whether it is a bare string or a table.
fn plugin_type_of(proxy: &toml::map::Map<String, toml::Value>) -> Option<String> {
    match proxy.get("plugin")? {
        toml::Value::String(name) => Some(name.clone()),
        toml::Value::Table(table) => table
            .get("type")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        _ => None,
    }
}

/// Drops every key of `table` not in `allowed`.
///
/// An empty `allowed` means "this table is free-form", used for the
/// user-defined maps (`metadatas`, `annotations`).
fn retain(table: &mut toml::map::Map<String, toml::Value>, allowed: &[&str]) {
    if allowed.is_empty() {
        return;
    }
    // `toml::map::Map`'s `retain` hands the closure a `&str`, not a `&String`.
    table.retain(|key, _| allowed.contains(&key));
}

/// Prunes a nested table, if it is present and a table.
fn prune_table(table: &mut toml::map::Map<String, toml::Value>, key: &str, allowed: &[&str]) {
    if let Some(inner) = table.get_mut(key).and_then(|value| value.as_table_mut()) {
        retain(inner, allowed);
    }
}

/// TOML's own errors already carry line and column, so they are passed through
/// with the prefix the rest of this crate's messages use.
fn format_toml_error(err: toml::de::Error) -> String {
    format!("parse config: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginConfig, ProxyKind};

    #[test]
    fn a_toml_file_produces_a_completed_config() {
        let loaded = load_from_str(
            r#"
            serverAddr = "1.2.3.4"
            serverPort = 7000
            auth.token = "secret"

            [[proxies]]
            name = "ssh"
            type = "tcp"
            localPort = 22
            remotePort = 6000
            "#,
        )
        .unwrap();

        assert_eq!(loaded.format, ConfigFormat::Toml);
        assert!(loaded.warnings.is_empty());
        let config = &loaded.config;
        assert_eq!(config.common.server_addr, "1.2.3.4");
        assert_eq!(config.common.auth.as_ref().unwrap().token, "secret");
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].name, "ssh");
        assert_eq!(config.proxies[0].type_name(), "tcp");
    }

    #[test]
    fn a_legacy_ini_file_is_recognized_by_its_common_section() {
        let loaded = load_from_str(
            r#"
            [common]
            server_addr = 1.2.3.4
            server_port = 7000
            "#,
        )
        .unwrap();
        assert_eq!(loaded.format, ConfigFormat::LegacyIni);
        assert_eq!(loaded.config.common.server_addr, "1.2.3.4");
    }

    #[test]
    fn a_toml_file_without_a_common_section_is_not_read_as_ini() {
        let loaded = load_from_str("serverAddr = \"1.2.3.4\"\n").unwrap();
        assert_eq!(loaded.format, ConfigFormat::Toml);
    }

    /// The `keys` table is a duplicate of the schema, so it is only safe if it
    /// is checked against the real thing. Pruning must remove exactly the keys
    /// strict mode rejects: if a model field is added and `keys` is not updated,
    /// this fails rather than silently dropping the new key in lenient mode.
    #[test]
    fn pruning_matches_strict_mode_exactly() {
        let unknowns = [
            "notARealKey = 1",
            "[log]\nnotARealKey = 1",
            "[transport]\nnotARealKey = 1",
            "[transport.tls]\nnotARealKey = 1",
            "[transport.quic]\nnotARealKey = 1",
            "[webServer]\nnotARealKey = 1",
            "[auth]\nnotARealKey = 1",
            "[auth.oidc]\nnotARealKey = 1",
            "[store]\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"tcp\"\nremotePort = 1\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"http\"\ncustomDomains = [\"a\"]\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"xtcp\"\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"xtcp\"\nnatTraversal.disableAssistedAddrs = true\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"tcp\"\nremotePort = 1\n[proxies.plugin]\ntype = \"socks5\"\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"http\"\ncustomDomains = [\"a\"]\n[proxies.healthCheck]\ntype = \"tcp\"\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"http\"\ncustomDomains = [\"a\"]\n[proxies.loadBalancer]\ngroup = \"g\"\nnotARealKey = 1",
            "[[proxies]]\nname = \"x\"\ntype = \"tcp\"\nremotePort = 1\n[proxies.transport]\nuseEncryption = true\nnotARealKey = 1",
            "[[visitors]]\nname = \"v\"\ntype = \"stcp\"\nserverName = \"s\"\nbindPort = 1\nnotARealKey = 1",
            "[[visitors]]\nname = \"v\"\ntype = \"xtcp\"\nserverName = \"s\"\nbindPort = 1\nnotARealKey = 1",
            "[[visitors]]\nname = \"v\"\ntype = \"stcp\"\nserverName = \"s\"\nbindPort = 1\n[visitors.transport]\nuseEncryption = true\nnotARealKey = 1",
        ];

        for body in unknowns {
            assert!(
                load_from_str_with(body, Strictness::Strict).is_err(),
                "strict mode accepted an unknown key:\n{body}"
            );
            // Lenient mode must drop it and otherwise succeed. A failure here
            // means the key was pruned but the rest did not decode, which is a
            // different bug than a missing entry in `keys`.
            load_from_str_with(body, Strictness::Lenient)
                .unwrap_or_else(|err| panic!("lenient mode rejected:\n{body}\n{err}"));
        }
    }

    /// And the converse: every key the model does know must survive pruning, or
    /// lenient mode would quietly change a config's meaning.
    #[test]
    fn pruning_keeps_every_known_key() {
        let loaded = load_from_str_with(
            r#"
            serverAddr = "1.2.3.4"
            serverPort = 7000
            loginFailExit = false
            udpPacketSize = 1500
            metadatas.region = "eu"
            renameOnConflict = true

            [auth]
            method = "token"
            token = "t"
            additionalScopes = ["HeartBeats"]

            [log]
            to = "console"
            level = "debug"
            maxDays = 3
            format = "json"

            [webServer]
            port = 7400
            metricsEnable = true

            [transport]
            protocol = "tcp"
            wireProtocol = "v1"
            tcpMux = true
            heartbeatInterval = 30

            [transport.tls]
            enable = true

            [transport.quic]
            maxIdleTimeout = 30

            [store]
            path = "./store.json"

            [[proxies]]
            name = "ssh"
            type = "tcp"
            remotePort = 6000
            localIP = "127.0.0.1"
            localPort = 22
            metadatas.var1 = "abc"
            healthCheck.type = "tcp"
            loadBalancer.group = "g"
            transport.useEncryption = true
            transport.bandwidthLimit = "1MB"

            [[proxies]]
            name = "web"
            type = "http"
            customDomains = ["a.example.com"]
            locations = ["/"]
            httpUser = "u"
            httpPassword = "p"
            hostHeaderRewrite = "h"
            routeByHTTPUser = "r"
            requestHeaders.set.x = "y"
            responseHeaders.set.a = "b"
            localPort = 80
            [proxies.plugin]
            type = "https2http"
            localAddr = "127.0.0.1:80"
            crtPath = "./c.crt"
            keyPath = "./c.key"
            enableHTTP2 = false

            [[visitors]]
            name = "vis"
            type = "stcp"
            serverName = "ssh"
            serverUser = "u"
            bindAddr = "127.0.0.1"
            bindPort = 9000
            secretKey = "sk"
            [visitors.transport]
            useCompression = true
            "#,
            Strictness::Lenient,
        )
        .unwrap();

        let config = &loaded.config;
        assert_eq!(config.common.server_addr, "1.2.3.4");
        assert_eq!(config.common.login_fail_exit, Some(false));
        assert_eq!(
            config.common.metadatas.get("region").map(String::as_str),
            Some("eu")
        );
        assert!(config.common.rename_on_conflict);
        assert_eq!(
            config.common.log.as_ref().unwrap().format.as_deref(),
            Some("json")
        );
        assert_eq!(config.common.web_server.as_ref().unwrap().port, 7400);
        assert!(config.common.web_server.as_ref().unwrap().metrics_enable);
        assert_eq!(config.common.store.as_ref().unwrap().path, "./store.json");
        assert_eq!(
            config.common.transport.as_ref().unwrap().heartbeat_interval,
            30
        );

        let ssh = &config.proxies[0];
        assert_eq!(ssh.qos().local_port, 22);
        assert_eq!(
            ssh.qos().metadatas.get("var1").map(String::as_str),
            Some("abc")
        );
        assert_eq!(
            ssh.qos().health_check.as_ref().map(|h| h.r#type.as_str()),
            Some("tcp")
        );
        assert_eq!(
            ssh.qos().load_balancer.as_ref().map(|lb| lb.group.as_str()),
            Some("g")
        );
        let transport = ssh.qos().transport.as_ref().unwrap();
        assert!(transport.use_encryption);
        assert_eq!(transport.bandwidth_limit, "1MB");

        let web = &config.proxies[1];
        match web.kind() {
            ProxyKind::Http {
                custom_domains,
                locations,
                route_by_http_user,
                request_headers,
                ..
            } => {
                assert_eq!(custom_domains, &vec!["a.example.com".to_string()]);
                assert_eq!(locations, &vec!["/".to_string()]);
                assert_eq!(route_by_http_user, "r");
                assert_eq!(
                    request_headers
                        .as_ref()
                        .unwrap()
                        .set
                        .get("x")
                        .map(String::as_str),
                    Some("y")
                );
            }
            other => panic!("expected http, got {other:?}"),
        }
        match web.plugin().unwrap() {
            PluginConfig::Https2Http {
                local_addr,
                crt_path,
                enable_http2,
                ..
            } => {
                assert_eq!(local_addr, "127.0.0.1:80");
                assert_eq!(crt_path, "./c.crt");
                assert_eq!(*enable_http2, Some(false));
            }
            other => panic!("expected https2http, got {other:?}"),
        }

        let visitor = &config.visitors[0];
        assert_eq!(visitor.server_name, "ssh");
        assert_eq!(visitor.bind_port, 9000);
        assert!(visitor.transport.as_ref().unwrap().use_compression);
    }

    /// Visitor sections are understood but not implemented, so they must be
    /// reported rather than silently dropped.
    #[test]
    fn legacy_visitor_sections_produce_a_warning() {
        let loaded = load_from_str(
            r#"
            [common]
            server_addr = 1.2.3.4

            [secret_tcp]
            type = stcp
            sk = abc

            [secret_tcp_visitor]
            role = visitor
            type = stcp
            server_name = secret_tcp
            bind_port = 9000
            "#,
        )
        .unwrap();

        assert_eq!(loaded.config.proxies.len(), 1);
        assert_eq!(loaded.config.proxies[0].name, "secret_tcp");
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded.warnings[0].contains("secret_tcp_visitor"),
            "{:?}",
            loaded.warnings
        );
    }

    #[test]
    fn a_malformed_toml_file_reports_the_line() {
        let err = load_from_str("serverAddr = \n").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("parse config"), "{message}");
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let err = load_file(Path::new("does/not/exist.toml")).unwrap_err();
        assert!(err.to_string().contains("does/not/exist.toml"), "{err}");
    }
}
