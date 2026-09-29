//! The legacy `[common]` INI format.
//!
//! Faithfulness here is mostly about the go-ini options frp sets, because two of
//! them are visible in configs people actually have:
//!
//! * `IgnoreInlineComment: true` — a trailing `# comment` on a value line becomes
//!   **part of the value**. It looks like a bug and is deliberate.
//! * `AllowBooleanKeys: true` — a bare `key` with no `=` is a boolean true.
//!
//! Prefix handling is asymmetric and also deliberate: `meta_*` and `header_*`
//! strip their prefix, while `plugin_*` **keeps** it (the plugin's own config
//! vocabulary is `plugin_local_addr` and friends, so the prefix is part of the
//! key). Visitors are not silently dropped: sections with `role = visitor` land
//! in [`ParsedIni::visitors`] so the caller can say so instead of quietly
//! ignoring half of someone's config.

use std::collections::BTreeMap;

use crate::crypto::Secret;
use crate::error::{Error, Result};
use crate::util::range::parse_range_numbers;

use super::model::{
    AuthClientConfig, ClientCommonConfig, ClientConfig, ClientTransportConfig, HeaderOperations,
    HealthCheckConfig, LoadBalancerConfig, LogConfig, PluginConfig, ProxyConfig, ProxyKind,
    ProxyTransport, Qos, StoreConfig, TlsClientConfig, WebServerConfig,
};

/// A parsed INI file, plus the sections the client model cannot hold yet.
#[derive(Debug, Clone, Default)]
pub struct ParsedIni {
    pub config: ClientConfig,
    /// Sections with `role = visitor`, kept as raw key/value maps.
    pub visitors: Vec<BTreeMap<String, String>>,
}

/// Whether the text should be handled as legacy INI: it must parse as INI *and*
/// have a `[common]` section, matching `DetectLegacyINIFormat`.
pub fn looks_like_legacy_ini(content: &str) -> bool {
    match parse_ini(content) {
        Ok(file) => file.sections.contains_key("common"),
        Err(_) => false,
    }
}

/// Parses the client config, keeping the visitor sections.
pub fn parse_client_config_detailed(content: &str) -> Result<ParsedIni> {
    let file = parse_ini(content)?;

    let common = file
        .sections
        .get("common")
        .ok_or_else(|| Error::config("legacy ini config requires a [common] section"))?;

    let mut config = ClientConfig {
        common: common_from_ini(common)?,
        proxies: Vec::new(),
        visitors: Vec::new(),
    };
    let mut visitors = Vec::new();

    for (name, section) in &file.sections {
        if name == "common" || name == "DEFAULT" {
            continue;
        }
        // `[range:name]` sections expand into one proxy per port pair.
        let (base_name, is_range) = match name.strip_prefix("range:") {
            Some(rest) => (rest.trim().to_string(), true),
            None => (name.clone(), false),
        };

        if section.get("role").map(String::as_str) == Some("visitor") {
            let mut visitor = section.clone();
            visitor.insert("name".into(), base_name);
            visitors.push(visitor);
            continue;
        }

        if is_range {
            config
                .proxies
                .extend(expand_range_section(&base_name, section)?);
        } else {
            config.proxies.push(proxy_from_ini(&base_name, section)?);
        }
    }

    Ok(ParsedIni { config, visitors })
}

/// Expands a `[range:name]` section into one proxy per index, named
/// `name_<i>` after the expanded `local_port` / `remote_port` pair.
fn expand_range_section(
    name: &str,
    section: &BTreeMap<String, String>,
) -> Result<Vec<ProxyConfig>> {
    let local = section
        .get("local_port")
        .ok_or_else(|| Error::config(format!("[{name}] range section needs local_port")))?;
    let remote = section
        .get("remote_port")
        .ok_or_else(|| Error::config(format!("[{name}] range section needs remote_port")))?;

    let locals = parse_range_numbers(local)?;
    let remotes = parse_range_numbers(remote)?;
    if locals.len() != remotes.len() {
        return Err(Error::config(
            "local ports number should be same with remote ports number",
        ));
    }

    let mut out = Vec::with_capacity(locals.len());
    for (index, (local_port, remote_port)) in locals.into_iter().zip(remotes).enumerate() {
        let mut section = section.clone();
        section.insert("local_port".into(), local_port.to_string());
        section.insert("remote_port".into(), remote_port.to_string());
        out.push(proxy_from_ini(&format!("{name}_{index}"), &section)?);
    }
    Ok(out)
}

fn common_from_ini(section: &BTreeMap<String, String>) -> Result<ClientCommonConfig> {
    let get = |key: &str| get_string(section, key);
    let get_int = |key: &str| -> Result<i64> { int_of(section, "[common]", key) };
    let get_u16 = |key: &str| -> Result<u16> { u16_of(section, "[common]", key) };
    let get_bool = |key: &str| get_bool(section, key);
    let split = |key: &str| split_list(&get(key));

    let mut scopes = Vec::new();
    if get_bool("authenticate_heartbeats") {
        scopes.push("HeartBeats".to_string());
    }
    if get_bool("authenticate_new_work_conns") {
        scopes.push("NewWorkConns".to_string());
    }

    let mut metadatas = get_dotted_map(section, "meta");
    // The undotted form `meta_var1` is what the older examples use.
    for (key, value) in section {
        if let Some(name) = key.strip_prefix("meta_") {
            metadatas.insert(name.to_string(), value.clone());
        }
    }

    let auth = AuthClientConfig {
        method: get("authentication_method"),
        additional_scopes: scopes,
        token: get("token"),
        oidc: None,
    };

    let transport = ClientTransportConfig {
        protocol: get("protocol"),
        wire_protocol: get("wire_protocol"),
        dial_server_timeout: get_int("dial_server_timeout")?,
        dial_server_keepalive: get_int("dial_server_keepalive")?,
        connect_server_local_ip: get("connect_server_local_ip"),
        proxy_url: get("http_proxy"),
        pool_count: get_int("pool_count")? as i32,
        tcp_mux: section.get("tcp_mux").map(|value| value.trim() == "true"),
        tcp_mux_keepalive_interval: get_int("tcp_mux_keepalive_interval")?,
        heartbeat_interval: get_int("heartbeat_interval")?,
        heartbeat_timeout: get_int("heartbeat_timeout")?,
        quic: None,
        tls: Some(TlsClientConfig {
            enable: section
                .get("tls_enable")
                .map(|value| value.trim() == "true"),
            disable_custom_tls_first_byte: section
                .get("disable_custom_tls_first_byte")
                .map(|value| value.trim() == "true"),
            cert_file: get("tls_cert_file"),
            key_file: get("tls_key_file"),
            trusted_ca_file: get("tls_trusted_ca_file"),
            server_name: get("tls_server_name"),
        }),
    };

    let web_server = if section.contains_key("admin_port") {
        Some(WebServerConfig {
            addr: get("admin_addr"),
            port: get_u16("admin_port")?,
            user: get("admin_user"),
            password: get("admin_pwd"),
            assets_dir: get("assets_dir"),
            pprof_enable: get_bool("pprof_enable"),
            metrics_enable: false,
        })
    } else {
        None
    };

    // The legacy key is `log_file`; `log_way` is dropped, matching Go's
    // conversion.
    let log = Some(LogConfig {
        to: get("log_file"),
        level: get("log_level"),
        max_days: get_int("log_max_days")?,
        disable_print_color: get_bool("disable_log_color"),
        format: None,
        color: None,
    });

    let store = {
        let path = get("store_path");
        if path.is_empty() {
            None
        } else {
            Some(StoreConfig { path })
        }
    };

    Ok(ClientCommonConfig {
        auth: Some(auth),
        user: get("user"),
        client_id: get("client_id"),
        server_addr: get("server_addr"),
        server_port: get_u16("server_port")?,
        nat_hole_stun_server: get("nat_hole_stun_server"),
        dns_server: get("dns_server"),
        login_fail_exit: section
            .get("login_fail_exit")
            .map(|value| value.trim() == "true"),
        start: split("start"),
        log,
        web_server,
        transport: Some(transport),
        udp_packet_size: get_int("udp_packet_size")?,
        metadatas,
        includes: split("includes"),
        store,
        rename_on_conflict: false,
    })
}

fn proxy_from_ini(name: &str, section: &BTreeMap<String, String>) -> Result<ProxyConfig> {
    let get = |key: &str| get_string(section, key);
    let get_int = |key: &str| -> Result<i64> { int_of(section, name, key) };
    let get_u16 = |key: &str| -> Result<u16> { u16_of(section, name, key) };
    let get_bool = |key: &str| get_bool(section, key);
    let split = |key: &str| split_list(&get(key));

    // `type` defaults to tcp.
    let type_name = {
        let raw = get("type");
        if raw.is_empty() {
            "tcp".to_string()
        } else {
            raw
        }
    };

    let custom_domains = split("custom_domains");
    let subdomain = get("subdomain");

    let kind = match type_name.as_str() {
        "tcp" => ProxyKind::Tcp {
            remote_port: get_u16("remote_port")?,
        },
        "udp" => ProxyKind::Udp {
            remote_port: get_u16("remote_port")?,
        },
        "http" => ProxyKind::Http {
            custom_domains,
            subdomain,
            locations: split("locations"),
            http_user: get("http_user"),
            http_password: get("http_pwd"),
            host_header_rewrite: get("host_header_rewrite"),
            request_headers: header_operations(section, "header_"),
            response_headers: None,
            route_by_http_user: get("route_by_http_user"),
        },
        "https" => ProxyKind::Https {
            custom_domains,
            subdomain,
        },
        "tcpmux" => ProxyKind::Tcpmux {
            custom_domains,
            subdomain,
            http_user: get("http_user"),
            http_password: get("http_pwd"),
            route_by_http_user: get("route_by_http_user"),
            multiplexer: get("multiplexer"),
        },
        "stcp" => ProxyKind::Stcp {
            secret_key: Secret::new(get("sk")),
            allow_users: split("allow_users"),
        },
        "xtcp" => ProxyKind::Xtcp {
            secret_key: Secret::new(get("sk")),
            allow_users: split("allow_users"),
            // The INI format has no natTraversal keys.
            nat_traversal: None,
        },
        "sudp" => ProxyKind::Sudp {
            secret_key: Secret::new(get("sk")),
            allow_users: split("allow_users"),
        },
        other => {
            return Err(Error::config(format!("[{name}] invalid type [{other}]")));
        }
    };

    let mut metadatas = get_dotted_map(section, "meta");
    for (key, value) in section {
        if let Some(stripped) = key.strip_prefix("meta_") {
            metadatas.insert(stripped.to_string(), value.clone());
        }
    }

    // The examples write these both ways: the legacy `health_check_type` and the
    // dotted `healthCheck.type`.
    let health_check_type = {
        let legacy = get("health_check_type");
        if legacy.is_empty() {
            get("healthCheck.type")
        } else {
            legacy
        }
    };
    let health_check = if health_check_type.is_empty() {
        None
    } else {
        Some(HealthCheckConfig {
            r#type: health_check_type,
            timeout_seconds: get_int("health_check_timeout_s")? as i32,
            max_failed: get_int("health_check_max_failed")? as i32,
            interval_seconds: get_int("health_check_interval_s")? as i32,
            // The legacy key is `health_check_url`, not `health_check_path`.
            path: {
                let legacy = get("health_check_url");
                if legacy.is_empty() {
                    get("healthCheck.path")
                } else {
                    legacy
                }
            },
            http_headers: Vec::new(),
        })
    };

    let load_balancer = {
        let group = {
            let legacy = get("group");
            if legacy.is_empty() {
                get("loadBalancer.group")
            } else {
                legacy
            }
        };
        if group.is_empty() {
            None
        } else {
            Some(LoadBalancerConfig {
                group,
                group_key: {
                    let legacy = get("group_key");
                    if legacy.is_empty() {
                        get("loadBalancer.groupKey")
                    } else {
                        legacy
                    }
                },
            })
        }
    };

    let transport = ProxyTransport {
        use_encryption: get_bool("use_encryption") || get_bool("transport.useEncryption"),
        use_compression: get_bool("use_compression") || get_bool("transport.useCompression"),
        bandwidth_limit: {
            let legacy = get("bandwidth_limit");
            if legacy.is_empty() {
                get("transport.bandwidthLimit")
            } else {
                legacy
            }
        },
        bandwidth_limit_mode: {
            let legacy = get("bandwidth_limit_mode");
            if legacy.is_empty() {
                get("transport.bandwidthLimitMode")
            } else {
                legacy
            }
        },
        proxy_protocol_version: {
            let legacy = get("proxy_protocol_version");
            if legacy.is_empty() {
                get("transport.proxyProtocolVersion")
            } else {
                legacy
            }
        },
    };

    Ok(ProxyConfig {
        name: name.to_string(),
        enabled: None,
        kind,
        qos: Qos {
            transport: Some(transport),
            metadatas,
            annotations: {
                let dotted = get_dotted_map(section, "annotations");
                if dotted.is_empty() {
                    get_dotted_map(section, "annotations.")
                } else {
                    dotted
                }
            },
            load_balancer,
            health_check,
            local_ip: get("local_ip"),
            local_port: get_u16("local_port")?,
        },
        plugin: plugin_from_ini(section),
    })
}

/// `plugin_*` keys are kept verbatim (the prefix is part of the key), while
/// `header_*` keys have theirs stripped.
fn header_operations(section: &BTreeMap<String, String>, prefix: &str) -> Option<HeaderOperations> {
    let mut set = BTreeMap::new();
    for (key, value) in section {
        if let Some(name) = key.strip_prefix(prefix) {
            if !name.is_empty() {
                set.insert(name.to_string(), value.clone());
            }
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(HeaderOperations { set })
    }
}

fn plugin_from_ini(section: &BTreeMap<String, String>) -> Option<PluginConfig> {
    let r#type = section.get("plugin").cloned().unwrap_or_default();
    if r#type.is_empty() {
        return None;
    }
    let get = |key: &str| get_string(section, key);
    let headers = || header_operations(section, "plugin_header_");

    Some(match r#type.as_str() {
        "http2https" => PluginConfig::Http2Https {
            local_addr: get("plugin_local_addr"),
            host_header_rewrite: get("plugin_host_header_rewrite"),
            request_headers: headers(),
        },
        "http2http" => PluginConfig::Http2Http {
            local_addr: get("plugin_local_addr"),
            host_header_rewrite: get("plugin_host_header_rewrite"),
            request_headers: headers(),
        },
        "https2http" => PluginConfig::Https2Http {
            local_addr: get("plugin_local_addr"),
            host_header_rewrite: get("plugin_host_header_rewrite"),
            request_headers: headers(),
            enable_http2: None,
            crt_path: get("plugin_crt_path"),
            key_path: get("plugin_key_path"),
        },
        "https2https" => PluginConfig::Https2Https {
            local_addr: get("plugin_local_addr"),
            host_header_rewrite: get("plugin_host_header_rewrite"),
            request_headers: headers(),
            enable_http2: None,
            crt_path: get("plugin_crt_path"),
            key_path: get("plugin_key_path"),
        },
        "http_proxy" => PluginConfig::HttpProxy {
            http_user: get("plugin_http_user"),
            http_password: get("plugin_http_passwd"),
        },
        "socks5" => PluginConfig::Socks5 {
            username: get("plugin_user"),
            password: get("plugin_passwd"),
        },
        "static_file" => PluginConfig::StaticFile {
            local_path: get("plugin_local_path"),
            strip_prefix: get("plugin_strip_prefix"),
            http_user: get("plugin_http_user"),
            http_password: get("plugin_http_passwd"),
        },
        "unix_domain_socket" => PluginConfig::UnixDomainSocket {
            unix_path: get("plugin_unix_path"),
        },
        "tls2raw" => PluginConfig::Tls2Raw {
            local_addr: get("plugin_local_addr"),
            crt_path: get("plugin_crt_path"),
            key_path: get("plugin_key_path"),
        },
        // Anything else keeps its name without options, matching the Go
        // conversion.
        _ => PluginConfig::VirtualNet {},
    })
}

// --- helpers -------------------------------------------------------------

/// Reads a dotted key into a `bool`, treating anything but the literal `true` as
/// false — the same leniency the rest of this reader has.
fn get_bool(section: &BTreeMap<String, String>, key: &str) -> bool {
    section
        .get(key)
        .map(|value| value.trim() == "true")
        .unwrap_or(false)
}

/// Reads a dotted key into a string.
fn get_string(section: &BTreeMap<String, String>, key: &str) -> String {
    section.get(key).cloned().unwrap_or_default()
}

/// Reads a `<prefix>.<name>` group into a map, as `metadatas.var1 = "abc"` does.
fn get_dotted_map(section: &BTreeMap<String, String>, prefix: &str) -> BTreeMap<String, String> {
    let prefix = format!("{prefix}.");
    let mut out = BTreeMap::new();
    for (key, value) in section {
        if let Some(name) = key.strip_prefix(&prefix) {
            out.insert(name.to_string(), value.clone());
        }
    }
    out
}

/// Splits a comma-separated list, matching go-ini's slice handling.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn int_of(section: &BTreeMap<String, String>, where_: &str, key: &str) -> Result<i64> {
    let raw = get_string(section, key);
    if raw.is_empty() {
        return Ok(0);
    }
    raw.trim()
        .parse::<i64>()
        .map_err(|_| Error::config(format!("{where_} {key} is not a number: {raw}")))
}

fn u16_of(section: &BTreeMap<String, String>, where_: &str, key: &str) -> Result<u16> {
    let value = int_of(section, where_, key)?;
    u16::try_from(value).map_err(|_| Error::config(format!("{where_} {key} out of range: {value}")))
}

// --- the INI reader ------------------------------------------------------

/// A parsed INI file: an ordered list of sections, each an ordered key/value map.
#[derive(Debug, Clone, Default)]
struct IniFile {
    /// Keyed by section name. Keys and section names are **case sensitive**,
    /// because frp disables go-ini's `Insensitive` options.
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

/// Parses the subset of INI that frp's configs use.
///
/// Rules, all taken from the go-ini options frp sets:
///
/// * section and key names are case sensitive;
/// * `key = value` and `key: value` are both accepted;
/// * a line that is just `key` is a boolean key with value `true`;
/// * `#` and `;` start a comment only at the *start* of a line — inline comments
///   are part of the value (`IgnoreInlineComment`);
/// * a `\` at the end of a line continues the value;
/// * keys outside any section land in `DEFAULT`.
fn parse_ini(content: &str) -> Result<IniFile> {
    let mut file = IniFile::default();
    let mut current = "DEFAULT".to_string();
    file.sections.insert(current.clone(), BTreeMap::new());

    let mut lines = content.lines().peekable();
    while let Some(raw_line) = lines.next() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[') {
            let name = name
                .strip_suffix(']')
                .ok_or_else(|| Error::config(format!("ini: malformed section header: {line}")))?;
            current = name.trim().to_string();
            file.sections.entry(current.clone()).or_default();
            continue;
        }

        let (key, value) = match split_key_value(line) {
            Some(pair) => pair,
            // A bare key is `true`, which is what `AllowBooleanKeys` buys.
            None => (line.to_string(), "true".to_string()),
        };

        let mut value = value.trim().to_string();
        // A trailing backslash continues the value onto the next line.
        while value.ends_with('\\') {
            value.pop();
            match lines.next() {
                Some(next) => {
                    value.push('\n');
                    value.push_str(next.trim());
                }
                None => break,
            }
        }

        file.sections
            .entry(current.clone())
            .or_default()
            .insert(key.trim().to_string(), value);
    }

    Ok(file)
}

/// Splits `key = value` or `key: value` at whichever separator comes first. A
/// line with neither is a boolean key.
fn split_key_value(line: &str) -> Option<(String, String)> {
    let index = match (line.find('='), line.find(':')) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    Some((line[..index].to_string(), line[index + 1..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_files_with_a_common_section() {
        assert!(looks_like_legacy_ini("[common]\nserver_addr = 1.2.3.4\n"));
        assert!(!looks_like_legacy_ini("serverAddr = \"1.2.3.4\"\n"));
        assert!(!looks_like_legacy_ini("[ssh]\ntype = tcp\n"));
    }

    #[test]
    fn inline_comments_stay_in_the_value() {
        // `IgnoreInlineComment: true`. Changing this would silently break
        // configs in the wild, so it is pinned.
        let file = parse_ini("[common]\ntoken = abc # not a comment\n").unwrap();
        assert_eq!(
            file.sections["common"]["token"],
            "abc # not a comment".to_string()
        );
    }

    #[test]
    fn full_line_comments_are_skipped() {
        let file = parse_ini("# a comment\n; another\n[common]\ntoken = abc\n").unwrap();
        assert_eq!(file.sections["common"]["token"], "abc");
        assert_eq!(file.sections["common"].len(), 1);
    }

    #[test]
    fn a_bare_key_is_a_boolean() {
        let file = parse_ini("[common]\nsome_flag\n").unwrap();
        assert_eq!(file.sections["common"]["some_flag"], "true");
    }

    #[test]
    fn both_separators_are_accepted() {
        let file = parse_ini("[common]\na = 1\nb : 2\n").unwrap();
        assert_eq!(file.sections["common"]["a"], "1");
        assert_eq!(file.sections["common"]["b"], "2");
    }

    #[test]
    fn a_trailing_backslash_continues_the_value() {
        let file = parse_ini("[common]\nlist = a,\\\nb\n").unwrap();
        assert_eq!(file.sections["common"]["list"], "a,\nb");
    }

    #[test]
    fn section_and_key_names_are_case_sensitive() {
        let file = parse_ini("[common]\nToken = abc\n").unwrap();
        assert!(!file.sections["common"].contains_key("token"));
        assert_eq!(file.sections["common"]["Token"], "abc");
    }

    #[test]
    fn range_sections_expand_into_one_proxy_per_pair() {
        let parsed = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [range:tcp_port]
            type = tcp
            local_port = 6000-6001
            remote_port = 7000-7001
            "#,
        )
        .unwrap();

        let names: Vec<&str> = parsed
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.name.as_str())
            .collect();
        assert_eq!(names, vec!["tcp_port_0", "tcp_port_1"]);
        match parsed.config.proxies[1].kind {
            ProxyKind::Tcp { remote_port } => assert_eq!(remote_port, 7001),
            ref other => panic!("expected tcp, got {other:?}"),
        }
    }

    #[test]
    fn a_range_section_with_mismatched_counts_is_rejected() {
        let err = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [range:tcp_port]
            local_port = 6000-6001
            remote_port = 7000
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("same with"), "{err}");
    }

    #[test]
    fn plugin_keys_keep_their_prefix_and_header_keys_do_not() {
        let parsed = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [web]
            type = http
            custom_domains = a.example.com
            local_port = 80
            plugin = https2http
            plugin_local_addr = 127.0.0.1:80
            plugin_crt_path = ./server.crt
            plugin_key_path = ./server.key
            header_X-From-Where = frp
            meta_var1 = 123
            "#,
        )
        .unwrap();

        let proxy = &parsed.config.proxies[0];
        match proxy.plugin.as_ref().unwrap() {
            PluginConfig::Https2Http {
                local_addr,
                crt_path,
                ..
            } => {
                assert_eq!(local_addr, "127.0.0.1:80");
                assert_eq!(crt_path, "./server.crt");
            }
            other => panic!("expected https2http, got {other:?}"),
        }
        // `header_` is stripped, `meta_` is stripped, `plugin_` is not.
        assert_eq!(
            proxy.qos.metadatas.get("var1").map(String::as_str),
            Some("123")
        );
        match &proxy.kind {
            ProxyKind::Http {
                request_headers, ..
            } => {
                let set = &request_headers.as_ref().unwrap().set;
                assert_eq!(set.get("X-From-Where").map(String::as_str), Some("frp"));
            }
            other => panic!("expected http, got {other:?}"),
        }
    }

    #[test]
    fn the_dotted_spelling_is_accepted_for_nested_proxy_keys() {
        let parsed = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [ssh]
            type = tcp
            local_port = 22
            remote_port = 6001
            transport.bandwidthLimit = 1MB
            transport.useEncryption = true
            loadBalancer.group = test_group
            healthCheck.type = tcp
            "#,
        )
        .unwrap();

        let proxy = &parsed.config.proxies[0];
        let transport = proxy.qos.transport.as_ref().unwrap();
        assert_eq!(transport.bandwidth_limit, "1MB");
        assert!(transport.use_encryption);
        assert_eq!(
            proxy.qos.load_balancer.as_ref().unwrap().group,
            "test_group"
        );
        assert_eq!(proxy.qos.health_check.as_ref().unwrap().r#type, "tcp");
    }

    #[test]
    fn the_legacy_health_check_url_becomes_path() {
        let parsed = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [web]
            type = http
            custom_domains = a.example.com
            local_port = 80
            health_check_type = http
            health_check_url = /status
            "#,
        )
        .unwrap();
        assert_eq!(
            parsed.config.proxies[0]
                .qos
                .health_check
                .as_ref()
                .unwrap()
                .path,
            "/status"
        );
    }

    #[test]
    fn an_unknown_proxy_type_is_rejected() {
        let err = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4

            [weird]
            type = carrier-pigeon
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid type"), "{err}");
    }

    #[test]
    fn legacy_flags_land_in_the_right_places() {
        let parsed = parse_client_config_detailed(
            r#"
            [common]
            server_addr = 1.2.3.4
            admin_addr = 127.0.0.1
            admin_port = 7400
            log_file = console
            log_level = debug
            authenticate_heartbeats = true
            meta_region = eu
            pprof_enable = true
            "#,
        )
        .unwrap();

        let common = &parsed.config.common;
        let web = common.web_server.as_ref().unwrap();
        assert_eq!(web.port, 7400);
        assert!(web.pprof_enable);
        assert_eq!(common.log.as_ref().unwrap().to, "console");
        assert_eq!(common.log.as_ref().unwrap().level, "debug");
        assert_eq!(
            common.metadatas.get("region").map(String::as_str),
            Some("eu")
        );
        assert_eq!(
            common.auth.as_ref().unwrap().additional_scopes,
            vec!["HeartBeats".to_string()]
        );
    }
}
