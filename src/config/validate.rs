//! Configuration validation, mirroring `pkg/config/v1/validation`.
//!
//! The rule set is deliberately the Go one, message text included, because a
//! config that `frpc` rejects should be rejected here with a recognizable
//! complaint. Two categories exist: [`Severity::Error`] stops the client, and
//! [`Severity::Warning`] is printed and ignored — Go makes the same distinction,
//! notably for TLS files configured while TLS is off.

use crate::error::Result;

use super::model::{ClientConfig, ProxyConfig, ProxyKind};
use super::{
    SUPPORTED_AUTH_METHODS, SUPPORTED_AUTH_SCOPES, SUPPORTED_LOG_LEVELS, SUPPORTED_PROXY_TYPES,
    SUPPORTED_TRANSPORT_PROTOCOLS, SUPPORTED_WIRE_PROTOCOLS,
};

/// How seriously to take an issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One problem found in a config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub severity: Severity,
    /// Where it is, e.g. `proxy web` or `transport.tls`.
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        if self.field.is_empty() {
            write!(f, "{label}: {}", self.message)
        } else {
            write!(f, "{label}: {}: {}", self.field, self.message)
        }
    }
}

/// Validates a completed config. `Ok` may still carry warnings.
pub fn validate(config: &ClientConfig) -> Result<Vec<ValidationIssue>> {
    let mut issues = Vec::new();

    if let Some(transport) = config.common.transport.as_ref() {
        if !SUPPORTED_TRANSPORT_PROTOCOLS.contains(&transport.protocol.as_str()) {
            issues.push(error(
                "transport.protocol",
                format!(
                    "invalid protocol, optional values are {:?}",
                    SUPPORTED_TRANSPORT_PROTOCOLS
                ),
            ));
        }
        if !SUPPORTED_WIRE_PROTOCOLS.contains(&transport.wire_protocol.as_str()) {
            issues.push(error(
                "transport.wireProtocol",
                format!(
                    "invalid wire protocol, optional values are {:?}",
                    SUPPORTED_WIRE_PROTOCOLS
                ),
            ));
        }
        // Both being disabled is the default with tcpMux on, so only an
        // inconsistent *enabled* pair is an error.
        if transport.heartbeat_interval > 0
            && transport.heartbeat_timeout > 0
            && transport.heartbeat_timeout < transport.heartbeat_interval
        {
            issues.push(error(
                "transport.heartbeatTimeout",
                "invalid transport.heartbeatTimeout, heartbeat timeout should not less than heartbeat interval",
            ));
        }
        if let Some(tls) = transport.tls.as_ref() {
            if tls.enable == Some(false) {
                for (field, value) in [
                    ("transport.tls.certFile", &tls.cert_file),
                    ("transport.tls.keyFile", &tls.key_file),
                    ("transport.tls.trustedCaFile", &tls.trusted_ca_file),
                ] {
                    if !value.is_empty() {
                        issues.push(warning(
                            field,
                            format!("{field} is invalid when transport.tls.enable is false"),
                        ));
                    }
                }
            }
        }
    }

    if let Some(auth) = config.common.auth.as_ref() {
        if !SUPPORTED_AUTH_METHODS.contains(&auth.method.as_str()) {
            issues.push(error(
                "auth.method",
                format!("invalid auth method, optional values are {SUPPORTED_AUTH_METHODS:?}"),
            ));
        }
        for scope in &auth.additional_scopes {
            if !SUPPORTED_AUTH_SCOPES.contains(&scope.as_str()) {
                issues.push(error(
                    "auth.additionalScopes",
                    format!(
                        "invalid auth additional scopes, optional values are {SUPPORTED_AUTH_SCOPES:?}"
                    ),
                ));
            }
        }
    }

    if let Some(log) = config.common.log.as_ref() {
        if !SUPPORTED_LOG_LEVELS.contains(&log.level.as_str()) {
            issues.push(error(
                "log.level",
                format!("invalid log level, optional values are {SUPPORTED_LOG_LEVELS:?}"),
            ));
        }
    }

    if !(0..=65535).contains(&config.common.server_port) {
        // `serverPort` is a u16, so this can only be zero, which `complete()`
        // has already repaired. Kept for symmetry with the Go check.
        issues.push(error(
            "serverPort",
            "port number must be in the range 0..65535",
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    for proxy in &config.proxies {
        if !seen.insert(proxy.name.clone()) {
            issues.push(error(
                &format!("proxy {}", proxy.name),
                format!("proxy name [{}] is duplicated", proxy.name),
            ));
        }
        issues.extend(validate_proxy(proxy));
    }

    Ok(issues)
}

fn validate_proxy(proxy: &ProxyConfig) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let field = format!("proxy {}", proxy.name);
    let kind = proxy.kind.type_name();

    if !SUPPORTED_PROXY_TYPES.contains(&kind) {
        issues.push(error(&field, format!("unknown proxy type: {kind}")));
        return issues;
    }

    if let Some(transport) = proxy.qos.transport.as_ref() {
        if !matches!(transport.proxy_protocol_version.as_str(), "" | "v1" | "v2") {
            issues.push(error(
                &field,
                format!(
                    "not support proxy protocol version: {}",
                    transport.proxy_protocol_version
                ),
            ));
        }
        if !matches!(transport.bandwidth_limit_mode.as_str(), "client" | "server") {
            issues.push(error(
                &field,
                "bandwidth limit mode should be client or server",
            ));
        }
        if !transport.bandwidth_limit.is_empty() {
            if let Err(message) = parse_bandwidth(&transport.bandwidth_limit) {
                issues.push(error(&field, message));
            }
        }
    }

    // `localPort` is only meaningful without a plugin; with one, the plugin owns
    // the backend address.
    if proxy.plugin.is_none()
        && proxy.qos.local_port == 0
        && kind != "stcp"
        && kind != "xtcp"
        && kind != "sudp"
    {
        issues.push(error(&field, "localPort should not be empty".to_string()));
    }

    if let Some(health) = proxy.qos.health_check.as_ref() {
        if !matches!(health.r#type.as_str(), "" | "tcp" | "http") {
            issues.push(error(
                &field,
                format!("not support health check type: {}", health.r#type),
            ));
        }
        if health.r#type == "http" && health.path.is_empty() {
            issues.push(error(&field, "health check path should not be empty"));
        }
    }

    if proxy.kind.requires_domain() {
        let (domains, subdomain) = proxy.kind.domains();
        if domains.is_empty() && subdomain.is_empty() {
            issues.push(error(
                &field,
                "subdomain and custom domains should not be both empty",
            ));
        }
        if !subdomain.is_empty() && (subdomain.contains('.') || subdomain.contains('*')) {
            issues.push(error(&field, "'.' and '*' are not supported in subdomain"));
        }
    }

    if let ProxyKind::Tcpmux { multiplexer, .. } = &proxy.kind {
        if !matches!(multiplexer.as_str(), "" | "httpconnect") {
            issues.push(error(
                &field,
                format!("not support multiplexer: {multiplexer}"),
            ));
        }
    }

    if let Some(plugin) = proxy.plugin.as_ref() {
        if let Some(issue) = validate_plugin(&field, plugin) {
            issues.push(issue);
        }
    }

    issues
}

fn validate_plugin(field: &str, plugin: &super::model::PluginConfig) -> Option<ValidationIssue> {
    use super::model::PluginConfig;
    match plugin {
        PluginConfig::Http2Https { local_addr, .. }
        | PluginConfig::Http2Http { local_addr, .. }
        | PluginConfig::Https2Http { local_addr, .. }
        | PluginConfig::Https2Https { local_addr, .. }
        | PluginConfig::Tls2Raw { local_addr, .. }
            if local_addr.is_empty() =>
        {
            Some(error(field, "plugin localAddr is required"))
        }
        PluginConfig::StaticFile { local_path, .. } if local_path.is_empty() => {
            Some(error(field, "plugin localPath is required"))
        }
        PluginConfig::UnixDomainSocket { unix_path } if unix_path.is_empty() => {
            Some(error(field, "plugin unixPath is required"))
        }
        _ => None,
    }
}

/// `"1MB"` / `"1.5KB"` / `""`. Mirrors `types.BandwidthQuantity`: only `KB` and
/// `MB` are recognized, and `GB` in particular is an error rather than a very
/// large number.
fn parse_bandwidth(value: &str) -> std::result::Result<i64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let (number, multiplier) = if let Some(rest) = trimmed.strip_suffix("MB") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = trimmed.strip_suffix("KB") {
        (rest, 1024)
    } else {
        return Err(format!("unit not support: {value}"));
    };
    number
        .trim()
        .parse::<f64>()
        .map(|value| (value * multiplier as f64) as i64)
        .map_err(|_| format!("invalid bandwidth limit: {value}"))
}

fn error(field: &str, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        severity: Severity::Error,
        field: field.to_string(),
        message: message.into(),
    }
}

fn warning(field: &str, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        severity: Severity::Warning,
        field: field.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_proxy(kind: ProxyKind) -> ClientConfig {
        let mut config = ClientConfig {
            proxies: vec![ProxyConfig {
                name: "test".into(),
                enabled: None,
                kind,
                qos: crate::config::Qos {
                    local_port: 22,
                    ..crate::config::Qos::default()
                },
                plugin: None,
                wire_type: String::new(),
            }],
            ..ClientConfig::default()
        };
        config.complete();
        config
    }

    fn errors(config: &ClientConfig) -> Vec<String> {
        validate(config)
            .unwrap()
            .into_iter()
            .filter(|issue| issue.severity == Severity::Error)
            .map(|issue| issue.message)
            .collect()
    }

    #[test]
    fn a_minimal_config_validates_cleanly() {
        let config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        assert!(errors(&config).is_empty(), "{:?}", errors(&config));
    }

    #[test]
    fn an_unknown_transport_protocol_is_an_error() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        config.common.transport.as_mut().unwrap().protocol = "carrier-pigeon".into();
        assert!(errors(&config)[0].contains("invalid protocol"));
    }

    #[test]
    fn duplicate_proxy_names_are_rejected() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        let duplicate = config.proxies[0].clone();
        config.proxies.push(duplicate);
        assert!(errors(&config)
            .iter()
            .any(|message| message.contains("is duplicated")));
    }

    #[test]
    fn http_without_any_domain_is_rejected() {
        let config = config_with_proxy(ProxyKind::Http {
            custom_domains: vec![],
            subdomain: String::new(),
            locations: vec![],
            http_user: String::new(),
            http_password: String::new(),
            host_header_rewrite: String::new(),
            request_headers: None,
            response_headers: None,
            route_by_http_user: String::new(),
        });
        assert!(errors(&config)[0].contains("subdomain and custom domains"));
    }

    #[test]
    fn a_dotted_subdomain_is_rejected() {
        let config = config_with_proxy(ProxyKind::Http {
            custom_domains: vec![],
            subdomain: "a.b".into(),
            locations: vec![],
            http_user: String::new(),
            http_password: String::new(),
            host_header_rewrite: String::new(),
            request_headers: None,
            response_headers: None,
            route_by_http_user: String::new(),
        });
        assert!(errors(&config)[0].contains("'.' and '*' are not supported"));
    }

    #[test]
    fn tls_files_configured_while_tls_is_off_warn_rather_than_fail() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        let tls = config
            .common
            .transport
            .as_mut()
            .unwrap()
            .tls
            .as_mut()
            .unwrap();
        tls.enable = Some(false);
        tls.cert_file = "client.crt".into();

        let issues = validate(&config).unwrap();
        let warnings: Vec<_> = issues
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0]
            .message
            .contains("invalid when transport.tls.enable is false"));
        assert!(errors(&config).is_empty());
    }

    #[test]
    fn an_inconsistent_heartbeat_pair_is_rejected() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        let transport = config.common.transport.as_mut().unwrap();
        transport.heartbeat_interval = 30;
        transport.heartbeat_timeout = 10;
        assert!(errors(&config)[0].contains("should not less than"));
    }

    #[test]
    fn bandwidth_units_other_than_kb_and_mb_are_rejected() {
        assert_eq!(parse_bandwidth("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_bandwidth("1.5KB").unwrap(), 1536);
        assert_eq!(parse_bandwidth("").unwrap(), 0);
        assert!(parse_bandwidth("1GB").is_err());
    }

    #[test]
    fn a_proxy_protocol_version_other_than_v1_or_v2_is_rejected() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        config.proxies[0]
            .qos
            .transport
            .as_mut()
            .unwrap()
            .proxy_protocol_version = "v3".into();
        assert!(errors(&config)[0].contains("not support proxy protocol version"));
    }

    #[test]
    fn a_plugin_without_its_required_key_is_rejected() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        config.proxies[0].plugin = Some(crate::config::PluginConfig::UnixDomainSocket {
            unix_path: String::new(),
        });
        assert!(errors(&config)[0].contains("unixPath is required"));
    }

    #[test]
    fn a_plugin_suppresses_the_local_port_requirement() {
        let mut config = config_with_proxy(ProxyKind::Tcp { remote_port: 6000 });
        config.proxies[0].qos.local_port = 0;
        assert!(errors(&config)
            .iter()
            .any(|message| message.contains("localPort")));

        config.proxies[0].plugin = Some(crate::config::PluginConfig::Socks5 {
            username: String::new(),
            password: String::new(),
        });
        assert!(!errors(&config)
            .iter()
            .any(|message| message.contains("localPort")));
    }
}
