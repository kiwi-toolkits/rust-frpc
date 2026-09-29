//! The client configuration model, mirroring `pkg/config/v1/client.go` and
//! `proxy.go`.
//!
//! Field names are the TOML/JSON keys, so the structs read the same as a config
//! file. Defaults live in [`ClientConfig::complete`] rather than in `Default`,
//! because "unset" and "set to the default" have to stay distinguishable until
//! the file has been fully read — the Go client makes exactly the same
//! distinction with its `Complete()` pass.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::Secret;

/// Tri-state boolean: absent, explicitly true, explicitly false.
///
/// Go uses `*bool` for this and the difference matters — `tcpMux` defaults to
/// true, so "absent" and "false" must not collapse.
pub type TriState = Option<bool>;

/// `auth` on the client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthClientConfig {
    /// `token` (default) or `oidc`.
    #[serde(rename = "method", skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// Any of `HeartBeats`, `NewWorkConns`.
    #[serde(rename = "additionalScopes", skip_serializing_if = "Vec::is_empty")]
    pub additional_scopes: Vec<String>,
    #[serde(rename = "token", skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(rename = "oidc", skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcClientConfig>,
}

/// `auth.oidc`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcClientConfig {
    #[serde(rename = "clientID", skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(rename = "clientSecret", skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    #[serde(rename = "audience", skip_serializing_if = "String::is_empty")]
    pub audience: String,
    #[serde(rename = "scope", skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(rename = "tokenEndpointURL", skip_serializing_if = "String::is_empty")]
    pub token_endpoint_url: String,
    #[serde(
        rename = "additionalEndpointParams",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub additional_endpoint_params: BTreeMap<String, String>,
    #[serde(rename = "trustedCaFile", skip_serializing_if = "String::is_empty")]
    pub trusted_ca_file: String,
    #[serde(rename = "insecureSkipVerify", skip_serializing_if = "is_false")]
    pub insecure_skip_verify: bool,
    #[serde(rename = "proxyURL", skip_serializing_if = "String::is_empty")]
    pub proxy_url: String,
}

/// `log`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `console` (default) or a file path.
    #[serde(rename = "to", skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(rename = "level", skip_serializing_if = "String::is_empty")]
    pub level: String,
    /// Not `skip_serializing_if`, matching Go's tag on this one field.
    #[serde(rename = "maxDays")]
    pub max_days: i64,
    #[serde(rename = "disablePrintColor", skip_serializing_if = "is_false")]
    pub disable_print_color: bool,

    // --- additions, not present in the Go config -------------------------
    /// `text` (default) or `json`.
    #[serde(rename = "format", skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// `auto` (default), `always` or `never`.
    #[serde(rename = "color", skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// `webServer`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebServerConfig {
    #[serde(rename = "addr", skip_serializing_if = "String::is_empty")]
    pub addr: String,
    #[serde(rename = "port", skip_serializing_if = "is_zero")]
    pub port: u16,
    #[serde(rename = "user", skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(rename = "password", skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(rename = "assetsDir", skip_serializing_if = "String::is_empty")]
    pub assets_dir: String,
    #[serde(rename = "pprofEnable", skip_serializing_if = "is_false")]
    pub pprof_enable: bool,

    // --- additions -------------------------------------------------------
    /// Lightweight proxy/connection/traffic counters at `/metrics`.
    #[serde(rename = "metricsEnable", skip_serializing_if = "is_false")]
    pub metrics_enable: bool,
}

/// `transport.tls` on the client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsClientConfig {
    /// Defaults to **true** since frp v0.50.0.
    #[serde(rename = "enable", skip_serializing_if = "Option::is_none")]
    pub enable: TriState,
    /// Defaults to **true** since frp v0.50.0, i.e. the `0x17` first byte is
    /// *not* sent unless this is explicitly set to false.
    #[serde(
        rename = "disableCustomTLSFirstByte",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_custom_tls_first_byte: TriState,
    #[serde(rename = "certFile", skip_serializing_if = "String::is_empty")]
    pub cert_file: String,
    #[serde(rename = "keyFile", skip_serializing_if = "String::is_empty")]
    pub key_file: String,
    #[serde(rename = "trustedCaFile", skip_serializing_if = "String::is_empty")]
    pub trusted_ca_file: String,
    #[serde(rename = "serverName", skip_serializing_if = "String::is_empty")]
    pub server_name: String,
}

/// `transport.quic`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicOptions {
    #[serde(rename = "keepalivePeriod", skip_serializing_if = "is_zero")]
    pub keepalive_period: i64,
    #[serde(rename = "maxIdleTimeout", skip_serializing_if = "is_zero")]
    pub max_idle_timeout: i64,
    #[serde(rename = "maxIncomingStreams", skip_serializing_if = "is_zero")]
    pub max_incoming_streams: i64,
}

/// `transport` on the client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientTransportConfig {
    /// `tcp`, `kcp`, `quic`, `websocket` or `wss`.
    #[serde(rename = "protocol", skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// `v1` (default) or `v2`.
    #[serde(rename = "wireProtocol", skip_serializing_if = "String::is_empty")]
    pub wire_protocol: String,
    #[serde(rename = "dialServerTimeout", skip_serializing_if = "is_zero")]
    pub dial_server_timeout: i64,
    #[serde(rename = "dialServerKeepalive", skip_serializing_if = "is_zero")]
    pub dial_server_keepalive: i64,
    #[serde(
        rename = "connectServerLocalIP",
        skip_serializing_if = "String::is_empty"
    )]
    pub connect_server_local_ip: String,
    #[serde(rename = "proxyURL", skip_serializing_if = "String::is_empty")]
    pub proxy_url: String,
    #[serde(rename = "poolCount", skip_serializing_if = "is_zero")]
    pub pool_count: i32,
    #[serde(rename = "tcpMux", skip_serializing_if = "Option::is_none")]
    pub tcp_mux: TriState,
    #[serde(rename = "tcpMuxKeepaliveInterval", skip_serializing_if = "is_zero")]
    pub tcp_mux_keepalive_interval: i64,
    /// Disabled (-1) by default whenever `tcpMux` is on.
    #[serde(rename = "heartbeatInterval", skip_serializing_if = "is_zero")]
    pub heartbeat_interval: i64,
    /// Disabled (-1) by default whenever `tcpMux` is on.
    #[serde(rename = "heartbeatTimeout", skip_serializing_if = "is_zero")]
    pub heartbeat_timeout: i64,
    #[serde(rename = "quic", skip_serializing_if = "Option::is_none")]
    pub quic: Option<QuicOptions>,
    #[serde(rename = "tls", skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsClientConfig>,
}

/// `store`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(rename = "path", skip_serializing_if = "String::is_empty")]
    pub path: String,
}

/// The client-wide configuration: everything outside `[[proxies]]` and
/// `[[visitors]]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientCommonConfig {
    #[serde(rename = "auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthClientConfig>,
    /// Prefixes every proxy's wire name with `"{user}."`.
    #[serde(rename = "user", skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(rename = "clientID", skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(rename = "serverAddr", skip_serializing_if = "String::is_empty")]
    pub server_addr: String,
    #[serde(rename = "serverPort", skip_serializing_if = "is_zero")]
    pub server_port: u16,
    #[serde(rename = "natHoleStunServer", skip_serializing_if = "String::is_empty")]
    pub nat_hole_stun_server: String,
    #[serde(rename = "dnsServer", skip_serializing_if = "String::is_empty")]
    pub dns_server: String,
    /// `true` by default: exit instead of retrying forever when the first login
    /// fails.
    #[serde(rename = "loginFailExit", skip_serializing_if = "Option::is_none")]
    pub login_fail_exit: TriState,
    /// Allowlist of proxy names. Empty means all of them.
    #[serde(rename = "start", skip_serializing_if = "Vec::is_empty")]
    pub start: Vec<String>,
    #[serde(rename = "log", skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
    #[serde(rename = "webServer", skip_serializing_if = "Option::is_none")]
    pub web_server: Option<WebServerConfig>,
    #[serde(rename = "transport", skip_serializing_if = "Option::is_none")]
    pub transport: Option<ClientTransportConfig>,
    #[serde(rename = "udpPacketSize", skip_serializing_if = "is_zero")]
    pub udp_packet_size: i64,
    #[serde(rename = "metadatas", skip_serializing_if = "BTreeMap::is_empty")]
    pub metadatas: BTreeMap<String, String>,
    /// Glob paths of extra config files to merge.
    #[serde(rename = "includes", skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,
    #[serde(rename = "store", skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreConfig>,

    // --- additions -------------------------------------------------------
    /// Enables the rename-retry strategy. Off by default because it changes a
    /// proxy's public name.
    #[serde(rename = "renameOnConflict", skip_serializing_if = "is_false")]
    pub rename_on_conflict: bool,
}

/// `transport` inside a proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyTransport {
    #[serde(rename = "useEncryption", skip_serializing_if = "is_false")]
    pub use_encryption: bool,
    #[serde(rename = "useCompression", skip_serializing_if = "is_false")]
    pub use_compression: bool,
    /// A string like `"1MB"` or `"10KB"`; empty means unlimited. Kept verbatim so
    /// it round-trips through the admin API the way frp's `BandwidthQuantity`
    /// does.
    #[serde(rename = "bandwidthLimit", skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit: String,
    /// `client` (default) or `server`.
    #[serde(
        rename = "bandwidthLimitMode",
        skip_serializing_if = "String::is_empty"
    )]
    pub bandwidth_limit_mode: String,
    #[serde(
        rename = "proxyProtocolVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub proxy_protocol_version: String,
}

/// `loadBalancer` inside a proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoadBalancerConfig {
    #[serde(rename = "group", skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(rename = "groupKey", skip_serializing_if = "String::is_empty")]
    pub group_key: String,
}

/// `healthCheck` inside a proxy.
///
/// The defaults for the numeric fields are applied by the health monitor at
/// runtime rather than by `complete()`, matching Go: a value of 0 still means
/// "use the default", not "zero seconds".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// `tcp`, `http`, or empty for "disabled".
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    #[serde(rename = "timeoutSeconds", skip_serializing_if = "is_zero")]
    pub timeout_seconds: i32,
    #[serde(rename = "maxFailed", skip_serializing_if = "is_zero")]
    pub max_failed: i32,
    #[serde(rename = "intervalSeconds", skip_serializing_if = "is_zero")]
    pub interval_seconds: i32,
    #[serde(rename = "path", skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(rename = "httpHeaders", skip_serializing_if = "Vec::is_empty")]
    pub http_headers: Vec<HttpHeader>,
}

/// `healthCheck.httpHeaders[]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpHeader {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "value")]
    pub value: String,
}

/// `natTraversal`, used by `xtcp` proxies and visitors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatTraversalConfig {
    /// When true, only STUN-discovered public addresses are offered, and the
    /// local interfaces are left out. Useful on slow VPN links.
    #[serde(rename = "disableAssistedAddrs", skip_serializing_if = "is_false")]
    pub disable_assisted_addrs: bool,
}

/// `requestHeaders` / `responseHeaders`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderOperations {
    #[serde(rename = "set", skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
}

/// Quality-of-service knobs shared by every proxy type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Qos {
    #[serde(rename = "transport", skip_serializing_if = "Option::is_none")]
    pub transport: Option<ProxyTransport>,
    #[serde(rename = "metadatas", skip_serializing_if = "BTreeMap::is_empty")]
    pub metadatas: BTreeMap<String, String>,
    #[serde(rename = "annotations", skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(rename = "loadBalancer", skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<LoadBalancerConfig>,
    #[serde(rename = "healthCheck", skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(rename = "localIP", skip_serializing_if = "String::is_empty")]
    pub local_ip: String,
    #[serde(rename = "localPort", skip_serializing_if = "is_zero")]
    pub local_port: u16,
}
/// The eight proxy types, as one enum carrying each type's own keys.
///
/// Serde's `tag` on `type` reproduces the Go side's `TypedProxyConfig`: the
/// discriminator is read first and the rest is decoded against that variant, so
/// an unknown key inside a `tcp` proxy is rejected the way Go's strict decoder
/// rejects it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ProxyKind {
    Tcp {
        #[serde(rename = "remotePort", default, skip_serializing_if = "is_zero")]
        remote_port: u16,
    },
    Udp {
        #[serde(rename = "remotePort", default, skip_serializing_if = "is_zero")]
        remote_port: u16,
    },
    Http {
        #[serde(
            rename = "customDomains",
            default,
            skip_serializing_if = "Vec::is_empty"
        )]
        custom_domains: Vec<String>,
        #[serde(
            rename = "subdomain",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        subdomain: String,
        #[serde(rename = "locations", default, skip_serializing_if = "Vec::is_empty")]
        locations: Vec<String>,
        #[serde(rename = "httpUser", default, skip_serializing_if = "String::is_empty")]
        http_user: String,
        #[serde(
            rename = "httpPassword",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        http_password: String,
        #[serde(
            rename = "hostHeaderRewrite",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        host_header_rewrite: String,
        #[serde(
            rename = "requestHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        request_headers: Option<HeaderOperations>,
        #[serde(
            rename = "responseHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        response_headers: Option<HeaderOperations>,
        #[serde(
            rename = "routeByHTTPUser",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        route_by_http_user: String,
    },
    Https {
        #[serde(
            rename = "customDomains",
            default,
            skip_serializing_if = "Vec::is_empty"
        )]
        custom_domains: Vec<String>,
        #[serde(
            rename = "subdomain",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        subdomain: String,
    },
    Tcpmux {
        #[serde(
            rename = "customDomains",
            default,
            skip_serializing_if = "Vec::is_empty"
        )]
        custom_domains: Vec<String>,
        #[serde(
            rename = "subdomain",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        subdomain: String,
        #[serde(rename = "httpUser", default, skip_serializing_if = "String::is_empty")]
        http_user: String,
        #[serde(
            rename = "httpPassword",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        http_password: String,
        #[serde(
            rename = "routeByHTTPUser",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        route_by_http_user: String,
        #[serde(
            rename = "multiplexer",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        multiplexer: String,
    },
    Stcp {
        #[serde(
            rename = "secretKey",
            default,
            skip_serializing_if = "Secret::is_empty"
        )]
        secret_key: Secret,
        #[serde(rename = "allowUsers", default, skip_serializing_if = "Vec::is_empty")]
        allow_users: Vec<String>,
    },
    Xtcp {
        #[serde(
            rename = "secretKey",
            default,
            skip_serializing_if = "Secret::is_empty"
        )]
        secret_key: Secret,
        #[serde(rename = "allowUsers", default, skip_serializing_if = "Vec::is_empty")]
        allow_users: Vec<String>,
        #[serde(
            rename = "natTraversal",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        nat_traversal: Option<NatTraversalConfig>,
    },
    Sudp {
        #[serde(
            rename = "secretKey",
            default,
            skip_serializing_if = "Secret::is_empty"
        )]
        secret_key: Secret,
        #[serde(rename = "allowUsers", default, skip_serializing_if = "Vec::is_empty")]
        allow_users: Vec<String>,
    },
}

impl ProxyKind {
    /// The `type` string, as it goes on the wire.
    pub fn type_name(&self) -> &'static str {
        match self {
            ProxyKind::Tcp { .. } => "tcp",
            ProxyKind::Udp { .. } => "udp",
            ProxyKind::Http { .. } => "http",
            ProxyKind::Https { .. } => "https",
            ProxyKind::Tcpmux { .. } => "tcpmux",
            ProxyKind::Stcp { .. } => "stcp",
            ProxyKind::Xtcp { .. } => "xtcp",
            ProxyKind::Sudp { .. } => "sudp",
        }
    }

    /// Whether this type reads from a local TCP port (as opposed to a plugin or
    /// a visitor listener).
    pub fn is_tcp_family(&self) -> bool {
        !matches!(self, ProxyKind::Udp { .. } | ProxyKind::Sudp { .. })
    }

    /// Whether the type requires at least one domain or a subdomain.
    pub fn requires_domain(&self) -> bool {
        matches!(
            self,
            ProxyKind::Http { .. } | ProxyKind::Https { .. } | ProxyKind::Tcpmux { .. }
        )
    }

    /// The domains and subdomain this proxy claims, for validation and for the
    /// rename strategy.
    pub fn domains(&self) -> (&[String], &str) {
        match self {
            ProxyKind::Http {
                custom_domains,
                subdomain,
                ..
            }
            | ProxyKind::Https {
                custom_domains,
                subdomain,
            }
            | ProxyKind::Tcpmux {
                custom_domains,
                subdomain,
                ..
            } => (custom_domains, subdomain),
            _ => (&[], ""),
        }
    }
}

/// One `[[proxies]]` entry: identity plus the type-specific body.
///
/// Hand-written deserialization, because serde cannot do what this needs. The
/// type-specific keys (`remotePort`, `customDomains`, …) and the shared ones
/// (`localIP`, `transport.useEncryption`, `healthCheck.path`, …) live at the
/// **same** level in the file, which is what `TypedProxyConfig` plus an embedded
/// `ProxyBaseConfig` gives the Go side. Serde has two ways to model that and both
/// fall short:
///
/// * two `#[serde(flatten)]` fields panic at runtime ("can only flatten structs
///   and maps");
/// * one `flatten` plus `deny_unknown_fields` rejects every key that belongs to
///   the flattened struct, because flattening buffers the input into a map and
///   the deny check then sees all of it as unknown.
///
/// So the keys are routed by hand: the type-specific ones are handed to
/// [`ProxyKind`] (which does keep `deny_unknown_fields`, so a typo inside an
/// `http` proxy is still caught), and everything else goes to [`Qos`] or
/// [`PluginConfig`]. The `kind` and `qos` fields are anonymous internally so the
/// derived `Serialize` keeps emitting a flat object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyConfig {
    #[serde(rename = "name")]
    pub name: String,
    /// Absent means enabled.
    #[serde(rename = "enabled", skip_serializing_if = "Option::is_none")]
    pub enabled: TriState,
    #[serde(flatten)]
    pub kind: ProxyKind,
    #[serde(flatten)]
    pub qos: Qos,
    #[serde(rename = "plugin", skip_serializing_if = "Option::is_none")]
    pub plugin: Option<PluginConfig>,
}

/// Routes each key of a `[[proxies]]` entry to the struct that owns it.
impl<'de> Deserialize<'de> for ProxyConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        /// The keys shared by every proxy type, which belong to [`Qos`].
        ///
        /// Keeping the list here rather than in `Qos` is what lets an unknown key
        /// reach [`ProxyKind`], where `deny_unknown_fields` reports it as the
        /// typo it is.
        const QOS_KEYS: &[&str] = &[
            "transport",
            "metadatas",
            "annotations",
            "loadBalancer",
            "healthCheck",
            "localIP",
            "localPort",
        ];

        let map = toml::map::Map::<String, toml::Value>::deserialize(deserializer)?;

        let mut name: Option<String> = None;
        let mut enabled: TriState = None;
        let mut plugin: Option<PluginConfig> = None;
        let mut kind = toml::map::Map::new();
        let mut qos = toml::map::Map::new();

        for (key, value) in map {
            match key.as_str() {
                "name" => name = Some(value.try_into().map_err(D::Error::custom)?),
                "enabled" => enabled = value.try_into().map_err(D::Error::custom)?,
                // A plugin is named either by a bare string (`plugin = "socks5"`)
                // or by a table whose `type` names it. Its options are only ever
                // inside that table — the legacy INI form that writes options as
                // siblings never reaches this decoder, because `ini.rs` builds
                // the `PluginConfig` by hand.
                "plugin" => match value {
                    toml::Value::String(name) => {
                        plugin = Some(
                            toml::Value::Table(toml::map::Map::from_iter([(
                                "type".to_string(),
                                toml::Value::String(name),
                            )]))
                            .try_into()
                            .map_err(D::Error::custom)?,
                        );
                    }
                    toml::Value::Table(_) => {
                        plugin = Some(value.try_into().map_err(D::Error::custom)?);
                    }
                    other => {
                        return Err(D::Error::custom(format!(
                            "plugin must be a string or a table, got {other}"
                        )))
                    }
                },
                _ if QOS_KEYS.contains(&key.as_str()) => {
                    qos.insert(key, value);
                }
                // `type` and every type-specific key.
                _ => {
                    kind.insert(key, value);
                }
            }
        }

        let name = name.ok_or_else(|| D::Error::missing_field("name"))?;
        let kind: ProxyKind = toml::Value::Table(kind)
            .try_into()
            .map_err(D::Error::custom)?;
        let qos: Qos = toml::Value::Table(qos)
            .try_into()
            .map_err(D::Error::custom)?;

        Ok(ProxyConfig {
            name,
            enabled,
            kind,
            qos,
            plugin,
        })
    }
}

impl ProxyConfig {
    /// Builds a proxy from its parts. The fields are private so that a `kind`
    /// and a `qos` cannot drift apart, but tests and the legacy INI reader both
    /// need to assemble one.
    pub fn new(
        name: impl Into<String>,
        enabled: TriState,
        kind: ProxyKind,
        qos: Qos,
        plugin: Option<PluginConfig>,
    ) -> Self {
        Self {
            name: name.into(),
            enabled,
            kind,
            qos,
            plugin,
        }
    }

    /// The type-specific body.
    pub fn kind(&self) -> &ProxyKind {
        &self.kind
    }

    /// The shared knobs, including `localIP` / `localPort` / `transport`.
    pub fn qos(&self) -> &Qos {
        &self.qos
    }

    /// The shared knobs, mutably.
    pub fn qos_mut(&mut self) -> &mut Qos {
        &mut self.qos
    }

    /// The client-side plugin, if any.
    pub fn plugin(&self) -> Option<&PluginConfig> {
        self.plugin.as_ref()
    }

    pub fn type_name(&self) -> &'static str {
        self.kind.type_name()
    }

    /// Whether this proxy should be started, given the global `start` allowlist.
    pub fn is_enabled(&self, start: &[String]) -> bool {
        if self.enabled == Some(false) {
            return false;
        }
        start.is_empty() || start.iter().any(|name| name == &self.name)
    }
}

/// A client-side plugin: the `type` discriminator plus that plugin's own keys.
///
/// Modelled as an enum rather than one struct with every key, because frp's
/// plugin options genuinely are separate types — `http_proxy` takes
/// `httpUser`/`httpPassword` while `socks5` takes `username`/`password`, and the
/// strict decoder on the Go side rejects a key that belongs to a different
/// plugin. One flat struct would have to drop that check.
///
/// Behaviour lives with the proxy implementations; this is only the config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum PluginConfig {
    #[serde(rename = "http2https")]
    Http2Https {
        #[serde(
            rename = "localAddr",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_addr: String,
        #[serde(
            rename = "hostHeaderRewrite",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        host_header_rewrite: String,
        #[serde(
            rename = "requestHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        request_headers: Option<HeaderOperations>,
    },
    #[serde(rename = "http2http")]
    Http2Http {
        #[serde(
            rename = "localAddr",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_addr: String,
        #[serde(
            rename = "hostHeaderRewrite",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        host_header_rewrite: String,
        #[serde(
            rename = "requestHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        request_headers: Option<HeaderOperations>,
    },
    #[serde(rename = "https2http")]
    Https2Http {
        #[serde(
            rename = "localAddr",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_addr: String,
        #[serde(
            rename = "hostHeaderRewrite",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        host_header_rewrite: String,
        #[serde(
            rename = "requestHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        request_headers: Option<HeaderOperations>,
        /// Defaults to true, applied in [`ClientConfig::complete`].
        #[serde(
            rename = "enableHTTP2",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        enable_http2: TriState,
        #[serde(rename = "crtPath", default, skip_serializing_if = "String::is_empty")]
        crt_path: String,
        #[serde(rename = "keyPath", default, skip_serializing_if = "String::is_empty")]
        key_path: String,
    },
    #[serde(rename = "https2https")]
    Https2Https {
        #[serde(
            rename = "localAddr",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_addr: String,
        #[serde(
            rename = "hostHeaderRewrite",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        host_header_rewrite: String,
        #[serde(
            rename = "requestHeaders",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        request_headers: Option<HeaderOperations>,
        #[serde(
            rename = "enableHTTP2",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        enable_http2: TriState,
        #[serde(rename = "crtPath", default, skip_serializing_if = "String::is_empty")]
        crt_path: String,
        #[serde(rename = "keyPath", default, skip_serializing_if = "String::is_empty")]
        key_path: String,
    },
    #[serde(rename = "tls2raw")]
    Tls2Raw {
        #[serde(
            rename = "localAddr",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_addr: String,
        #[serde(rename = "crtPath", default, skip_serializing_if = "String::is_empty")]
        crt_path: String,
        #[serde(rename = "keyPath", default, skip_serializing_if = "String::is_empty")]
        key_path: String,
    },
    #[serde(rename = "http_proxy")]
    HttpProxy {
        #[serde(rename = "httpUser", default, skip_serializing_if = "String::is_empty")]
        http_user: String,
        #[serde(
            rename = "httpPassword",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        http_password: String,
    },
    #[serde(rename = "socks5")]
    Socks5 {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        username: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        password: String,
    },
    #[serde(rename = "static_file")]
    StaticFile {
        #[serde(
            rename = "localPath",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        local_path: String,
        #[serde(
            rename = "stripPrefix",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        strip_prefix: String,
        #[serde(rename = "httpUser", default, skip_serializing_if = "String::is_empty")]
        http_user: String,
        #[serde(
            rename = "httpPassword",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        http_password: String,
    },
    #[serde(rename = "unix_domain_socket")]
    UnixDomainSocket {
        #[serde(rename = "unixPath", default, skip_serializing_if = "String::is_empty")]
        unix_path: String,
    },
    #[serde(rename = "virtual_net")]
    VirtualNet {},
}

impl PluginConfig {
    /// The `plugin.type` value.
    pub fn type_name(&self) -> &'static str {
        match self {
            PluginConfig::Http2Https { .. } => "http2https",
            PluginConfig::Http2Http { .. } => "http2http",
            PluginConfig::Https2Http { .. } => "https2http",
            PluginConfig::Https2Https { .. } => "https2https",
            PluginConfig::Tls2Raw { .. } => "tls2raw",
            PluginConfig::HttpProxy { .. } => "http_proxy",
            PluginConfig::Socks5 { .. } => "socks5",
            PluginConfig::StaticFile { .. } => "static_file",
            PluginConfig::UnixDomainSocket { .. } => "unix_domain_socket",
            PluginConfig::VirtualNet {} => "virtual_net",
        }
    }

    /// `enableHTTP2` for the TLS-terminating plugins, which default to true.
    pub fn enable_http2(&self) -> bool {
        match self {
            PluginConfig::Https2Http { enable_http2, .. }
            | PluginConfig::Https2Https { enable_http2, .. } => enable_http2.unwrap_or(true),
            _ => true,
        }
    }
}

/// `visitors[].plugin` — only `virtual_net` exists today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum VisitorPluginConfig {
    #[serde(rename = "virtual_net")]
    VirtualNet {
        #[serde(
            rename = "destinationIP",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        destination_ip: String,
    },
}

/// One `[[visitors]]` entry: the client side of `stcp` / `xtcp` / `sudp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum VisitorKind {
    Stcp {},
    Sudp {},
    Xtcp {
        /// `quic` (default) or `kcp`.
        #[serde(rename = "protocol", default, skip_serializing_if = "String::is_empty")]
        protocol: String,
        #[serde(rename = "keepTunnelOpen", default, skip_serializing_if = "is_false")]
        keep_tunnel_open: bool,
        #[serde(rename = "maxRetriesAnHour", default, skip_serializing_if = "is_zero")]
        max_retries_an_hour: i32,
        #[serde(rename = "minRetryInterval", default, skip_serializing_if = "is_zero")]
        min_retry_interval: i32,
        /// Name of another visitor to hand a connection to when hole punching
        /// fails.
        #[serde(
            rename = "fallbackTo",
            default,
            skip_serializing_if = "String::is_empty"
        )]
        fallback_to: String,
        #[serde(rename = "fallbackTimeoutMs", default, skip_serializing_if = "is_zero")]
        fallback_timeout_ms: i32,
    },
}

impl VisitorKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            VisitorKind::Stcp {} => "stcp",
            VisitorKind::Sudp {} => "sudp",
            VisitorKind::Xtcp { .. } => "xtcp",
        }
    }
}

/// One `[[visitors]]` entry.
///
/// No `deny_unknown_fields` here, because it cannot be combined with the
/// flattened `kind` (see [`ProxyConfig`] for the full explanation). Strictness
/// still applies one level down: [`VisitorKind`] denies unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisitorConfig {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "enabled", default, skip_serializing_if = "Option::is_none")]
    pub enabled: TriState,
    #[serde(flatten)]
    pub kind: VisitorKind,
    #[serde(
        rename = "serverName",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub server_name: String,
    /// The user owning the target proxy; defaults to the local `user`.
    #[serde(
        rename = "serverUser",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub server_user: String,
    /// Defaults to `127.0.0.1`, applied in [`ClientConfig::complete`].
    #[serde(rename = "bindAddr", default, skip_serializing_if = "String::is_empty")]
    pub bind_addr: String,
    /// A negative value means "receive connections from other visitors only,
    /// without binding a local port".
    #[serde(rename = "bindPort", default, skip_serializing_if = "is_zero")]
    pub bind_port: i32,
    #[serde(
        rename = "secretKey",
        default,
        skip_serializing_if = "Secret::is_empty"
    )]
    pub secret_key: Secret,
    #[serde(rename = "transport", default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<VisitorTransport>,
    #[serde(
        rename = "natTraversal",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub nat_traversal: Option<NatTraversalConfig>,
    #[serde(rename = "plugin", default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<VisitorPluginConfig>,
}

/// `transport` inside a visitor: only the two encryption switches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VisitorTransport {
    #[serde(rename = "useEncryption", skip_serializing_if = "is_false")]
    pub use_encryption: bool,
    #[serde(rename = "useCompression", skip_serializing_if = "is_false")]
    pub use_compression: bool,
}

/// The whole client config file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(flatten)]
    pub common: ClientCommonConfig,
    #[serde(rename = "proxies", skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ProxyConfig>,
    #[serde(rename = "visitors", skip_serializing_if = "Vec::is_empty")]
    pub visitors: Vec<VisitorConfig>,
}

impl ClientConfig {
    /// Fills in every default, mirroring the Go `Complete()` chain.
    ///
    /// Idempotent: it only ever replaces zero values, so calling it twice is the
    /// same as calling it once.
    pub fn complete(&mut self) {
        let common = &mut self.common;

        common.server_addr = empty_or(&common.server_addr, "0.0.0.0").to_string();
        common.server_port = if common.server_port == 0 {
            7000
        } else {
            common.server_port
        };
        if common.login_fail_exit.is_none() {
            common.login_fail_exit = Some(true);
        }
        common.nat_hole_stun_server =
            empty_or(&common.nat_hole_stun_server, "stun.easyvoip.com:3478").to_string();
        common.udp_packet_size = if common.udp_packet_size == 0 {
            1500
        } else {
            common.udp_packet_size
        };

        let auth = common.auth.get_or_insert_with(AuthClientConfig::default);
        auth.method = empty_or(&auth.method, "token").to_string();

        let log = common.log.get_or_insert_with(LogConfig::default);
        log.to = empty_or(&log.to, "console").to_string();
        log.level = empty_or(&log.level, "info").to_string();
        if log.max_days == 0 {
            log.max_days = 3;
        }

        // Go's `WebServerConfig` is a value struct, so `Complete()` always has
        // one to fill in and `webServer.addr` always ends up set — the admin
        // server is simply off until `port` is non-zero.
        let web_server = common
            .web_server
            .get_or_insert_with(WebServerConfig::default);
        web_server.addr = empty_or(&web_server.addr, "127.0.0.1").to_string();

        let transport = common
            .transport
            .get_or_insert_with(ClientTransportConfig::default);
        transport.protocol = empty_or(&transport.protocol, "tcp").to_string();
        transport.wire_protocol = empty_or(&transport.wire_protocol, "v1").to_string();
        if transport.dial_server_timeout == 0 {
            transport.dial_server_timeout = 10;
        }
        if transport.dial_server_keepalive == 0 {
            transport.dial_server_keepalive = 7200;
        }
        if transport.proxy_url.is_empty() {
            transport.proxy_url = std::env::var("http_proxy").unwrap_or_default();
        }
        if transport.pool_count == 0 {
            transport.pool_count = 1;
        }
        let tcp_mux = transport.tcp_mux.unwrap_or(true);
        transport.tcp_mux = Some(tcp_mux);
        if transport.tcp_mux_keepalive_interval == 0 {
            transport.tcp_mux_keepalive_interval = 30;
        }
        // The application-level heartbeat is redundant while yamux is doing its
        // own, so both knobs default to "disabled" (-1) when tcpMux is on. A
        // user-set value still wins.
        if transport.heartbeat_interval == 0 {
            transport.heartbeat_interval = if tcp_mux { -1 } else { 30 };
        }
        if transport.heartbeat_timeout == 0 {
            transport.heartbeat_timeout = if tcp_mux { -1 } else { 90 };
        }
        let quic = transport.quic.get_or_insert_with(QuicOptions::default);
        if quic.keepalive_period == 0 {
            quic.keepalive_period = 10;
        }
        if quic.max_idle_timeout == 0 {
            quic.max_idle_timeout = 30;
        }
        if quic.max_incoming_streams == 0 {
            quic.max_incoming_streams = 100_000;
        }
        let tls = transport.tls.get_or_insert_with(TlsClientConfig::default);
        if tls.enable.is_none() {
            tls.enable = Some(true);
        }
        if tls.disable_custom_tls_first_byte.is_none() {
            tls.disable_custom_tls_first_byte = Some(true);
        }

        for proxy in &mut self.proxies {
            proxy.qos.local_ip = empty_or(&proxy.qos.local_ip, "127.0.0.1").to_string();
            let transport = proxy
                .qos
                .transport
                .get_or_insert_with(ProxyTransport::default);
            transport.bandwidth_limit_mode =
                empty_or(&transport.bandwidth_limit_mode, "client").to_string();
            if let Some(
                PluginConfig::Https2Http { enable_http2, .. }
                | PluginConfig::Https2Https { enable_http2, .. },
            ) = proxy.plugin.as_mut()
            {
                if enable_http2.is_none() {
                    *enable_http2 = Some(true);
                }
            }
        }
    }

    /// `transport.tcpMux`, after defaults.
    pub fn tcp_mux(&self) -> bool {
        self.common
            .transport
            .as_ref()
            .and_then(|t| t.tcp_mux)
            .unwrap_or(true)
    }

    /// `transport.tls.enable`, after defaults.
    pub fn tls_enable(&self) -> bool {
        self.common
            .transport
            .as_ref()
            .and_then(|t| t.tls.as_ref())
            .and_then(|t| t.enable)
            .unwrap_or(true)
    }
}

/// Go's `util.EmptyOr` for strings: a zero value becomes the fallback.
fn empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

/// `skip_serializing_if` for any numeric field, matching Go's `omitempty`.
fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_fills_the_documented_defaults() {
        let mut config = ClientConfig::default();
        config.complete();

        assert_eq!(config.common.server_addr, "0.0.0.0");
        assert_eq!(config.common.server_port, 7000);
        assert_eq!(config.common.udp_packet_size, 1500);
        assert_eq!(config.common.nat_hole_stun_server, "stun.easyvoip.com:3478");
        assert_eq!(config.common.login_fail_exit, Some(true));
        assert_eq!(config.common.auth.as_ref().unwrap().method, "token");
        assert_eq!(config.common.log.as_ref().unwrap().to, "console");
        assert_eq!(config.common.log.as_ref().unwrap().max_days, 3);
        assert_eq!(config.common.web_server.as_ref().unwrap().addr, "127.0.0.1");
    }

    /// The default that catches people out: with `tcpMux` on (the default),
    /// both heartbeat knobs come back disabled.
    #[test]
    fn heartbeats_are_disabled_by_default_because_tcp_mux_is_on() {
        let mut config = ClientConfig::default();
        config.complete();
        let transport = config.common.transport.as_ref().unwrap();
        assert_eq!(transport.tcp_mux, Some(true));
        assert_eq!(transport.heartbeat_interval, -1);
        assert_eq!(transport.heartbeat_timeout, -1);
    }

    #[test]
    fn heartbeats_default_to_30_and_90_without_tcp_mux() {
        let mut config = ClientConfig {
            common: ClientCommonConfig {
                transport: Some(ClientTransportConfig {
                    tcp_mux: Some(false),
                    ..ClientTransportConfig::default()
                }),
                ..ClientCommonConfig::default()
            },
            ..ClientConfig::default()
        };
        config.complete();
        let transport = config.common.transport.as_ref().unwrap();
        assert_eq!(transport.heartbeat_interval, 30);
        assert_eq!(transport.heartbeat_timeout, 90);
    }

    #[test]
    fn an_explicit_heartbeat_survives_completion() {
        let mut config = ClientConfig {
            common: ClientCommonConfig {
                transport: Some(ClientTransportConfig {
                    heartbeat_interval: 5,
                    ..ClientTransportConfig::default()
                }),
                ..ClientCommonConfig::default()
            },
            ..ClientConfig::default()
        };
        config.complete();
        assert_eq!(
            config.common.transport.as_ref().unwrap().heartbeat_interval,
            5
        );
    }

    #[test]
    fn tls_is_on_by_default_and_the_custom_first_byte_is_off() {
        let mut config = ClientConfig::default();
        config.complete();
        assert!(config.tls_enable());
        let tls = config
            .common
            .transport
            .as_ref()
            .unwrap()
            .tls
            .as_ref()
            .unwrap();
        assert_eq!(tls.disable_custom_tls_first_byte, Some(true));
    }

    #[test]
    fn complete_is_idempotent() {
        let mut once = ClientConfig::default();
        once.complete();
        let mut twice = once.clone();
        twice.complete();
        assert_eq!(once, twice);
    }

    #[test]
    fn proxy_local_ip_and_bandwidth_mode_get_defaults() {
        let mut config = ClientConfig {
            proxies: vec![ProxyConfig {
                name: "web".into(),
                enabled: None,
                kind: ProxyKind::Tcp { remote_port: 6000 },
                qos: Qos::default(),
                plugin: None,
            }],
            ..ClientConfig::default()
        };
        config.complete();
        assert_eq!(config.proxies[0].qos.local_ip, "127.0.0.1");
        assert_eq!(
            config.proxies[0]
                .qos
                .transport
                .as_ref()
                .unwrap()
                .bandwidth_limit_mode,
            "client"
        );
    }

    #[test]
    fn the_start_allowlist_and_enabled_flag_both_filter() {
        let proxy = |name: &str, enabled: TriState| ProxyConfig {
            name: name.into(),
            enabled,
            kind: ProxyKind::Tcp { remote_port: 1 },
            qos: Qos::default(),
            plugin: None,
        };

        assert!(proxy("a", None).is_enabled(&[]));
        assert!(proxy("a", Some(true)).is_enabled(&[]));
        assert!(!proxy("a", Some(false)).is_enabled(&[]));
        assert!(proxy("a", None).is_enabled(&["a".into()]));
        assert!(!proxy("a", None).is_enabled(&["b".into()]));
    }

    #[test]
    fn unknown_proxy_type_is_rejected() {
        let err = toml::from_str::<ClientConfig>(
            r#"
            [[proxies]]
            name = "x"
            type = "nope"
            "#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn unknown_keys_inside_a_proxy_are_rejected() {
        // This is what strict mode is for: a typo in a type-specific key should
        // not be silently ignored.
        let err = toml::from_str::<ClientConfig>(
            r#"
            [[proxies]]
            name = "x"
            type = "tcp"
            remotePort = 6000
            remote_port = 6001
            "#,
        );
        assert!(err.is_err());
    }
}
