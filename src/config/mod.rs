//! Configuration: files in, a validated runtime model out.
//!
//! The format is decided by **content**, not by extension, matching
//! `pkg/config/load.go`: a file that parses as INI and has a `[common]` section
//! is legacy INI, and anything else goes through the TOML/YAML/JSON path. That is
//! what lets an existing `frpc.ini` keep working when renamed.
//!
//! Defaults are not in the struct literal — they are applied by [`Complete`],
//! which only fills zero values and is therefore idempotent. This mirrors the Go
//! side, including the two defaults that surprise people:
//!
//! * `transport.tls.enable` defaults to **true**;
//! * `transport.heartbeatInterval` / `heartbeatTimeout` default to **-1**
//!   (disabled) whenever `tcpMux` is on, which it is by default.

mod ini;
mod keys;
mod model;
mod parse;
mod validate;

pub use model::{
    AuthClientConfig, ClientCommonConfig, ClientConfig, ClientTransportConfig, HeaderOperations,
    HealthCheckConfig, HttpHeader, LoadBalancerConfig, LogConfig, PluginConfig, ProxyConfig,
    ProxyKind, ProxyTransport, Qos, StoreConfig, TlsClientConfig, TriState, VisitorConfig,
    VisitorKind, VisitorPluginConfig, VisitorTransport, WebServerConfig,
};
pub use parse::{
    load_file, load_file_with, load_from_str, load_from_str_with, ConfigFormat, LoadedConfig,
    Strictness,
};
pub use validate::{validate, Severity, ValidationIssue};

/// The proxy type names frp accepts. Kept as a list rather than an enum-with-data
/// because the same string also appears in `NewProxy.proxy_type` and in the
/// admin API's response keys.
pub const SUPPORTED_PROXY_TYPES: &[&str] = &[
    "tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp", "sudp",
];

/// Transport protocol names `transport.protocol` accepts.
pub const SUPPORTED_TRANSPORT_PROTOCOLS: &[&str] = &["tcp", "kcp", "quic", "websocket", "wss"];

/// Wire protocol versions `transport.wireProtocol` accepts.
pub const SUPPORTED_WIRE_PROTOCOLS: &[&str] = &["v1", "v2"];

/// Auth methods `auth.method` accepts.
pub const SUPPORTED_AUTH_METHODS: &[&str] = &["token", "oidc"];

/// Auth scopes that may appear in `auth.additionalScopes`.
pub const SUPPORTED_AUTH_SCOPES: &[&str] = &["HeartBeats", "NewWorkConns"];

/// Log levels `log.level` accepts.
pub const SUPPORTED_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];
