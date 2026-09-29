//! Known config keys, for `--no-strict-config`.
//!
//! Strict mode is the default and is enforced by `deny_unknown_fields` on the
//! model structs. Lenient mode has to *drop* unknown keys instead of rejecting
//! them, and serde cannot express "deny or ignore, decided at runtime", so the
//! key surface is written out here and used to prune a `toml::Value` before it
//! is decoded.
//!
//! This is a duplicate of the schema, which is a liability — so it is checked
//! against the real thing rather than trusted. See the `prune_matches_strict`
//! test in `parse.rs`: pruning must remove exactly the keys strict mode rejects,
//! which means adding a field to a model struct and forgetting it here fails the
//! suite.

/// The client-wide keys, i.e. everything outside `[[proxies]]` / `[[visitors]]`.
pub const COMMON_KEYS: &[&str] = &[
    // The two arrays themselves, which `prune_unknown_keys` descends into.
    "proxies",
    "visitors",
    "auth",
    "user",
    "clientID",
    "serverAddr",
    "serverPort",
    "natHoleStunServer",
    "dnsServer",
    "loginFailExit",
    "start",
    "log",
    "webServer",
    "transport",
    "udpPacketSize",
    "metadatas",
    "includes",
    "store",
    // additions
    "renameOnConflict",
];

pub const AUTH_KEYS: &[&str] = &["method", "additionalScopes", "token", "oidc"];

pub const OIDC_KEYS: &[&str] = &[
    "clientID",
    "clientSecret",
    "audience",
    "scope",
    "tokenEndpointURL",
    "additionalEndpointParams",
    "trustedCaFile",
    "insecureSkipVerify",
    "proxyURL",
];

pub const LOG_KEYS: &[&str] = &[
    "to",
    "level",
    "maxDays",
    "disablePrintColor",
    // additions
    "format",
    "color",
];

pub const WEB_SERVER_KEYS: &[&str] = &[
    "addr",
    "port",
    "user",
    "password",
    "assetsDir",
    "pprofEnable",
    // additions
    "metricsEnable",
];

pub const TRANSPORT_KEYS: &[&str] = &[
    "protocol",
    "wireProtocol",
    "dialServerTimeout",
    "dialServerkeepalive",
    "dialServerKeepalive",
    "connectServerLocalIP",
    "proxyURL",
    "poolCount",
    "tcpMux",
    "tcpMuxKeepaliveInterval",
    "heartbeatInterval",
    "heartbeatTimeout",
    "quic",
    "tls",
];

pub const TLS_KEYS: &[&str] = &[
    "enable",
    "disableCustomTLSFirstByte",
    "certFile",
    "keyFile",
    "trustedCaFile",
    "serverName",
];

pub const QUIC_KEYS: &[&str] = &["keepalivePeriod", "maxIdleTimeout", "maxIncomingStreams"];

pub const STORE_KEYS: &[&str] = &["path"];

/// `[[proxies]]` keys that are not type-specific.
pub const PROXY_BASE_KEYS: &[&str] = &["name", "enabled", "type", "plugin"];

/// The per-proxy keys shared by every type.
pub const QOS_KEYS: &[&str] = &[
    "transport",
    "metadatas",
    "annotations",
    "loadBalancer",
    "healthCheck",
    "localIP",
    "localPort",
];

pub const PROXY_TRANSPORT_KEYS: &[&str] = &[
    "useEncryption",
    "useCompression",
    "bandwidthLimit",
    "bandwidthLimitMode",
    "proxyProtocolVersion",
];

pub const LOAD_BALANCER_KEYS: &[&str] = &["group", "groupKey"];

pub const HEALTH_CHECK_KEYS: &[&str] = &[
    "type",
    "timeoutSeconds",
    "maxFailed",
    "intervalSeconds",
    "path",
    "httpHeaders",
];

pub const NAT_TRAVERSAL_KEYS: &[&str] = &["disableAssistedAddrs"];

/// Keys belonging to one proxy type, on top of [`QOS_KEYS`].
pub fn proxy_type_keys(proxy_type: &str) -> &'static [&'static str] {
    match proxy_type {
        "tcp" | "udp" => &["remotePort"],
        "http" => &[
            "customDomains",
            "subdomain",
            "locations",
            "httpUser",
            "httpPassword",
            "hostHeaderRewrite",
            "requestHeaders",
            "responseHeaders",
            "routeByHTTPUser",
        ],
        "https" => &["customDomains", "subdomain"],
        "tcpmux" => &[
            "customDomains",
            "subdomain",
            "httpUser",
            "httpPassword",
            "routeByHTTPUser",
            "multiplexer",
        ],
        "stcp" | "sudp" => &["secretKey", "allowUsers"],
        "xtcp" => &["secretKey", "allowUsers", "natTraversal"],
        _ => &[],
    }
}

/// Keys belonging to one plugin type.
pub fn plugin_keys(plugin_type: &str) -> &'static [&'static str] {
    match plugin_type {
        "http2https" | "http2http" => &["type", "localAddr", "hostHeaderRewrite", "requestHeaders"],
        "https2http" | "https2https" => &[
            "type",
            "localAddr",
            "hostHeaderRewrite",
            "requestHeaders",
            "enableHTTP2",
            "crtPath",
            "keyPath",
        ],
        "tls2raw" => &["type", "localAddr", "crtPath", "keyPath"],
        "http_proxy" => &["type", "httpUser", "httpPassword"],
        "socks5" => &["type", "username", "password"],
        "static_file" => &[
            "type",
            "localPath",
            "stripPrefix",
            "httpUser",
            "httpPassword",
        ],
        "unix_domain_socket" => &["type", "unixPath"],
        "virtual_net" => &["type"],
        _ => &["type"],
    }
}

/// `[[visitors]]` keys that are not type-specific.
pub const VISITOR_BASE_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "serverName",
    "serverUser",
    "bindAddr",
    "bindPort",
    "secretKey",
    "transport",
    "natTraversal",
    "plugin",
];

/// Keys belonging to one visitor type.
pub fn visitor_type_keys(visitor_type: &str) -> &'static [&'static str] {
    match visitor_type {
        "xtcp" => &[
            "protocol",
            "keepTunnelOpen",
            "maxRetriesAnHour",
            "minRetryInterval",
            "fallbackTo",
            "fallbackTimeoutMs",
        ],
        _ => &[],
    }
}

/// `visitors[].transport` keys.
pub const VISITOR_TRANSPORT_KEYS: &[&str] = &["useEncryption", "useCompression"];
