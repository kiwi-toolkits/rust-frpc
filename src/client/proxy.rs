//! Turning a configured proxy into the `NewProxy` message that registers it.
//!
//! The field mapping is a faithful port of `MarshalToMsg` on the Go side, and
//! two of its rules are not obvious:
//!
//! * the wire name carries the user prefix, so a proxy called `ssh` on a client
//!   with `user = "alice"` is announced as `alice.ssh`. The prefix is *not* baked
//!   into the config, which is why it is applied here and stripped again on
//!   anything the server sends back;
//! * `bandwidthLimitMode` is left empty when it is `client`, because that is the
//!   server's default too and the Go client skips it "to reduce traffic".
//!
//! `remoteAddr` is deliberately absent: it comes back in the `NewProxyResp`.

use crate::config::{ClientConfig, HeaderOperations, ProxyConfig, ProxyKind};
use crate::crypto::Secret;
use crate::msg::NewProxy;
use crate::naming;

/// Builds the registration message for `proxy`.
///
/// `name` overrides the proxy's configured name. It is what the rename-retry
/// strategy will pass `ex_1_ssh` through when it is turned on; until then every
/// caller passes `proxy.name`, and the work-connection lookup in the control loop
/// matches on that same wire name.
pub fn to_new_proxy(config: &ClientConfig, proxy: &ProxyConfig, name: &str) -> NewProxy {
    let user = &config.common.user;
    let mut message = NewProxy {
        proxy_name: naming::add_user_prefix(user, name),
        // `wireType` when it is set, `type` otherwise. Only the registration is
        // affected; the local side follows `type`.
        proxy_type: proxy.wire_type_name().to_string(),
        ..NewProxy::default()
    };

    apply_qos(&mut message, proxy);
    apply_kind(&mut message, proxy.kind());

    message
}

/// The shared knobs, from `ProxyBaseConfig.MarshalToMsg`.
fn apply_qos(message: &mut NewProxy, proxy: &ProxyConfig) {
    let qos = proxy.qos();
    if let Some(transport) = qos.transport.as_ref() {
        message.use_encryption = transport.use_encryption;
        message.use_compression = transport.use_compression;
        message.bandwidth_limit = transport.bandwidth_limit.clone();
        // Empty means "client", which is the default on both sides.
        if transport.bandwidth_limit_mode != "client" {
            message.bandwidth_limit_mode = transport.bandwidth_limit_mode.clone();
        }
    }
    if let Some(load_balancer) = qos.load_balancer.as_ref() {
        message.group = load_balancer.group.clone();
        message.group_key = load_balancer.group_key.clone();
    }
    message.metas = qos.metadatas.clone();
    message.annotations = qos.annotations.clone();
}

/// The type-specific fields, from each type's `MarshalToMsg`.
fn apply_kind(message: &mut NewProxy, kind: &ProxyKind) {
    match kind {
        ProxyKind::Tcp { remote_port } | ProxyKind::Udp { remote_port } => {
            message.remote_port = *remote_port;
        }
        ProxyKind::Http {
            custom_domains,
            subdomain,
            locations,
            http_user,
            http_password,
            host_header_rewrite,
            request_headers,
            response_headers,
            route_by_http_user,
        } => {
            message.custom_domains = custom_domains.clone();
            message.subdomain = subdomain.clone();
            message.locations = locations.clone();
            message.http_user = http_user.clone();
            // The config key is `httpPassword`; the wire field is `http_pwd`.
            message.http_pwd = http_password.clone();
            message.host_header_rewrite = host_header_rewrite.clone();
            message.headers = headers_of(request_headers.as_ref());
            message.response_headers = headers_of(response_headers.as_ref());
            message.route_by_http_user = route_by_http_user.clone();
        }
        ProxyKind::Https {
            custom_domains,
            subdomain,
        } => {
            message.custom_domains = custom_domains.clone();
            message.subdomain = subdomain.clone();
        }
        ProxyKind::Tcpmux {
            custom_domains,
            subdomain,
            http_user,
            http_password,
            route_by_http_user,
            multiplexer,
        } => {
            message.custom_domains = custom_domains.clone();
            message.subdomain = subdomain.clone();
            message.multiplexer = multiplexer.clone();
            message.http_user = http_user.clone();
            message.http_pwd = http_password.clone();
            message.route_by_http_user = route_by_http_user.clone();
        }
        ProxyKind::Stcp {
            secret_key,
            allow_users,
        }
        | ProxyKind::Xtcp {
            secret_key,
            allow_users,
            ..
        }
        | ProxyKind::Sudp {
            secret_key,
            allow_users,
        } => {
            message.sk = expose(secret_key);
            message.allow_users = allow_users.clone();
        }
    }
}

fn headers_of(operations: Option<&HeaderOperations>) -> crate::msg::Metas {
    operations
        .map(|operations| operations.set.clone())
        .unwrap_or_default()
}

/// The secret key goes on the wire in the clear — the masking is only for logs
/// and the admin API — so this is where it is deliberately un-masked.
fn expose(secret: &Secret) -> String {
    secret.expose().to_string()
}

/// The name a proxy is announced under, including the user prefix.
pub fn wire_name(config: &ClientConfig, name: &str) -> String {
    naming::add_user_prefix(&config.common.user, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, PluginConfig, ProxyTransport, Qos};

    fn config_with_user(user: &str) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.common.user = user.to_string();
        config.complete();
        config
    }

    fn proxy(name: &str, kind: ProxyKind) -> ProxyConfig {
        ProxyConfig::new(name, None, kind, Qos::default(), None)
    }

    #[test]
    fn a_tcp_proxy_carries_its_remote_port_and_the_user_prefix() {
        let config = config_with_user("alice");
        let message = to_new_proxy(
            &config,
            &proxy("ssh", ProxyKind::Tcp { remote_port: 6000 }),
            "ssh",
        );

        assert_eq!(message.proxy_name, "alice.ssh");
        assert_eq!(message.proxy_type, "tcp");
        assert_eq!(message.remote_port, 6000);
    }

    #[test]
    fn without_a_user_the_name_is_bare() {
        let config = config_with_user("");
        let message = to_new_proxy(
            &config,
            &proxy("ssh", ProxyKind::Tcp { remote_port: 6000 }),
            "ssh",
        );
        assert_eq!(message.proxy_name, "ssh");
    }

    #[test]
    fn the_rename_override_replaces_the_name_but_keeps_the_prefix() {
        let config = config_with_user("alice");
        let message = to_new_proxy(
            &config,
            &proxy("ssh", ProxyKind::Tcp { remote_port: 6000 }),
            "ex_1_ssh",
        );
        assert_eq!(message.proxy_name, "alice.ex_1_ssh");
    }

    /// Registration and the work-connection lookup have to agree on the name.
    ///
    /// They are two different pieces of code — one builds `NewProxy`, the other
    /// matches the `StartWorkConn` the server sends back against the configured
    /// proxies — and the rename-retry strategy sits between them. As long as the
    /// strategy is off, every caller must pass the configured name, or a work
    /// connection arrives for a proxy nobody can find.
    #[test]
    fn a_registered_proxy_can_be_found_again_by_its_wire_name() {
        let config = config_with_user("alice");
        let p = proxy("ssh", ProxyKind::Tcp { remote_port: 6000 });
        let message = to_new_proxy(&config, &p, &p.name);

        // The same comparison the control loop makes when a `StartWorkConn`
        // arrives, and with the same precedence: the proxy's *configured* name,
        // not a rename override.
        let found = naming::add_user_prefix(&config.common.user, &p.name) == message.proxy_name;
        assert!(found, "{} is not findable again", message.proxy_name);
    }

    #[test]
    fn a_wire_type_override_is_what_gets_registered() {
        // `virtual_net` registers a `tcp`-shaped proxy as something else; the
        // local side is unaffected.
        let config = config_with_user("");
        let mut p = proxy("hook", ProxyKind::Tcp { remote_port: 0 });
        p.wire_type = "virtual_net".into();
        assert_eq!(p.type_name(), "tcp");
        assert_eq!(to_new_proxy(&config, &p, "hook").proxy_type, "virtual_net");

        // And with no override the configured type is what goes out.
        let plain = proxy("ssh", ProxyKind::Tcp { remote_port: 6000 });
        assert_eq!(to_new_proxy(&config, &plain, "ssh").proxy_type, "tcp");
    }

    #[test]
    fn the_client_default_bandwidth_mode_is_left_off_the_wire() {
        let config = config_with_user("");
        let mut p = proxy("ssh", ProxyKind::Tcp { remote_port: 6000 });
        p.qos_mut().transport = Some(ProxyTransport {
            bandwidth_limit: "1MB".into(),
            bandwidth_limit_mode: "client".into(),
            ..ProxyTransport::default()
        });
        let message = to_new_proxy(&config, &p, "ssh");
        assert_eq!(message.bandwidth_limit, "1MB");
        // Go omits it "to reduce traffic", and the server defaults to client.
        assert!(message.bandwidth_limit_mode.is_empty());

        p.qos_mut().transport = Some(ProxyTransport {
            bandwidth_limit_mode: "server".into(),
            ..ProxyTransport::default()
        });
        assert_eq!(
            to_new_proxy(&config, &p, "ssh").bandwidth_limit_mode,
            "server"
        );
    }

    #[test]
    fn encryption_and_compression_flags_are_carried() {
        let config = config_with_user("");
        let mut p = proxy("ssh", ProxyKind::Tcp { remote_port: 6000 });
        p.qos_mut().transport = Some(ProxyTransport {
            use_encryption: true,
            use_compression: true,
            ..ProxyTransport::default()
        });
        let message = to_new_proxy(&config, &p, "ssh");
        assert!(message.use_encryption);
        assert!(message.use_compression);
    }

    #[test]
    fn group_and_metadata_reach_the_wire() {
        let config = config_with_user("");
        let mut p = proxy("ssh", ProxyKind::Tcp { remote_port: 6000 });
        p.qos_mut().load_balancer = Some(crate::config::LoadBalancerConfig {
            group: "g".into(),
            group_key: "k".into(),
        });
        p.qos_mut().metadatas.insert("region".into(), "eu".into());

        let message = to_new_proxy(&config, &p, "ssh");
        assert_eq!(message.group, "g");
        assert_eq!(message.group_key, "k");
        assert_eq!(message.metas.get("region").map(String::as_str), Some("eu"));
    }

    #[test]
    fn an_http_proxy_carries_its_domains_locations_and_headers() {
        let config = config_with_user("");
        let p = proxy(
            "web",
            ProxyKind::Http {
                custom_domains: vec!["a.example.com".into()],
                subdomain: "web".into(),
                locations: vec!["/".into(), "/api".into()],
                http_user: "u".into(),
                http_password: "p".into(),
                host_header_rewrite: "backend".into(),
                request_headers: Some(HeaderOperations {
                    set: [("X-A".to_string(), "1".to_string())].into_iter().collect(),
                }),
                response_headers: Some(HeaderOperations {
                    set: [("X-B".to_string(), "2".to_string())].into_iter().collect(),
                }),
                route_by_http_user: "rw".into(),
            },
        );

        let message = to_new_proxy(&config, &p, "web");
        assert_eq!(message.proxy_type, "http");
        assert_eq!(message.custom_domains, vec!["a.example.com"]);
        assert_eq!(message.subdomain, "web");
        assert_eq!(message.locations, vec!["/", "/api"]);
        assert_eq!(message.http_user, "u");
        // The config key is `httpPassword`; the wire field is `http_pwd`.
        assert_eq!(message.http_pwd, "p");
        assert_eq!(message.host_header_rewrite, "backend");
        assert_eq!(message.headers.get("X-A").map(String::as_str), Some("1"));
        assert_eq!(
            message.response_headers.get("X-B").map(String::as_str),
            Some("2")
        );
        assert_eq!(message.route_by_http_user, "rw");
    }

    #[test]
    fn a_tcpmux_proxy_carries_its_multiplexer() {
        let config = config_with_user("");
        let p = proxy(
            "mux",
            ProxyKind::Tcpmux {
                custom_domains: vec!["tunnel".into()],
                subdomain: String::new(),
                http_user: String::new(),
                http_password: String::new(),
                route_by_http_user: String::new(),
                multiplexer: "httpconnect".into(),
            },
        );
        let message = to_new_proxy(&config, &p, "mux");
        assert_eq!(message.proxy_type, "tcpmux");
        assert_eq!(message.multiplexer, "httpconnect");
        assert_eq!(message.custom_domains, vec!["tunnel"]);
    }

    #[test]
    fn a_secret_proxy_carries_its_key_in_the_clear() {
        // The masking is for logs and the admin API; the server needs the value.
        let config = config_with_user("");
        let p = proxy(
            "db",
            ProxyKind::Stcp {
                secret_key: Secret::new("s3cret"),
                allow_users: vec!["*".into()],
            },
        );
        let message = to_new_proxy(&config, &p, "db");
        assert_eq!(message.sk, "s3cret");
        assert_eq!(message.allow_users, vec!["*"]);
    }

    #[test]
    fn an_enabled_proxy_with_a_plugin_still_registers_normally() {
        // The plugin changes how the client handles a work connection, not what
        // it tells the server.
        let config = config_with_user("");
        let p = ProxyConfig::new(
            "sock",
            None,
            ProxyKind::Tcp { remote_port: 6003 },
            Qos::default(),
            Some(PluginConfig::UnixDomainSocket {
                unix_path: "/var/run/docker.sock".into(),
            }),
        );
        let message = to_new_proxy(&config, &p, "sock");
        assert_eq!(message.proxy_type, "tcp");
        assert_eq!(message.remote_port, 6003);
    }

    #[test]
    fn the_registration_serializes_to_the_field_names_frps_expects() {
        // A guard against a rename in `msg.rs` silently changing the wire
        // format of the one message that matters most.
        let config = config_with_user("alice");
        let message = to_new_proxy(
            &config,
            &proxy("ssh", ProxyKind::Tcp { remote_port: 6000 }),
            "ssh",
        );
        let json = String::from_utf8(crate::msg::go_json::to_vec(&message).unwrap()).unwrap();
        assert!(json.contains("\"proxy_name\":\"alice.ssh\""), "{json}");
        assert!(json.contains("\"proxy_type\":\"tcp\""), "{json}");
        assert!(json.contains("\"remote_port\":6000"), "{json}");
    }
}
