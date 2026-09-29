//! Proxy naming, matching `pkg/naming`.

/// The wire form of a proxy name: `"{user}.{name}"`, or the bare name when
/// `user` is empty.
///
/// The user prefix is *not* baked into the configured name. It is applied when a
/// proxy is announced to the server and stripped again on anything the server
/// sends back, which is why both directions live here.
pub fn add_user_prefix(user: &str, name: &str) -> String {
    if user.is_empty() {
        name.to_string()
    } else {
        format!("{user}.{name}")
    }
}

/// Removes exactly one `"{user}."` prefix, leaving the rest untouched.
pub fn strip_user_prefix(user: &str, name: &str) -> String {
    if user.is_empty() {
        return name.to_string();
    }
    name.strip_prefix(user)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(name)
        .to_string()
}

/// The name a visitor targets: the server-side user wins over the local one.
pub fn build_target_server_proxy_name(
    local_user: &str,
    server_user: &str,
    server_name: &str,
) -> String {
    let user = if server_user.is_empty() {
        local_user
    } else {
        server_user
    };
    add_user_prefix(user, server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_only_when_a_user_is_set() {
        assert_eq!(add_user_prefix("", "web"), "web");
        assert_eq!(add_user_prefix("u1", "web"), "u1.web");
    }

    #[test]
    fn stripping_removes_exactly_one_prefix() {
        assert_eq!(strip_user_prefix("u1", "u1.web"), "web");
        assert_eq!(strip_user_prefix("u1", "u1.u1.web"), "u1.web");
        // No prefix present: left alone rather than truncated.
        assert_eq!(strip_user_prefix("u1", "web"), "web");
        // Only a partial match: left alone.
        assert_eq!(strip_user_prefix("u1", "u12.web"), "u12.web");
        assert_eq!(strip_user_prefix("", "u1.web"), "u1.web");
    }

    #[test]
    fn round_trips() {
        let wire = add_user_prefix("alice", "ssh");
        assert_eq!(strip_user_prefix("alice", &wire), "ssh");
    }

    #[test]
    fn visitor_target_prefers_the_server_user() {
        assert_eq!(
            build_target_server_proxy_name("alice", "bob", "db"),
            "bob.db"
        );
        assert_eq!(
            build_target_server_proxy_name("alice", "", "db"),
            "alice.db"
        );
        assert_eq!(build_target_server_proxy_name("", "", "db"), "db");
    }
}
