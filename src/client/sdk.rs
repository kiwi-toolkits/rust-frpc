//! The client side of the admin API: what `frpc reload`, `status` and `stop` use.
//!
//! Only what those three commands need — a request with an optional body, and a
//! reply read back by `Content-Length`. The Go client uses a shared SDK package
//! for the same job; this is the three calls that exist here, over a socket,
//! without pulling in an HTTP stack for them.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// How long to wait for the admin API, matching the Go `--api-timeout` default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A reply from the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    /// Whether the request succeeded.
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The message from the error envelope, or the raw body when there is no
    /// envelope to parse.
    pub fn error_message(&self) -> String {
        #[derive(serde::Deserialize)]
        struct GeneralResponse {
            msg: String,
        }
        match serde_json::from_str::<GeneralResponse>(&self.body) {
            Ok(envelope) => envelope.msg,
            Err(_) => self.body.trim().to_string(),
        }
    }
}

/// Where the admin API is, and how to authenticate to it.
#[derive(Debug, Clone)]
pub struct AdminClient {
    addr: String,
    /// The `Authorization` header value, already encoded.
    authorization: Option<String>,
    timeout: Duration,
}

impl AdminClient {
    /// Builds a client for a `webServer` block.
    pub fn new(
        addr: &str,
        port: u16,
        user: &str,
        password: &str,
        timeout: Option<Duration>,
    ) -> Self {
        // Encoded once, at construction, so the credentials are not rebuilt for
        // every call — and so an empty pair is simply no header at all.
        let authorization = if user.is_empty() && password.is_empty() {
            None
        } else {
            Some(format!(
                "Basic {}",
                base64_encode(format!("{user}:{password}").as_bytes())
            ))
        };
        Self {
            addr: crate::proto::transport::join_host_port(addr, port),
            authorization,
            timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        }
    }

    /// `GET /api/status`.
    pub async fn status(&self) -> Result<Reply> {
        self.request("GET", "/api/status", None).await
    }

    /// `GET /api/reload?strictConfig=true`.
    pub async fn reload(&self, strict: bool) -> Result<Reply> {
        let path = if strict {
            "/api/reload?strictConfig=true"
        } else {
            "/api/reload"
        };
        self.request("GET", path, None).await
    }

    /// `POST /api/stop`.
    pub async fn stop(&self) -> Result<Reply> {
        self.request("POST", "/api/stop", None).await
    }

    /// An arbitrary route, for tests and for routes this crate does not wrap.
    pub async fn request_for_test(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Reply> {
        self.request(method, path, body).await
    }

    /// One request, one reply, one connection.
    async fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Reply> {
        let reply = tokio::time::timeout(self.timeout, self.request_inner(method, path, body))
            .await
            .map_err(|_| {
                Error::other(format!(
                    "the admin API at {} did not answer within {:?}",
                    self.addr, self.timeout
                ))
            })??;
        Ok(reply)
    }

    async fn request_inner(&self, method: &str, path: &str, body: Option<&str>) -> Result<Reply> {
        let mut socket = TcpStream::connect(&self.addr).await.map_err(|err| {
            Error::other(format!(
                "cannot reach the admin API at {}: {err}",
                self.addr
            ))
        })?;

        let body = body.unwrap_or("");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Content-Length: {}\r\n",
            self.addr,
            body.len(),
        );
        if let Some(authorization) = self.authorization.as_deref() {
            request.push_str(&format!("Authorization: {authorization}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);

        socket.write_all(request.as_bytes()).await?;
        socket.flush().await?;

        let mut raw = Vec::new();
        socket.read_to_end(&mut raw).await?;
        parse_reply(&raw).ok_or_else(|| {
            Error::other(format!(
                "the admin API at {} returned a malformed reply",
                self.addr
            ))
        })
    }
}

/// Splits an HTTP reply into its status and body.
///
/// `Content-Length` is trusted when present and ignored when not: Go's handlers
/// always send one, but a `Connection: close` reply is self-delimiting anyway, so
/// falling back to "everything after the headers" is both simpler and correct.
fn parse_reply(raw: &[u8]) -> Option<Reply> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let body = &raw[split + 4..];

    let status_line = head.lines().next()?;
    let status = status_line.split(' ').nth(1)?.parse().ok()?;

    // Chunked replies are not sent by the handlers this talks to, but a proxy in
    // front of one could, so the check is explicit rather than silent.
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };

    Some(Reply {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Unwraps a chunked body. Returns `None` if the framing does not parse.
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&rest[..end]).ok()?.trim(), 16).ok()?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Some(out);
        }
        if rest.len() < size {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..)?;
    }
}

/// Base64, for the `Authorization: Basic` header.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let triple = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// The encoder, exposed so the admin server's decoder can be tested against it.
#[cfg(test)]
pub(crate) fn base64_encode_for_test(input: &[u8]) -> String {
    base64_encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn a_reply_is_split_into_status_and_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let reply = parse_reply(raw).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "{}");
        assert!(reply.is_ok());
    }

    #[test]
    fn an_error_envelope_is_unwrapped() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 30\r\n\r\n\
                    {\"code\":404,\"msg\":\"not found\"}";
        let reply = parse_reply(raw).unwrap();
        assert_eq!(reply.status, 404);
        assert!(!reply.is_ok());
        assert_eq!(reply.error_message(), "not found");
    }

    #[test]
    fn a_body_that_is_not_an_envelope_is_reported_verbatim() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized\n";
        let reply = parse_reply(raw).unwrap();
        assert_eq!(reply.status, 401);
        assert_eq!(reply.error_message(), "Unauthorized");
    }

    #[test]
    fn a_chunked_body_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let reply = parse_reply(raw).unwrap();
        assert_eq!(reply.body, "hello world");
    }

    #[test]
    fn a_malformed_reply_is_rejected_rather_than_guessed_at() {
        assert!(parse_reply(b"not http at all").is_none());
        assert!(parse_reply(b"HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn an_empty_credential_pair_sends_no_header() {
        let client = AdminClient::new("127.0.0.1", 7400, "", "", None);
        assert!(client.authorization.is_none());
        assert_eq!(client.addr, "127.0.0.1:7400");

        let client = AdminClient::new("127.0.0.1", 7400, "admin", "hunter2", None);
        assert_eq!(
            client.authorization.as_deref(),
            Some("Basic YWRtaW46aHVudGVyMg==")
        );
    }

    #[test]
    fn the_timeout_defaults_to_the_go_api_timeout() {
        let client = AdminClient::new("127.0.0.1", 7400, "", "", None);
        assert_eq!(client.timeout, Duration::from_secs(30));
    }
}
