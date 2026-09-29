//! The frp message set and both control-connection framings.
//!
//! Field names, types and — importantly — the `omitempty` behaviour are copied
//! from `pkg/msg/msg.go`. Two Go quirks are load-bearing and easy to get wrong:
//!
//! * `omitempty` has no effect on a struct-typed field, only on its leaf fields,
//!   so `Login.client_spec` and `NatHoleResp.detect_behavior` are always present
//!   and serialize as `{}` when empty. [`omit`] handles the leaves, and the two
//!   structs deliberately carry no `skip_serializing_if` of their own.
//! * `encoding/json` escapes `<`, `>`, `&` as `<`, `>`, `&`, and
//!   emits map keys in sorted order. [`go_json`] reproduces both, so a body this
//!   crate writes is byte-identical to the one `frpc` would have written.
//!
//! Framing differs per wire protocol and is *not* negotiated — the client picks
//! it from `transport.wireProtocol` and the server sniffs the connection's first
//! bytes:
//!
//! * v1: `[1-byte type][i64 BE length][JSON]`, capped at [`V1_MAX_MESSAGE_LENGTH`].
//! * v2: a 7-byte magic, then `[u16 type][u16 flags][u32 length][payload]` frames
//!   where a `Message` frame's payload is a `u16` message id followed by JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// `golib`'s default cap on a v1 message body. frp never raises it, so a v1
/// message larger than this is rejected by the server's reader.
pub const V1_MAX_MESSAGE_LENGTH: i64 = 10_240;

/// The 7 bytes that announce wire protocol v2, before any frame.
pub const V2_MAGIC: &[u8; 7] = b"FRP\x00\x02\r\n";

/// A v2 frame payload cannot exceed this.
pub const V2_MAX_FRAME_PAYLOAD: usize = 65_536;

/// Frame kinds in the v2 header.
pub const FRAME_TYPE_CLIENT_HELLO: u16 = 1;
pub const FRAME_TYPE_SERVER_HELLO: u16 = 2;
pub const FRAME_TYPE_MESSAGE: u16 = 16;

/// `omitempty` predicates for the wire structs.
pub mod go_types;
pub mod omit {
    /// Drops zero-valued numbers, matching Go's `omitempty`.
    pub fn zero<T: Default + PartialEq>(value: &T) -> bool {
        *value == T::default()
    }

    /// Drops empty maps.
    pub fn map<K, V, S>(value: &std::collections::HashMap<K, V, S>) -> bool {
        value.is_empty()
    }

    /// Drops empty sorted maps.
    pub fn btree<K: Ord, V>(value: &std::collections::BTreeMap<K, V>) -> bool {
        value.is_empty()
    }
}

/// JSON encoding that matches Go's `encoding/json` byte for byte.
pub mod go_json {
    use crate::error::{Error, Result};

    /// Serializes with sorted keys (via `BTreeMap`) and Go's HTML escaping.
    pub fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        let plain = serde_json::to_string(value)
            .map_err(|err| Error::other(format!("encode json: {err}")))?;
        Ok(escape_html(plain).into_bytes())
    }

    /// Escapes `<`, `>`, `&` the way `encoding/json` does.
    ///
    /// A byte-level replacement is safe because `serde_json` only ever emits
    /// those three as literals: every escape it produces is a backslash followed
    /// by ASCII, and it escapes control characters as `\u00XX` rather than
    /// leaving them raw.
    fn escape_html(input: String) -> String {
        let mut out = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                '<' => out.push_str("\\u003c"),
                '>' => out.push_str("\\u003e"),
                '&' => out.push_str("\\u0026"),
                other => out.push(other),
            }
        }
        out
    }
}

/// A `map[string]string` on the wire. Sorted, so bodies are reproducible.
pub type Metas = BTreeMap<String, String>;

/// `msg.ClientSpec`, always serialized as an object even when empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSpec {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub always_auth_pass: bool,
}

/// `msg.Login`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "omit::btree")]
    pub metas: Metas,
    /// No `skip_serializing_if`: Go emits `"client_spec":{}` here.
    #[serde(default)]
    pub client_spec: ClientSpec,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub pool_count: i32,
}

/// `msg.LoginResp`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `msg.NewProxy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewProxy {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_type: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub use_encryption: bool,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub use_compression: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit_mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_key: String,
    #[serde(default, skip_serializing_if = "omit::btree")]
    pub metas: Metas,
    #[serde(default, skip_serializing_if = "omit::btree")]
    pub annotations: Metas,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub remote_port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subdomain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_pwd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_header_rewrite: String,
    #[serde(default, skip_serializing_if = "omit::btree")]
    pub headers: Metas,
    #[serde(default, skip_serializing_if = "omit::btree")]
    pub response_headers: Metas,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub route_by_http_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sk: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_users: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub multiplexer: String,
}

/// `msg.NewProxyResp`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewProxyResp {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `msg.CloseProxy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseProxy {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
}

/// `msg.NewWorkConn`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub timestamp: i64,
}

/// `msg.ReqWorkConn`, an empty struct that serializes as `{}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReqWorkConn {}

/// `msg.StartWorkConn`. Ports are `uint16` on the Go side, so a server port
/// above 65535 truncates rather than failing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartWorkConn {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub src_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dst_addr: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub src_port: u16,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub dst_port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `msg.NewVisitorConn`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewVisitorConn {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sign_key: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub use_encryption: bool,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub use_compression: bool,
}

/// `msg.NewVisitorConnResp`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewVisitorConnResp {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `msg.Ping`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub timestamp: i64,
}

/// `msg.Pong`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `net.UDPAddr` as `encoding/json` renders it: the IP goes through
/// `MarshalText` (so `"1.2.3.4"`, not base64) and `Zone` has no `omitempty`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpAddr {
    #[serde(default, rename = "IP", skip_serializing_if = "Option::is_none")]
    pub ip: Option<go_types::GoIp>,
    #[serde(default, rename = "Port")]
    pub port: u16,
    #[serde(default, rename = "Zone")]
    pub zone: String,
}

/// `msg.UDPPacket`. The JSON tags here are single letters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpPacket {
    /// Base64 on the wire, as Go's `[]byte` is — see [`go_types`].
    #[serde(
        default,
        rename = "c",
        skip_serializing_if = "go_types::GoBytes::is_empty"
    )]
    pub content: go_types::GoBytes,
    #[serde(default, rename = "l", skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpAddr>,
    #[serde(default, rename = "r", skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpAddr>,
}

/// `msg.NatHoleVisitor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleVisitor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub pre_check: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sign_key: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
}

/// `msg.NatHoleClient`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleClient {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
}

/// `msg.PortsRange`, as used inside `NatHoleDetectBehavior`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortsRange {
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub from: u16,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub to: u16,
}

/// `msg.NatHoleDetectBehavior`, always serialized as an object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleDetectBehavior {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub mode: i32,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub ttl: i32,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub send_delay_ms: i32,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub read_timeout: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_ports: Vec<PortsRange>,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub send_random_ports: i32,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub listen_random_ports: i32,
}

/// `msg.NatHoleResp`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleResp {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
    /// No `skip_serializing_if`: Go emits `"detect_behavior":{...}` here.
    #[serde(default)]
    pub detect_behavior: NatHoleDetectBehavior,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `msg.NatHoleSid`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub response: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce: String,
}

/// `msg.NatHoleReport`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatHoleReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "omit::zero")]
    pub success: bool,
}

/// One of the 18 registered message types.
///
/// Boxed because the largest variant (`NewProxy`) is around 500 bytes and the
/// rest are far smaller; keeping `Message` itself the size of a pointer means a
/// queued or buffered message does not cost 500 bytes per slot. Messages are
/// short-lived and low-volume, so the extra allocation is not on any hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    Login(Box<Login>),
    LoginResp(Box<LoginResp>),
    NewProxy(Box<NewProxy>),
    NewProxyResp(Box<NewProxyResp>),
    CloseProxy(Box<CloseProxy>),
    NewWorkConn(Box<NewWorkConn>),
    ReqWorkConn(Box<ReqWorkConn>),
    StartWorkConn(Box<StartWorkConn>),
    NewVisitorConn(Box<NewVisitorConn>),
    NewVisitorConnResp(Box<NewVisitorConnResp>),
    Ping(Box<Ping>),
    Pong(Box<Pong>),
    UdpPacket(Box<UdpPacket>),
    NatHoleVisitor(Box<NatHoleVisitor>),
    NatHoleClient(Box<NatHoleClient>),
    NatHoleResp(Box<NatHoleResp>),
    NatHoleSid(Box<NatHoleSid>),
    NatHoleReport(Box<NatHoleReport>),
}

impl Message {
    /// The v1 type byte, as written in front of the JSON body.
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Login(_) => b'o',
            Message::LoginResp(_) => b'1',
            Message::NewProxy(_) => b'p',
            Message::NewProxyResp(_) => b'2',
            Message::CloseProxy(_) => b'c',
            Message::NewWorkConn(_) => b'w',
            Message::ReqWorkConn(_) => b'r',
            Message::StartWorkConn(_) => b's',
            Message::NewVisitorConn(_) => b'v',
            Message::NewVisitorConnResp(_) => b'3',
            Message::Ping(_) => b'h',
            Message::Pong(_) => b'4',
            Message::UdpPacket(_) => b'u',
            Message::NatHoleVisitor(_) => b'i',
            Message::NatHoleClient(_) => b'n',
            Message::NatHoleResp(_) => b'm',
            Message::NatHoleSid(_) => b'5',
            Message::NatHoleReport(_) => b'6',
        }
    }

    /// The v2 message id.
    ///
    /// `UDPPacketBinary` (19) is not part of the generic registry — it has its
    /// own codec and no `Message` variant here.
    pub fn v2_id(&self) -> u16 {
        match self {
            Message::Login(_) => 1,
            Message::LoginResp(_) => 2,
            Message::NewProxy(_) => 3,
            Message::NewProxyResp(_) => 4,
            Message::CloseProxy(_) => 5,
            Message::NewWorkConn(_) => 6,
            Message::ReqWorkConn(_) => 7,
            Message::StartWorkConn(_) => 8,
            Message::NewVisitorConn(_) => 9,
            Message::NewVisitorConnResp(_) => 10,
            Message::Ping(_) => 11,
            Message::Pong(_) => 12,
            Message::UdpPacket(_) => 13,
            Message::NatHoleVisitor(_) => 14,
            Message::NatHoleClient(_) => 15,
            Message::NatHoleResp(_) => 16,
            Message::NatHoleSid(_) => 17,
            Message::NatHoleReport(_) => 18,
        }
    }

    /// The message's JSON body, matching Go's `encoding/json`.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        match self {
            Message::Login(m) => go_json::to_vec(m),
            Message::LoginResp(m) => go_json::to_vec(m),
            Message::NewProxy(m) => go_json::to_vec(m),
            Message::NewProxyResp(m) => go_json::to_vec(m),
            Message::CloseProxy(m) => go_json::to_vec(m),
            Message::NewWorkConn(m) => go_json::to_vec(m),
            Message::ReqWorkConn(m) => go_json::to_vec(m),
            Message::StartWorkConn(m) => go_json::to_vec(m),
            Message::NewVisitorConn(m) => go_json::to_vec(m),
            Message::NewVisitorConnResp(m) => go_json::to_vec(m),
            Message::Ping(m) => go_json::to_vec(m),
            Message::Pong(m) => go_json::to_vec(m),
            Message::UdpPacket(m) => go_json::to_vec(m),
            Message::NatHoleVisitor(m) => go_json::to_vec(m),
            Message::NatHoleClient(m) => go_json::to_vec(m),
            Message::NatHoleResp(m) => go_json::to_vec(m),
            Message::NatHoleSid(m) => go_json::to_vec(m),
            Message::NatHoleReport(m) => go_json::to_vec(m),
        }
    }

    /// Parses a body that belongs to `type_byte` (v1) or `id` (v2).
    fn from_json_kind(kind: MessageKind, json: &[u8]) -> Result<Message> {
        fn parse<T: for<'a> Deserialize<'a>>(json: &[u8]) -> Result<Box<T>> {
            serde_json::from_slice(json)
                .map(Box::new)
                .map_err(|err| Error::protocol(format!("decode json message: {err}")))
        }
        Ok(match kind {
            MessageKind::Login => Message::Login(parse(json)?),
            MessageKind::LoginResp => Message::LoginResp(parse(json)?),
            MessageKind::NewProxy => Message::NewProxy(parse(json)?),
            MessageKind::NewProxyResp => Message::NewProxyResp(parse(json)?),
            MessageKind::CloseProxy => Message::CloseProxy(parse(json)?),
            MessageKind::NewWorkConn => Message::NewWorkConn(parse(json)?),
            MessageKind::ReqWorkConn => Message::ReqWorkConn(parse(json)?),
            MessageKind::StartWorkConn => Message::StartWorkConn(parse(json)?),
            MessageKind::NewVisitorConn => Message::NewVisitorConn(parse(json)?),
            MessageKind::NewVisitorConnResp => Message::NewVisitorConnResp(parse(json)?),
            MessageKind::Ping => Message::Ping(parse(json)?),
            MessageKind::Pong => Message::Pong(parse(json)?),
            MessageKind::UdpPacket => Message::UdpPacket(parse(json)?),
            MessageKind::NatHoleVisitor => Message::NatHoleVisitor(parse(json)?),
            MessageKind::NatHoleClient => Message::NatHoleClient(parse(json)?),
            MessageKind::NatHoleResp => Message::NatHoleResp(parse(json)?),
            MessageKind::NatHoleSid => Message::NatHoleSid(parse(json)?),
            MessageKind::NatHoleReport => Message::NatHoleReport(parse(json)?),
        })
    }

    pub fn from_v1(type_byte: u8, json: &[u8]) -> Result<Message> {
        let kind = MessageKind::from_type_byte(type_byte)
            .ok_or_else(|| Error::protocol(format!("unknown message type byte {type_byte:#x}")))?;
        Self::from_json_kind(kind, json)
    }

    pub fn from_v2(id: u16, json: &[u8]) -> Result<Message> {
        let kind = MessageKind::from_v2_id(id)
            .ok_or_else(|| Error::protocol(format!("unknown v2 message id {id}")))?;
        Self::from_json_kind(kind, json)
    }
}

/// The message identity without its body, used to pick a decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Login,
    LoginResp,
    NewProxy,
    NewProxyResp,
    CloseProxy,
    NewWorkConn,
    ReqWorkConn,
    StartWorkConn,
    NewVisitorConn,
    NewVisitorConnResp,
    Ping,
    Pong,
    UdpPacket,
    NatHoleVisitor,
    NatHoleClient,
    NatHoleResp,
    NatHoleSid,
    NatHoleReport,
}

impl MessageKind {
    fn from_type_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            b'o' => Self::Login,
            b'1' => Self::LoginResp,
            b'p' => Self::NewProxy,
            b'2' => Self::NewProxyResp,
            b'c' => Self::CloseProxy,
            b'w' => Self::NewWorkConn,
            b'r' => Self::ReqWorkConn,
            b's' => Self::StartWorkConn,
            b'v' => Self::NewVisitorConn,
            b'3' => Self::NewVisitorConnResp,
            b'h' => Self::Ping,
            b'4' => Self::Pong,
            b'u' => Self::UdpPacket,
            b'i' => Self::NatHoleVisitor,
            b'n' => Self::NatHoleClient,
            b'm' => Self::NatHoleResp,
            b'5' => Self::NatHoleSid,
            b'6' => Self::NatHoleReport,
            _ => return None,
        })
    }

    fn from_v2_id(id: u16) -> Option<Self> {
        Some(match id {
            1 => Self::Login,
            2 => Self::LoginResp,
            3 => Self::NewProxy,
            4 => Self::NewProxyResp,
            5 => Self::CloseProxy,
            6 => Self::NewWorkConn,
            7 => Self::ReqWorkConn,
            8 => Self::StartWorkConn,
            9 => Self::NewVisitorConn,
            10 => Self::NewVisitorConnResp,
            11 => Self::Ping,
            12 => Self::Pong,
            13 => Self::UdpPacket,
            14 => Self::NatHoleVisitor,
            15 => Self::NatHoleClient,
            16 => Self::NatHoleResp,
            17 => Self::NatHoleSid,
            18 => Self::NatHoleReport,
            _ => return None,
        })
    }
}

/// Encodes one v1 message: `[type byte][i64 BE body length][body]`.
pub fn encode_v1(message: &Message) -> Result<Vec<u8>> {
    let body = message.to_json()?;
    if body.len() as i64 > V1_MAX_MESSAGE_LENGTH {
        return Err(Error::protocol(format!(
            "v1 message body is {} bytes, over the {V1_MAX_MESSAGE_LENGTH} byte limit",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(9 + body.len());
    out.push(message.type_byte());
    out.extend_from_slice(&(body.len() as i64).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Encodes a v2 `Message` frame payload: `[u16 BE id][body]`.
pub fn encode_v2_message(message: &Message) -> Result<Vec<u8>> {
    let body = message.to_json()?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&message.v2_id().to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// A parsed v2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Frame {
    pub frame_type: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl V2Frame {
    /// Encodes the 8-byte header plus payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.payload.len() > V2_MAX_FRAME_PAYLOAD {
            return Err(Error::protocol(format!(
                "v2 frame payload is {} bytes, over the {V2_MAX_FRAME_PAYLOAD} byte limit",
                self.payload.len()
            )));
        }
        let mut out = Vec::with_capacity(8 + self.payload.len());
        out.extend_from_slice(&self.frame_type.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Splits the payload of a `Message` frame into its id and body.
    pub fn message(&self) -> Result<Message> {
        if self.payload.len() < 2 {
            return Err(Error::protocol("v2 message frame is shorter than its id"));
        }
        let id = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        Message::from_v2(id, &self.payload[2..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_framing_is_type_then_i64_length_then_json() {
        let encoded = encode_v1(&Message::ReqWorkConn(Box::default())).unwrap();
        assert_eq!(encoded[0], b'r');
        assert_eq!(i64::from_be_bytes(encoded[1..9].try_into().unwrap()), 2);
        assert_eq!(&encoded[9..], b"{}");
    }

    #[test]
    fn v2_req_work_conn_is_four_bytes() {
        // Pinned by pkg/msg/wire_v2_test.go on the Go side.
        let payload = encode_v2_message(&Message::ReqWorkConn(Box::default())).unwrap();
        assert_eq!(payload, vec![0x00, 0x07, b'{', b'}']);
    }

    #[test]
    fn client_spec_is_always_serialized_even_when_empty() {
        // Go's omitempty does not apply to struct-valued fields.
        let login = Login::default();
        let json = String::from_utf8(login_json(&login)).unwrap();
        assert!(json.contains("\"client_spec\":{}"), "{json}");
    }

    fn login_json(login: &Login) -> Vec<u8> {
        go_json::to_vec(login).unwrap()
    }

    #[test]
    fn detect_behavior_is_always_serialized_even_when_empty() {
        let json = String::from_utf8(go_json::to_vec(&NatHoleResp::default()).unwrap()).unwrap();
        assert!(json.contains("\"detect_behavior\":{}"), "{json}");
    }

    #[test]
    fn empty_strings_and_numbers_are_omitted() {
        let json = String::from_utf8(login_json(&Login::default())).unwrap();
        assert_eq!(json, r#"{"client_spec":{}}"#);
    }

    #[test]
    fn map_keys_are_sorted_and_html_escaped_like_go() {
        let mut metas = Metas::new();
        metas.insert("zeta".into(), "<b>&</b>".into());
        metas.insert("alpha".into(), "1".into());
        let login = Login {
            metas,
            ..Login::default()
        };
        let json = String::from_utf8(login_json(&login)).unwrap();
        assert_eq!(
            json,
            "{\"metas\":{\"alpha\":\"1\",\"zeta\":\"\\u003cb\\u003e\\u0026\\u003c/b\\u003e\"},\"client_spec\":{}}"
        );
    }

    #[test]
    fn round_trips_through_v1() {
        let original = Message::StartWorkConn(Box::new(StartWorkConn {
            proxy_name: "web".into(),
            src_addr: "10.0.0.1".into(),
            src_port: 1234,
            dst_addr: "127.0.0.1".into(),
            dst_port: 80,
            error: String::new(),
        }));
        let encoded = encode_v1(&original).unwrap();
        let decoded = Message::from_v1(encoded[0], &encoded[9..]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trips_through_v2() {
        let original = Message::Login(Box::new(Login {
            version: "0.1.0".into(),
            user: "u1".into(),
            timestamp: 1,
            ..Login::default()
        }));
        let payload = encode_v2_message(&original).unwrap();
        let frame = V2Frame {
            frame_type: FRAME_TYPE_MESSAGE,
            flags: 0,
            payload,
        };
        let decoded = frame.message().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_unknown_type_bytes() {
        assert!(Message::from_v1(b'Z', b"{}").is_err());
    }

    #[test]
    fn rejects_oversized_v1_bodies() {
        let big = Message::Login(Box::new(Login {
            hostname: "x".repeat(V1_MAX_MESSAGE_LENGTH as usize),
            ..Login::default()
        }));
        assert!(encode_v1(&big).is_err());
    }

    #[test]
    fn udp_packet_matches_what_go_puts_on_the_wire() {
        // Byte-for-byte against `encoding/json` for this struct. Two things are
        // wrong-by-default in serde and both are silent: an IP is text rather
        // than a byte array, and a `[]byte` is base64 rather than an array of
        // numbers. Go produced exactly this.
        let packet = UdpPacket {
            content: vec![1, 2, 3].into(),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: Some(crate::msg::go_types::GoIp("127.0.0.1".parse().unwrap())),
                port: 53,
                zone: String::new(),
            }),
        };
        let json = String::from_utf8(go_json::to_vec(&packet).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"c":"AQID","r":{"IP":"127.0.0.1","Port":53,"Zone":""}}"#
        );
    }

    #[test]
    fn a_udp_packet_round_trips() {
        let packet = UdpPacket {
            content: b"\x00\xffbinary".to_vec().into(),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: Some(crate::msg::go_types::GoIp("2001:db8::1".parse().unwrap())),
                port: 5353,
                zone: String::new(),
            }),
        };
        let json = go_json::to_vec(&packet).unwrap();
        let decoded = Message::from_v1(b'u', &json).unwrap();
        assert_eq!(decoded, Message::UdpPacket(Box::new(packet)));
    }
}
