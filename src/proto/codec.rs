//! Message framing over a byte stream.
//!
//! Two framings, chosen by `transport.wireProtocol`. They are *not* negotiated:
//! a v2 client announces itself with a magic prefix, a v1 client just sends its
//! first message. Pointing one at a peer speaking the other fails at the first
//! read, which is why v1 is the default here.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::msg::{
    encode_v1, encode_v2_message, Message, FRAME_TYPE_CLIENT_HELLO, FRAME_TYPE_MESSAGE,
    FRAME_TYPE_SERVER_HELLO, V1_MAX_MESSAGE_LENGTH, V2_MAGIC, V2_MAX_FRAME_PAYLOAD,
};

/// Which framing to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireProtocol {
    /// `[type byte][i64 BE length][JSON]`, the default.
    #[default]
    V1,
    /// A 7-byte magic followed by `[u16 type][u16 flags][u32 length]` frames.
    V2,
}

impl WireProtocol {
    /// Parses the config value. Anything but `v2` is v1, which is what the Go
    /// side's `EmptyOr(..., "v1")` amounts to after validation.
    pub fn parse(value: &str) -> WireProtocol {
        match value {
            "v2" => WireProtocol::V2,
            _ => WireProtocol::V1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WireProtocol::V1 => "v1",
            WireProtocol::V2 => "v2",
        }
    }
}

/// Reads and writes complete messages on a stream.
///
/// Deliberately does not buffer or pipeline: frp's control connection is a
/// request/response conversation with one message in flight, and a plain
/// await-per-message loop is much easier to reason about than a framed codec with
/// its own task.
#[derive(Debug, Clone, Copy)]
pub struct Codec {
    protocol: WireProtocol,
}

impl Default for Codec {
    fn default() -> Self {
        Self::new(WireProtocol::V1)
    }
}

impl Codec {
    pub fn new(protocol: WireProtocol) -> Self {
        Self { protocol }
    }

    pub fn protocol(&self) -> WireProtocol {
        self.protocol
    }

    /// Writes the v2 magic, if this is a v2 session.
    ///
    /// Called once per connection, before the first message. On a v1 session it
    /// writes nothing.
    pub async fn write_handshake_prefix<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<()> {
        if self.protocol == WireProtocol::V2 {
            writer.write_all(V2_MAGIC).await?;
        }
        Ok(())
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W, msg: &Message) -> Result<()> {
        match self.protocol {
            WireProtocol::V1 => {
                let bytes = encode_v1(msg)?;
                writer.write_all(&bytes).await?;
            }
            WireProtocol::V2 => {
                let payload = encode_v2_message(msg)?;
                let frame = crate::msg::V2Frame {
                    frame_type: FRAME_TYPE_MESSAGE,
                    flags: 0,
                    payload,
                };
                writer.write_all(&frame.encode()?).await?;
            }
        }
        writer.flush().await?;
        Ok(())
    }

    /// Reads one complete message.
    pub async fn read<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Message> {
        match self.protocol {
            WireProtocol::V1 => read_v1(reader).await,
            WireProtocol::V2 => read_v2(reader).await,
        }
    }

    /// Writes a `ClientHello` frame, needed once at the start of a v2 control
    /// session. Work connections must not send one.
    pub async fn write_client_hello<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        if self.protocol != WireProtocol::V2 {
            return Err(Error::protocol(
                "a ClientHello only exists in wire protocol v2",
            ));
        }
        let frame = crate::msg::V2Frame {
            frame_type: FRAME_TYPE_CLIENT_HELLO,
            flags: 0,
            payload: payload.to_vec(),
        };
        writer.write_all(&frame.encode()?).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Reads the next frame, whatever its kind. Used for the v2 hello exchange.
    pub async fn read_frame<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<crate::msg::V2Frame> {
        let mut header = [0u8; 8];
        reader.read_exact(&mut header).await?;

        let frame_type = u16::from_be_bytes([header[0], header[1]]);
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        if flags != 0 {
            return Err(Error::protocol(format!(
                "v2 frame has non-zero flags {flags:#x}"
            )));
        }
        if length > V2_MAX_FRAME_PAYLOAD {
            return Err(Error::protocol(format!(
                "v2 frame payload is {length} bytes, over the {V2_MAX_FRAME_PAYLOAD} byte limit"
            )));
        }

        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;
        Ok(crate::msg::V2Frame {
            frame_type,
            flags,
            payload,
        })
    }
}

/// The frame kinds the codec knows about, re-exported for callers that read raw
/// frames.
pub const CLIENT_HELLO: u16 = FRAME_TYPE_CLIENT_HELLO;
pub const SERVER_HELLO: u16 = FRAME_TYPE_SERVER_HELLO;

async fn read_v1<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message> {
    let mut type_byte = [0u8; 1];
    reader.read_exact(&mut type_byte).await?;

    let mut length_bytes = [0u8; 8];
    reader.read_exact(&mut length_bytes).await?;
    let length = i64::from_be_bytes(length_bytes);

    if length < 0 {
        return Err(Error::protocol(format!(
            "v1 message length {length} is negative"
        )));
    }
    if length > V1_MAX_MESSAGE_LENGTH {
        // The Go reader rejects this too, so a peer that sends it is broken
        // rather than merely newer.
        return Err(Error::protocol(format!(
            "v1 message body is {length} bytes, over the {V1_MAX_MESSAGE_LENGTH} byte limit"
        )));
    }

    let mut body = vec![0u8; length as usize];
    reader.read_exact(&mut body).await?;
    Message::from_v1(type_byte[0], &body)
}

async fn read_v2<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;

    let frame_type = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    if flags != 0 {
        return Err(Error::protocol(format!(
            "v2 frame has non-zero flags {flags:#x}"
        )));
    }
    if length > V2_MAX_FRAME_PAYLOAD {
        return Err(Error::protocol(format!(
            "v2 frame payload is {length} bytes, over the {V2_MAX_FRAME_PAYLOAD} byte limit"
        )));
    }
    if frame_type != FRAME_TYPE_MESSAGE {
        return Err(Error::protocol(format!(
            "expected a v2 Message frame (16), got frame type {frame_type}"
        )));
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    crate::msg::V2Frame {
        frame_type,
        flags,
        payload,
    }
    .message()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Login;

    /// Encodes a message, then reads it back through the codec. The two
    /// framings differ enough that both need their own round trip.
    #[tokio::test]
    async fn v1_round_trips_through_the_codec() {
        let codec = Codec::new(WireProtocol::V1);
        let mut buffer = Vec::new();
        let original = Message::Login(Box::new(Login {
            version: "rust-frpc.0.1.0".into(),
            user: "u1".into(),
            timestamp: 1_712_345_678,
            ..Login::default()
        }));

        codec.write_handshake_prefix(&mut buffer).await.unwrap();
        // A v1 session sends nothing before its first message.
        assert!(buffer.is_empty());
        codec.write(&mut buffer, &original).await.unwrap();

        let mut cursor = &buffer[..];
        let decoded = codec.read(&mut cursor).await.unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    async fn v2_round_trips_and_prefixes_the_magic() {
        let codec = Codec::new(WireProtocol::V2);
        let mut buffer = Vec::new();
        let original = Message::ReqWorkConn(Box::default());

        codec.write_handshake_prefix(&mut buffer).await.unwrap();
        assert_eq!(&buffer, V2_MAGIC);
        codec.write(&mut buffer, &original).await.unwrap();

        let mut cursor = &buffer[V2_MAGIC.len()..];
        let decoded = codec.read(&mut cursor).await.unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    async fn v1_rejects_an_oversized_length() {
        let codec = Codec::new(WireProtocol::V1);
        let mut bytes = vec![b'o'];
        bytes.extend_from_slice(&(V1_MAX_MESSAGE_LENGTH + 1).to_be_bytes());
        let err = codec.read(&mut &bytes[..]).await.unwrap_err();
        assert!(err.to_string().contains("over the"), "{err}");
    }

    #[tokio::test]
    async fn v2_rejects_a_non_message_frame_where_a_message_belongs() {
        let codec = Codec::new(WireProtocol::V2);
        let frame = crate::msg::V2Frame {
            frame_type: FRAME_TYPE_SERVER_HELLO,
            flags: 0,
            payload: b"{}".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = codec.read(&mut &bytes[..]).await.unwrap_err();
        assert!(err.to_string().contains("Message frame"), "{err}");
    }

    #[tokio::test]
    async fn v2_rejects_non_zero_flags() {
        let codec = Codec::new(WireProtocol::V2);
        let frame = crate::msg::V2Frame {
            frame_type: FRAME_TYPE_MESSAGE,
            flags: 1,
            payload: vec![0, 7, b'{', b'}'],
        };
        let bytes = frame.encode().unwrap();
        let err = codec.read(&mut &bytes[..]).await.unwrap_err();
        assert!(err.to_string().contains("non-zero flags"), "{err}");
    }

    #[tokio::test]
    async fn a_client_hello_is_refused_on_v1() {
        let codec = Codec::new(WireProtocol::V1);
        let mut buffer = Vec::new();
        assert!(codec.write_client_hello(&mut buffer, b"{}").await.is_err());
    }

    #[test]
    fn wire_protocol_parses_like_the_go_side() {
        assert_eq!(WireProtocol::parse("v2"), WireProtocol::V2);
        assert_eq!(WireProtocol::parse("v1"), WireProtocol::V1);
        // Anything unrecognized behaves as the default.
        assert_eq!(WireProtocol::parse(""), WireProtocol::V1);
    }

    #[tokio::test]
    async fn a_second_message_follows_the_first_on_the_same_stream() {
        // The control loop writes and reads repeatedly on one connection, so the
        // reader must not over-consume.
        let codec = Codec::new(WireProtocol::V1);
        let mut buffer = Vec::new();
        codec
            .write(&mut buffer, &Message::LoginResp(Box::default()))
            .await
            .unwrap();
        codec
            .write(&mut buffer, &Message::Pong(Box::default()))
            .await
            .unwrap();

        let mut cursor = &buffer[..];
        assert_eq!(
            codec.read(&mut cursor).await.unwrap(),
            Message::LoginResp(Box::default())
        );
        assert_eq!(
            codec.read(&mut cursor).await.unwrap(),
            Message::Pong(Box::default())
        );
    }
}
