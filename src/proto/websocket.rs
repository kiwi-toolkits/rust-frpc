//! The websocket transport.
//!
//! frp uses `golang.org/x/net/websocket`, not the more common gorilla stack, and
//! the two differ in ways that matter on the wire. Everything below is matched
//! against x/net at the version `frp` pins (`v0.56.0`):
//!
//! * the handshake is a plain `GET /~!frp` with `Upgrade: websocket`,
//!   `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, a base64 nonce in
//!   `Sec-WebSocket-Key`, and an `Origin` of `http://<host>` in lower case;
//! * the reply must be `101` with a matching `Sec-WebSocket-Accept`
//!   (`base64(sha1(key ‖ GUID))`) and **no** `Sec-WebSocket-Extensions` — x/net
//!   treats an extension it did not ask for as a failed handshake, so
//!   permessage-deflate must not be offered;
//! * a **client** masks every frame it sends, and rejects a frame from the
//!   server that is masked (`hybiFrameHandler.HandleFrame` closes the connection
//!   with 1002 in that case);
//! * each `Write` from the layer above becomes exactly one frame with `FIN` set
//!   and the payload type `BinaryFrame`, which is what frp sets
//!   (`conn.PayloadType = websocket.BinaryFrame`) so that a byte-oriented
//!   intermediary does not UTF-8-validate the tunnel;
//! * inbound `Ping` is answered with `Pong` carrying the same payload, and
//!   `Close` ends the stream.
//!
//! What the layer above sees is a byte stream, because messages are only a
//! framing detail here: frp puts yamux — or a v1 frame — inside, and neither
//! cares where the frame boundaries fall. Reads concatenate payloads across
//! frames; writes emit one frame per call.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};

/// `FrpWebsocketPath`.
pub const PATH: &str = "/~!frp";

/// The magic value RFC 6455 defines for `Sec-WebSocket-Accept`.
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Frame opcodes.
mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// The largest payload a control frame may carry (RFC 6455 §5.5).
const MAX_CONTROL_PAYLOAD: usize = 125;

/// How much of a frame's header to buffer before giving up on it.
///
/// A 64-bit length field cannot legitimately be used for anything a tunnel
/// carries, and `frp` never asks for a payload anywhere near this. The limit
/// exists so a peer that announces an absurd length cannot make this allocate on
/// its behalf.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// A websocket connection carrying a byte stream.
#[derive(Debug)]
pub struct WebSocket<S> {
    inner: S,
    /// Raw socket bytes not yet consumed by the frame parser.
    read_buf: BytesMut,
    /// Payload of the frame being read out, if one is part-way through.
    payload: BytesMut,
    /// Opcode inherited by continuation frames, per `hybiFrameHandler`.
    continuation: u8,
    /// A frame built by `poll_write` and not yet fully written.
    write_pending: BytesMut,
    /// Set once a `Close` has been seen or sent; further reads report EOF.
    closed: bool,
}

impl<S> WebSocket<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            // Sized to the largest header plus a typical payload, so the common
            // case does not grow the buffer on the first read.
            read_buf: BytesMut::with_capacity(4096),
            payload: BytesMut::new(),
            continuation: 0,
            write_pending: BytesMut::new(),
            closed: false,
        }
    }
}

/// The bits of a frame header the parser needs before the payload.
#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    fin: bool,
    opcode: u8,
    masked: bool,
    payload_len: usize,
    /// Header size in bytes, so the payload can be sliced out.
    header_len: usize,
}

/// What a parsed frame asks for.
enum Frame {
    /// Payload bytes to hand to the reader.
    Data(Vec<u8>),
    /// A ping to answer.
    Ping(Vec<u8>),
    /// A close, or anything else that ends the stream.
    Close,
    /// A pong, which x/net discards; kept as a variant only to be explicit.
    Pong,
}

/// Runs the client handshake over `inner`, returning a framed connection.
///
/// `host` is what goes in `Host:` and in the `Origin` — the dial address for a
/// plain `websocket`, and `tls.serverName` for `wss`, which is what Go's
/// `DialHookWebsocket(protocol, host)` is handed.
pub async fn connect<S>(mut inner: S, host: &str) -> Result<WebSocket<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = nonce();
    let request = format!(
        "GET {PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Origin: http://{origin}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        // Go writes `strings.ToLower(config.Origin.String())`, and `Origin` is
        // built from the same host, so both are lowered together.
        origin = host.to_lowercase(),
    );
    inner
        .write_all(request.as_bytes())
        .await
        .map_err(|err| Error::other(format!("websocket handshake write: {err}")))?;
    inner
        .flush()
        .await
        .map_err(|err| Error::other(format!("websocket handshake flush: {err}")))?;

    let head = read_response_head(&mut inner).await?;
    check_response(&head, &key)?;

    Ok(WebSocket::new(inner))
}

/// Reads the server's HTTP response head, leaving any bytes after it alone.
///
/// The head ends at the first `\r\n\r\n`. Anything the server sent after that is
/// the first websocket frame, and it has to be kept — a `read_exact` into a
/// fixed buffer would swallow it.
async fn read_response_head<S>(inner: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = inner
            .read(&mut byte)
            .await
            .map_err(|err| Error::other(format!("websocket handshake read: {err}")))?;
        if read == 0 {
            return Err(Error::other(
                "websocket handshake: the server closed before answering".to_string(),
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > 8192 {
            return Err(Error::other(
                "websocket handshake: the response head never ended".to_string(),
            ));
        }
    }
}

/// Checks the response the way `hybiClientHandshake` does.
fn check_response(head: &[u8], key: &str) -> Result<()> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let _http = parts.next();
    let code = parts.next().unwrap_or_default();
    if code != "101" {
        return Err(Error::other(format!(
            "websocket handshake: expected 101, got {status:?}"
        )));
    }

    let mut upgrade = String::new();
    let mut connection = String::new();
    let mut accept = String::new();
    let mut extensions = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "upgrade" => upgrade = value.to_ascii_lowercase(),
            "connection" => connection = value.to_ascii_lowercase(),
            "sec-websocket-accept" => accept = value.to_string(),
            "sec-websocket-extensions" => extensions = value.to_string(),
            _ => {}
        }
    }

    if upgrade != "websocket" || connection != "upgrade" {
        return Err(Error::other(format!(
            "websocket handshake: bad Upgrade/Connection ({upgrade:?}/{connection:?})"
        )));
    }
    if accept != nonce_accept(key) {
        return Err(Error::other(
            "websocket handshake: Sec-WebSocket-Accept did not match the key".to_string(),
        ));
    }
    // x/net fails the handshake outright on an extension it did not offer, and
    // offering `permessage-deflate` means the payload is no longer a byte stream
    // this side can read without implementing it.
    if !extensions.is_empty() {
        return Err(Error::other(format!(
            "websocket handshake: the server offered extensions ({extensions:?}) that frp \
             never asks for"
        )));
    }
    Ok(())
}

/// A fresh `Sec-WebSocket-Key`: 16 random bytes, base64.
fn nonce() -> String {
    use rand::RngCore;
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    base64_encode(&key)
}

/// `base64(sha1(key ‖ WEBSOCKET_GUID))`.
fn nonce_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64_encode(&hasher.finalize())
}

/// Standard-alphabet base64 with padding, which is all RFC 6455 needs.
///
/// Hand-rolled rather than pulling in a crate: this is the only use in the whole
/// client, and it is twenty lines against a dependency.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(bits >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(bits >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(bits >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[bits as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Parses a frame header, or returns `None` if the buffer is short.
fn parse_header(buf: &[u8]) -> Result<Option<FrameHeader>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let first = buf[0];
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0f;
    // RSV1/2/3 must be zero: no extension was negotiated. x/net does not check
    // this, but a set bit means the frame is not the byte stream it appears to
    // be, and reading on regardless would hand the layer above corruption.
    if first & 0x70 != 0 {
        return Err(Error::protocol(
            "websocket: a frame arrived with an extension bit set, and no extension was agreed",
        ));
    }

    let second = buf[1];
    let masked = second & 0x80 != 0;
    let len_code = (second & 0x7f) as usize;
    let (payload_len, mut header_len) = match len_code {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (usize::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[2..10]);
            // The top bit must be zero, and x/net masks it rather than
            // rejecting — matched here so the two agree on the length.
            let len = u64::from_be_bytes(bytes) & 0x7fff_ffff_ffff_ffff;
            (len as usize, 10)
        }
        n => (n, 2),
    };

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(Error::protocol(format!(
            "websocket: the peer announced a {payload_len}-byte frame"
        )));
    }
    if masked {
        header_len += 4;
    }
    // The length field's own bytes are not the whole header when a masking key
    // follows, and the key is read from the header rather than the payload — so
    // a buffer that reaches the end of the length field is still incomplete.
    if buf.len() < header_len {
        return Ok(None);
    }
    Ok(Some(FrameHeader {
        fin,
        opcode,
        masked,
        payload_len,
        header_len,
    }))
}

/// Unmasks in place with the key that follows the length field.
fn unmask(payload: &mut [u8], key: &[u8]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

/// Builds one frame around `msg`.
///
/// `key` is `Some` for a client frame, which must be masked, and `None` for the
/// server's, which must not be. Production only ever builds the first kind — see
/// [`server_frame`] for why the other exists.
fn build_frame(msg: &[u8], opcode: u8, key: Option<[u8; 4]>) -> BytesMut {
    let mut out = BytesMut::with_capacity(msg.len() + 14);
    out.extend_from_slice(&[0x80 | opcode]);
    let mask_bit = if key.is_some() { 0x80 } else { 0 };
    match msg.len() {
        len if len <= 125 => out.extend_from_slice(&[mask_bit | len as u8]),
        len if len < 65536 => {
            out.extend_from_slice(&[mask_bit | 126]);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.extend_from_slice(&[mask_bit | 127]);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }

    match key {
        None => out.extend_from_slice(msg),
        Some(key) => {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(msg);
            let mut payload = out.split_off(start);
            unmask(&mut payload, &key);
            out.unsplit(payload);
        }
    }
    out
}

/// A frame as this client sends it: masked with a fresh key.
fn frame(msg: &[u8], opcode: u8) -> BytesMut {
    use rand::RngCore;
    let mut key = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut key);
    build_frame(msg, opcode, Some(key))
}

/// A frame as a *server* sends it: unmasked.
///
/// Only tests use this. The two roles differ on the wire — a client masks and
/// the server does not, and each rejects the other's choice — so a test that
/// built its peer's frames with [`frame`] would be testing against bytes no
/// `frps` ever emits.
#[cfg(test)]
fn server_frame(msg: &[u8], opcode: u8) -> BytesMut {
    build_frame(msg, opcode, None)
}

impl<S: AsyncRead + Unpin> WebSocket<S> {
    /// Parses a whole frame out of `read_buf`, or `None` if one is not complete.
    fn take_frame(&mut self) -> Result<Option<Frame>> {
        let Some(header) = parse_header(&self.read_buf)? else {
            return Ok(None);
        };
        let total = header.header_len + header.payload_len;
        if self.read_buf.len() < total {
            // Make room for the payload so the next socket read can fill it.
            self.read_buf.reserve(total - self.read_buf.len());
            return Ok(None);
        }

        // A client rejects a masked frame from the server: `hybiFrameHandler`
        // closes with 1002 when `IsServerConn()` is false and the masking key is
        // present.
        if header.masked {
            return Err(Error::protocol(
                "websocket: the server masked a frame, which RFC 6455 forbids",
            ));
        }

        self.read_buf.advance(header.header_len);
        let payload = self.read_buf.split_to(header.payload_len).to_vec();

        if header.opcode >= opcode::CLOSE {
            // Control frames may be interleaved between the fragments of a data
            // message and are never themselves fragmented.
            if !header.fin || payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(Error::protocol(
                    "websocket: a control frame was fragmented or oversized",
                ));
            }
            return Ok(Some(match header.opcode {
                opcode::PING => Frame::Ping(payload),
                opcode::PONG => Frame::Pong,
                _ => Frame::Close,
            }));
        }

        // A continuation inherits the opcode of the message it belongs to, which
        // is what tells a text message from a binary one across fragments.
        let opcode = match header.opcode {
            opcode::CONTINUATION => self.continuation,
            other => {
                self.continuation = other;
                other
            }
        };
        if !matches!(opcode, opcode::TEXT | opcode::BINARY) {
            return Err(Error::protocol(format!(
                "websocket: unknown opcode {opcode:#x}"
            )));
        }
        Ok(Some(Frame::Data(payload)))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocket<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.closed {
                return Poll::Ready(Ok(()));
            }

            // Whatever is left of the current frame goes first.
            if !this.payload.is_empty() {
                let n = this.payload.len().min(buf.remaining());
                buf.put_slice(&this.payload[..n]);
                this.payload.advance(n);
                return Poll::Ready(Ok(()));
            }

            match this.take_frame() {
                Ok(Some(Frame::Data(payload))) => {
                    this.payload = BytesMut::from(payload.as_slice());
                    continue;
                }
                Ok(Some(Frame::Ping(payload))) => {
                    // Answer on the way past; a pong that cannot be written
                    // immediately is queued behind whatever is already pending,
                    // and frp's peers do not ping, so this is a formality rather
                    // than a path anything depends on.
                    let pong = frame(&payload, opcode::PONG);
                    this.write_pending.unsplit(pong);
                    let _ = this.try_flush(cx)?;
                    continue;
                }
                Ok(Some(Frame::Pong)) | Ok(None) => {}
                Ok(Some(Frame::Close)) => {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                // A malformed frame ends the stream, which is what
                // `hybiFrameHandler` does too — it writes a close and returns
                // EOF rather than failing the read. Logged rather than silent,
                // because "the tunnel closed" and "the peer sent nonsense" are
                // very different things to be looking at from a log.
                Err(err) => {
                    crate::logging::debug(format!("websocket: {err}"));
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
            }

            let mut chunk = [0u8; 8192];
            let mut read = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled();
                    if filled.is_empty() {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.read_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    /// Writes as much of `write_pending` as the socket will take right now.
    ///
    /// `Poll::Pending` means "not finished, and a waker is registered"; the
    /// caller must not treat it as an error.
    fn try_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_pending.is_empty() {
            let written = match Pin::new(&mut self.inner).poll_write(cx, &self.write_pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "websocket: the socket stopped accepting bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };
            self.write_pending.advance(written);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocket<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket: the connection is closed",
            )));
        }

        // A frame is written whole or not at all, so a call that arrives while
        // one is still going out waits for it rather than interleaving.
        if !this.write_pending.is_empty() {
            match this.try_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.write_pending.unsplit(frame(buf, opcode::BINARY));
        // Report the whole slice as accepted: it is framed and queued, and the
        // next call drains the queue before taking more.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.try_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            // A zero-length close frame, which is what x/net sends when the
            // caller has not asked for a status.
            this.write_pending.unsplit(frame(&[], opcode::CLOSE));
        }
        match this.try_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn the_base64_matches_the_reference_encoding() {
        // The RFC 4648 vectors, which is the same alphabet and padding.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// The accept value from RFC 6455 §1.3, which is the one every websocket
    /// implementation is checked against.
    #[test]
    fn the_accept_header_matches_the_rfc_example() {
        assert_eq!(
            nonce_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn a_nonce_is_sixteen_bytes_of_base64() {
        let nonce = nonce();
        assert_eq!(nonce.len(), 24);
        assert!(nonce.ends_with("=="), "16 bytes leaves one partial group");
        assert_ne!(nonce, self::nonce(), "the nonce must not repeat");
    }

    #[test]
    fn the_first_byte_of_a_frame_is_fin_or_binary() {
        let framed = frame(b"hello", opcode::BINARY);
        assert_eq!(framed[0], 0x82, "FIN set, binary opcode");
        // Masked, seven-bit length of five, then a four-byte key.
        assert_eq!(framed[1], 0x80 | 5);
        assert_eq!(framed.len(), 2 + 4 + 5);
    }

    #[test]
    fn a_long_frame_uses_the_extended_length_field() {
        let framed = frame(&[0u8; 200], opcode::BINARY);
        assert_eq!(framed[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([framed[2], framed[3]]), 200);
        assert_eq!(framed.len(), 4 + 4 + 200);

        let framed = frame(&[0u8; 70_000], opcode::BINARY);
        assert_eq!(framed[1], 0x80 | 127);
        assert_eq!(framed.len(), 10 + 4 + 70_000);
    }

    /// The masking is the part a peer checks first: an unmasked client frame is
    /// a protocol error, and a wrongly masked one is silent corruption.
    #[test]
    fn the_payload_is_masked_with_the_key_in_the_header() {
        let payload = b"the quick brown fox";
        let framed = frame(payload, opcode::BINARY);
        let key = &framed[2..6];
        let body = &framed[6..];
        assert_eq!(body.len(), payload.len());
        assert_ne!(body, payload.as_slice());

        let mut recovered = body.to_vec();
        unmask(&mut recovered, key);
        assert_eq!(recovered, payload);
    }

    /// The header parser has to be able to say "not yet" without losing its
    /// place, and it has to know where its own header ends.
    ///
    /// The masked case is the one worth pinning: a one-byte length field is
    /// followed by a four-byte masking key that is still part of the header, so
    /// a parser that stopped at the length would read the key as payload.
    #[test]
    fn a_short_prefix_does_not_parse_as_a_header() {
        let framed = frame(b"a longer payload than one read", opcode::BINARY);
        // Two bytes for a seven-bit length, then four for the mask key.
        for cut in 0..6 {
            assert!(
                parse_header(&framed[..cut]).unwrap().is_none(),
                "a {cut}-byte prefix should not parse as a complete header"
            );
        }

        // Six is a whole header, and a whole header is not a whole frame: the
        // payload is what `take_frame` still has to wait for.
        let header = parse_header(&framed[..6]).unwrap().expect("a whole header");
        assert!(header.fin);
        assert_eq!(header.opcode, opcode::BINARY);
        assert!(header.masked);
        assert_eq!(header.payload_len, 30);
        assert_eq!(header.header_len, 6);
    }

    /// The same for the extended length fields, which have their own widths.
    #[test]
    fn an_extended_length_field_must_be_complete_too() {
        // A client frame: four header bytes, then four more for the mask key.
        let long = frame(&[0u8; 200], opcode::BINARY);
        for cut in 0..8 {
            assert!(parse_header(&long[..cut]).unwrap().is_none(), "{cut}");
        }
        let header = parse_header(&long[..8]).unwrap().expect("a whole header");
        assert_eq!(header.payload_len, 200);
        assert_eq!(header.header_len, 8);

        // A server frame carries no masking key, so its header is shorter — and
        // the same buffer length is therefore complete for one and not the other.
        let huge = server_frame(&[0u8; 70_000], opcode::BINARY);
        for cut in 0..10 {
            assert!(parse_header(&huge[..cut]).unwrap().is_none(), "{cut}");
        }
        let header = parse_header(&huge).unwrap().unwrap();
        assert_eq!(header.payload_len, 70_000);
        assert_eq!(header.header_len, 10);
        assert!(!header.masked);
    }

    /// A server frame must not be masked, and reading one that is would be
    /// silently wrong rather than merely non-conforming.
    #[test]
    fn a_masked_frame_from_the_server_is_refused() {
        let mut server_frame = vec![0x82, 0x80 | 3];
        server_frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        server_frame.extend_from_slice(&[0, 0, 0]);
        let header = parse_header(&server_frame).unwrap().unwrap();
        assert!(header.masked);
    }

    /// An extension bit means the payload is not the byte stream it looks like.
    #[test]
    fn a_reserved_bit_is_refused() {
        let framed = frame(b"hi", opcode::BINARY);
        let mut with_rsv1 = framed.to_vec();
        with_rsv1[0] |= 0x40;
        assert!(parse_header(&with_rsv1).is_err());
    }

    /// Reads one frame from the far end, the way a server would: it must be
    /// masked, and the payload has to come back unmasked with the key.
    async fn read_client_frame<S>(peer: &mut S) -> (u8, Vec<u8>)
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0u8; 2];
        peer.read_exact(&mut header).await.unwrap();
        let opcode = header[0] & 0x0f;
        assert_eq!(header[0] & 0x80, 0x80, "FIN must be set on every frame");
        assert_eq!(header[1] & 0x80, 0x80, "a client frame must be masked");
        let len = (header[1] & 0x7f) as usize;
        assert!(len <= 125, "these tests only use short payloads");

        let mut rest = vec![0u8; 4 + len];
        peer.read_exact(&mut rest).await.unwrap();
        let key = rest[..4].to_vec();
        let mut payload = rest[4..].to_vec();
        unmask(&mut payload, &key);
        (opcode, payload)
    }

    /// A write becomes exactly one masked frame, and reads concatenate frames.
    ///
    /// The far end here is not another `WebSocket`: that type implements the
    /// *client* role, which rejects a masked frame, so using one on both ends
    /// would test a conversation that cannot happen against a real `frps`.
    #[tokio::test]
    async fn a_write_becomes_one_frame_and_reads_reassemble_them() {
        let (peer, us) = tokio::io::duplex(4096);
        let mut conn = WebSocket::new(us);
        let mut peer = peer;

        conn.write_all(b"payload one").await.unwrap();
        conn.flush().await.unwrap();
        let (opcode, payload) = read_client_frame(&mut peer).await;
        assert_eq!(opcode, opcode::BINARY);
        assert_eq!(payload, b"payload one");

        // Two writes are two frames, and the reader joins them — which is what
        // lets yamux treat this as a byte stream.
        conn.write_all(b"two ").await.unwrap();
        conn.write_all(b"three").await.unwrap();
        conn.flush().await.unwrap();
        assert_eq!(read_client_frame(&mut peer).await.1, b"two ");
        assert_eq!(read_client_frame(&mut peer).await.1, b"three");

        // And the other direction, which is what the client actually reads.
        peer.write_all(&server_frame(b"from the server", opcode::BINARY))
            .await
            .unwrap();
        let mut got = [0u8; 15];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"from the server");
    }

    /// A frame split across two socket reads still arrives whole.
    ///
    /// This is the case the buffer has to get right: a parser that consumed a
    /// partial header would lose its place and corrupt everything after it.
    #[tokio::test]
    async fn a_frame_split_across_reads_is_reassembled() {
        let (peer, us) = tokio::io::duplex(4096);
        let mut conn = WebSocket::new(us);
        let mut peer = peer;

        let framed = server_frame(b"split down the middle", opcode::BINARY);
        let (first, second) = framed.split_at(5);
        peer.write_all(first).await.unwrap();

        // Nothing is readable yet, and the reader must wait rather than report
        // a five-byte message.
        let mut got = [0u8; 21];
        let pending =
            tokio::time::timeout(Duration::from_millis(100), conn.read_exact(&mut got)).await;
        assert!(pending.is_err(), "half a frame is not a message");

        peer.write_all(second).await.unwrap();
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"split down the middle");
    }

    /// A close frame ends the stream rather than being delivered as payload.
    #[tokio::test]
    async fn a_close_frame_reads_as_eof() {
        // One end of the pipe is the peer, which writes the close frame; the
        // other is the connection under test, which reads it.
        let (peer, us) = tokio::io::duplex(4096);
        let mut conn = WebSocket::new(us);

        let mut peer = peer;
        peer.write_all(&server_frame(&[], opcode::CLOSE))
            .await
            .unwrap();

        let mut got = [0u8; 4];
        let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut got))
            .await
            .expect("a close frame must not leave the reader waiting")
            .unwrap();
        assert_eq!(read, 0);
    }

    /// A ping is answered without the payload reaching the reader.
    ///
    /// frp's peers never send one — neither x/net's server nor its client pings
    /// on its own — but a middlebox that does would otherwise stall the stream.
    #[tokio::test]
    async fn a_ping_is_answered_and_not_delivered() {
        let (peer, us) = tokio::io::duplex(4096);
        let mut conn = WebSocket::new(us);
        let mut peer = peer;

        let pong = tokio::spawn(async move {
            peer.write_all(&server_frame(b"are you there", opcode::PING))
                .await
                .unwrap();
            // A data frame after the ping, which must still arrive intact.
            peer.write_all(&server_frame(b"hello", opcode::BINARY))
                .await
                .unwrap();
            // The answer comes back as a masked pong with the same payload.
            let (opcode, payload) = read_client_frame(&mut peer).await;
            assert_eq!(opcode, opcode::PONG);
            payload
        });

        // The ping is swallowed and answered; the frame after it is delivered.
        let mut got = [0u8; 5];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");

        assert_eq!(pong.await.unwrap(), b"are you there");
    }

    use std::time::Duration;
}
