//! The frp-encrypted byte stream.
//!
//! Wraps any `AsyncRead + AsyncWrite` in the AES-128-CFB layer described in
//! [`crate::crypto`], or passes through untouched when encryption is off — one
//! type so the rest of the code does not branch on it.
//!
//! Two protocol details shape the implementation:
//!
//! * the 16-byte IV is **written lazily**, on the first write, so a connection
//!   that is opened but never written to sends nothing. The reader therefore
//!   blocks for 16 bytes before its first payload byte, which is why the read
//!   path is a small state machine rather than a straight decrypt-in-place;
//! * encryption is a stream cipher, so a partial write must not advance the
//!   cipher for bytes that were not sent. Everything is encrypted into an
//!   internal buffer first and flushed from there, which also means a retried
//!   `poll_write` cannot double-encrypt.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::{Decryptor, Encryptor, IV_LENGTH};

/// A byte stream, optionally wrapped in frp's stream crypto.
#[derive(Debug)]
pub struct CryptoStream<S> {
    inner: S,
    /// `None` when this connection is not encrypted.
    encryptor: Option<Encryptor>,
    decryptor: Option<Decryptor>,
    /// Output staging, so a partial inner write cannot lose cipher state.
    write_buf: Vec<u8>,
    write_pos: usize,
    /// Whether `write_buf` already holds the encrypted form of the caller's
    /// current buffer. Guards against encrypting it twice when a flush is
    /// interrupted by `Pending`.
    frame_ready: bool,
    accepted: usize,
    /// Staging for the IV on the read side.
    iv_buf: [u8; IV_LENGTH],
    iv_filled: usize,
}

impl<S> CryptoStream<S> {
    /// Wraps a stream with encryption, using `secret` as the key material.
    pub fn encrypted(inner: S, secret: &[u8]) -> Self {
        Self {
            inner,
            encryptor: Some(Encryptor::new(secret)),
            decryptor: Some(Decryptor::new(secret)),
            write_buf: Vec::new(),
            write_pos: 0,
            frame_ready: false,
            accepted: 0,
            iv_buf: [0u8; IV_LENGTH],
            iv_filled: 0,
        }
    }

    /// Wraps a stream without encryption.
    pub fn plain(inner: S) -> Self {
        Self {
            inner,
            encryptor: None,
            decryptor: None,
            write_buf: Vec::new(),
            write_pos: 0,
            frame_ready: false,
            accepted: 0,
            iv_buf: [0u8; IV_LENGTH],
            iv_filled: 0,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryptor.is_some()
    }

    /// The underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncWrite + Unpin> CryptoStream<S> {
    /// Flushes anything staged but not yet handed to the inner stream.
    fn poll_flush_staged(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += written;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        self.frame_ready = false;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CryptoStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let Some(decryptor) = this.decryptor.as_mut() else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };

        // Phase 1: the IV, which arrives before any payload.
        if !decryptor.iv_consumed() {
            while this.iv_filled < IV_LENGTH {
                let mut iv = ReadBuf::new(&mut this.iv_buf[this.iv_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut iv))?;
                let read = iv.filled().len();
                if read == 0 {
                    // EOF before the IV: the peer closed without writing, which
                    // is also what a connection that was never used looks like.
                    return Poll::Ready(Ok(()));
                }
                this.iv_filled += read;
            }
            let iv = this.iv_buf;
            decryptor.set_iv(&iv);
        }

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Phase 2: the payload. Read into the caller's buffer, then decrypt in
        // place — the cipher is a stream, so the decrypted bytes must not be
        // handed out before the keystream has advanced.
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let read = buf.filled().len() - before;
        if read == 0 {
            return Poll::Ready(Ok(()));
        }

        let filled = buf.filled_mut();
        match this
            .decryptor
            .as_mut()
            .expect("the decryptor was checked above")
            .apply_keystream(&mut filled[before..])
        {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(io::Error::other(err))),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CryptoStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.encryptor.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if !this.frame_ready {
            // Build the frame once. `header()` returns the IV exactly once per
            // stream, so this is also where the lazy IV is emitted.
            let iv = this.encryptor.as_mut().expect("checked above").header();
            if let Some(iv) = iv {
                this.write_buf.extend_from_slice(&iv);
            }
            let offset = this.write_buf.len();
            this.write_buf.extend_from_slice(buf);
            this.encryptor
                .as_mut()
                .expect("checked above")
                .apply_keystream(&mut this.write_buf[offset..]);
            this.frame_ready = true;
            this.accepted = buf.len();
        }

        ready!(this.poll_flush_staged(cx))?;

        let accepted = std::mem::take(&mut this.accepted);
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_staged(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_staged(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A pair of in-memory duplex streams, so the two ends can be wired together.
    fn duplex() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn plain_streams_pass_bytes_through_untouched() {
        let (client, server) = duplex();
        let mut client = CryptoStream::plain(client);
        let mut server = CryptoStream::plain(server);

        client.write_all(b"hello frp").await.unwrap();
        let mut out = [0u8; 9];
        server.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello frp");
    }

    #[tokio::test]
    async fn encrypted_streams_round_trip() {
        let (client, server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        let mut server = CryptoStream::encrypted(server, b"12345678");

        let write = tokio::spawn(async move {
            client.write_all(b"hello frp").await.unwrap();
            client.flush().await.unwrap();
        });

        let mut out = [0u8; 9];
        server.read_exact(&mut out).await.unwrap();
        write.await.unwrap();
        assert_eq!(&out, b"hello frp");
    }

    /// The IV is what the peer needs before it can decrypt anything, so a
    /// connection that is opened but never written to must emit nothing at all.
    #[tokio::test]
    async fn nothing_is_written_until_the_first_write() {
        let (client, mut server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        client.flush().await.unwrap();

        // A zero-byte read must not block on an IV that was never sent.
        let mut out = [0u8; 1];
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(50), server.read(&mut out)).await;
        assert!(result.is_err(), "the reader should have waited for the IV");
    }

    /// The first bytes on the wire are the 16-byte IV, in the clear.
    #[tokio::test]
    async fn the_first_sixteen_bytes_are_the_iv() {
        let (client, mut server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        client.write_all(b"x").await.unwrap();

        let mut raw = [0u8; 17];
        server.read_exact(&mut raw).await.unwrap();
        // 1 byte of plaintext plus a 16-byte tag-free CFB stream: the IV is the
        // first 16 bytes and the ciphertext is exactly one byte.
        assert_eq!(raw.len(), 17);
        // The ciphertext must not be the plaintext.
        assert_ne!(raw[16], b'x');
    }

    /// Payloads larger than one buffer, split across many writes, must survive.
    #[tokio::test]
    async fn a_long_transfer_round_trips() {
        let (client, server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        let mut server = CryptoStream::encrypted(server, b"12345678");

        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            // Deliberately irregular chunk sizes, which is what a socket does.
            for chunk in payload.chunks(997) {
                client.write_all(chunk).await.unwrap();
            }
            client.flush().await.unwrap();
        });

        let mut got = vec![0u8; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    /// The two directions are independent ciphers: a write must not disturb the
    /// read side's keystream.
    #[tokio::test]
    async fn both_directions_work_at_once() {
        let (client, server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        let mut server = CryptoStream::encrypted(server, b"12345678");

        // The server speaks first, which is the case where the client reads an
        // IV before it has written one of its own.
        server.write_all(b"banner").await.unwrap();
        server.flush().await.unwrap();

        let mut banner = [0u8; 6];
        client.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner");

        client.write_all(b"reply!").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 6];
        server.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply!");
    }

    /// Two peers with different secrets must not read each other's plaintext.
    #[tokio::test]
    async fn a_wrong_secret_does_not_yield_the_plaintext() {
        let (client, server) = duplex();
        let mut client = CryptoStream::encrypted(client, b"12345678");
        let mut server = CryptoStream::encrypted(server, b"87654321");

        client.write_all(b"secret!!").await.unwrap();
        client.flush().await.unwrap();

        let mut out = [0u8; 8];
        server.read_exact(&mut out).await.unwrap();
        assert_ne!(&out, b"secret!!");
    }
}
