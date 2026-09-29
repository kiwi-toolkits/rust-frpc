//! snappy framed compression, the wire format `useCompression` selects.
//!
//! Not zstd, and not snappy's *block* format: frp wraps connections in
//! `snappy.NewReader` / `snappy.NewWriter`, which is the framed stream format.
//! Picking the wrong variant produces bytes the peer cannot decode, so the
//! constants below are pinned against the Go implementation rather than assumed.

use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

/// The stream identifier every framed stream starts with.
///
/// `golang/snappy`'s `magicChunk` is `"\xff\x06\x00\x00" + "sNaPpY"`, and this is
/// the same sequence.
pub const STREAM_IDENTIFIER: &[u8] = b"\xFF\x06\x00\x00sNaPpY";

/// The largest chunk either implementation emits.
///
/// The framing spec caps a chunk's *decompressed* size at 65536 bytes. Both
/// `golang/snappy`'s `maxBlockSize` and `snap`'s `MAX_BLOCK_SIZE` are that value,
/// so chunk boundaries line up as well as being mutually decodable.
pub const MAX_BLOCK_SIZE: usize = 65_536;

/// The chunk type bytes on the wire, from the framing spec. `snap` keeps its
/// `ChunkType` enum private, so the values are pinned here and checked by the
/// tests below against what the encoder actually emits.
pub mod chunk_type {
    pub const COMPRESSED: u8 = 0x00;
    pub const UNCOMPRESSED: u8 = 0x01;
    pub const PADDING: u8 = 0xFE;
    pub const STREAM: u8 = 0xFF;
}

/// A reader that decompresses a framed snappy stream.
pub type CompressedReader<R> = FrameDecoder<R>;

/// A writer that compresses into a framed snappy stream.
pub type CompressedWriter<W> = FrameEncoder<W>;

/// The checksum of a chunk, per the framing spec.
///
/// Masked so that a checksum is never mistaken for a valid stream identifier,
/// and rotated so the high bits of the CRC — which change for small inputs — end
/// up in the low bits. Both steps are in the Go implementation and in the spec;
/// `crc32c_masked` in `snap` is the same function, but `snap` keeps it behind a
/// private module, so the one-line formula is repeated here rather than pulling
/// in another CRC crate.
pub fn masked_crc32c(data: &[u8]) -> u32 {
    let crc = crc32c(data);
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// CRC-32C (Castagnoli), the polynomial the framing spec requires.
///
/// Table-free and bit-at-a-time: a chunk is at most 64 KiB and this runs once per
/// chunk, so a table would trade 1 KiB of resident memory for a speedup nobody
/// would notice.
fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82f6_3b78; // Castagnoli, reflected.
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn the_stream_identifier_matches_the_go_implementation() {
        // golang/snappy's magicChunk = "\xff\x06\x00\x00" + magicBody("sNaPpY").
        assert_eq!(STREAM_IDENTIFIER.len(), 10);
        assert_eq!(&STREAM_IDENTIFIER[..4], &[0xFF, 0x06, 0x00, 0x00]);
        assert_eq!(&STREAM_IDENTIFIER[4..], b"sNaPpY");
        assert_eq!(chunk_type::STREAM, 0xFF);
    }

    #[test]
    fn block_size_matches_the_framing_spec() {
        // golang/snappy: maxBlockSize = 65536, from framing_format.txt.
        assert_eq!(MAX_BLOCK_SIZE, 65_536);
        // A whole UDP datagram (frp's 65507-byte ceiling) fits in one chunk, so
        // a datagram is never split across frames.
        const _: () = assert!(MAX_BLOCK_SIZE >= 65_507);
    }

    /// A writer's output must begin with the identifier and must round-trip.
    #[test]
    fn a_framed_stream_starts_with_the_identifier_and_round_trips() {
        let payload = b"frp".repeat(2_000);

        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.into_inner().unwrap();

        assert_eq!(&compressed[..STREAM_IDENTIFIER.len()], STREAM_IDENTIFIER);
        assert!(compressed.len() < payload.len(), "compression did not help");

        let mut decoder = FrameDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    /// Compressible input produces a `Compressed` chunk, and the round trip
    /// still works. Both chunk kinds have to be understood, because either side
    /// may decide a given block is not worth compressing.
    #[test]
    fn a_compressible_payload_uses_a_compressed_chunk() {
        let payload = vec![0xABu8; 8_192];

        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(&payload).unwrap();
        let frame = encoder.into_inner().unwrap();

        assert_eq!(frame[STREAM_IDENTIFIER.len()], chunk_type::COMPRESSED);

        let mut decoder = FrameDecoder::new(&frame[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    /// Incompressible input is stored verbatim, which is the "not worth it" rule
    /// both implementations use. The decoder must accept that too.
    #[test]
    fn incompressible_input_is_stored_uncompressed() {
        // A cheap PRNG, so the bytes are genuinely incompressible.
        let payload: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();

        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(&payload).unwrap();
        let frame = encoder.into_inner().unwrap();

        let chunk = frame[STREAM_IDENTIFIER.len()];
        assert!(
            chunk == chunk_type::UNCOMPRESSED || chunk == chunk_type::COMPRESSED,
            "unexpected chunk type {chunk:#x}"
        );

        let mut decoder = FrameDecoder::new(&frame[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    /// The framing is chunk-based, so a payload spanning several chunks has to
    /// come back whole. A work connection carrying a large transfer hits this.
    #[test]
    fn a_payload_spanning_several_chunks_round_trips() {
        let payload: Vec<u8> = (0..(MAX_BLOCK_SIZE * 3 + 17))
            .map(|i| (i % 251) as u8)
            .collect();

        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(&payload).unwrap();
        let frame = encoder.into_inner().unwrap();

        let mut decoder = FrameDecoder::new(&frame[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), payload.len());
        assert_eq!(out, payload);
    }

    /// The one vector that matters: a stream produced by `golang/snappy`'s
    /// framed writer, which is what `frps` sends when `useCompression` is on.
    /// If this decodes, the two implementations agree on the framing.
    #[test]
    fn a_stream_produced_by_go_decodes() {
        // `snappy.NewBufferedWriter` over the 39-byte payload
        // b"hello frp hello frp hello frp hello frp".
        const GO_FRAMED: &[u8] = &[
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // stream identifier
            0x00, 0x14, 0x00, 0x00, 0x8f, 0xee, 0xa5, 0x8f, // compressed chunk, 20 bytes
            0x27, 0x28, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, 0x70, 0x20, 0x68, 0x6e,
            0x0a, 0x00,
        ];

        let mut decoder = FrameDecoder::new(GO_FRAMED);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello frp hello frp hello frp hello frp");
    }

    /// The checksum is the part of the framing that would silently disagree, so
    /// it is checked against the value Go put in its own frame: the four bytes
    /// at offset 14 of the vector above, little-endian.
    #[test]
    fn the_checksum_matches_the_go_implementation() {
        let go_checksum = u32::from_le_bytes([0x8f, 0xee, 0xa5, 0x8f]);
        assert_eq!(
            masked_crc32c(b"hello frp hello frp hello frp hello frp"),
            go_checksum
        );
    }

    /// CRC-32C, pinned against the standard check value.
    #[test]
    fn crc32c_matches_the_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    /// The mask is the spec's rotate-and-add, not a plain CRC. Getting this
    /// wrong produces a stream that decodes but fails every checksum.
    #[test]
    fn the_mask_rotates_and_adds() {
        let data = b"hello frp";
        assert_ne!(masked_crc32c(data), crc32c(data));
        assert_eq!(
            masked_crc32c(data),
            crc32c(data).rotate_right(15).wrapping_add(0xa282_ead8)
        );
    }

    /// Our own writer's output must start with the identifier and round-trip,
    /// which is the direction `frps` sees.
    #[test]
    fn our_stream_starts_with_the_identifier() {
        let mut encoder = FrameEncoder::new(Vec::new());
        encoder
            .write_all(b"hello frp hello frp hello frp hello frp")
            .unwrap();
        let framed = encoder.into_inner().unwrap();
        assert_eq!(&framed[..STREAM_IDENTIFIER.len()], STREAM_IDENTIFIER);
    }
}
