//! Go-compatible JSON, in the two places serde needs help.
//!
//! `serde_json` is a reasonable match for Go's `encoding/json` once the maps are
//! sorted and the HTML escaping is on — [`crate::msg::go_json`] does both. Two
//! things it does not match, and both of them are wrong *silently* rather than
//! loudly, so they get their own types here:
//!
//! * **`[]byte` is base64.** Go marshals a byte slice as a base64 string, serde
//!   marshals a `Vec<u8>` as an array of numbers. A `UDPPacket` sent as `[104,
//!   105]` instead of `"aGk="` is a packet the server cannot decode, and nothing
//!   in either implementation says so.
//! * **`net.IP` is text.** Not a byte array, not base64: `encoding.TextMarshaler`
//!   wins over the `[]byte` rule for a named type that implements it, so
//!   `net.UDPAddr.IP` goes on the wire as `"192.0.2.10"`. The same type plain
//!   would be `"wAAC Cg=="` — which is what a naive port produces.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A byte slice that serializes as base64, the way Go's `[]byte` does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoBytes(pub Vec<u8>);

impl GoBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper, yielding the bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for GoBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for GoBytes {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl Serialize for GoBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for GoBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64_decode(&encoded)
            .map(Self)
            .map_err(|_| D::Error::custom("a byte field is not valid base64"))
    }
}

/// An IP address that serializes as text, the way Go's `net.IP` does.
///
/// Kept as an `Option` at the field level rather than here, because Go's
/// `omitempty` on a `net.IP` treats a nil slice as empty — so an absent IP drops
/// the whole `IP` key, and the tests pin that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoIp(pub std::net::IpAddr);

impl GoIp {
    /// Parses an address. `None` for anything that is not one, which keeps the
    /// caller from having to decide what to do about a hostname.
    pub fn parse(text: &str) -> Option<Self> {
        text.parse().ok().map(Self)
    }
}

impl Serialize for GoIp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for GoIp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse()
            .map(Self)
            .map_err(|_| D::Error::custom(format!("{text:?} is not an IP address")))
    }
}

/// Standard base64 with padding, which is Go's `base64.StdEncoding`.
pub fn base64_encode(input: &[u8]) -> String {
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

/// Why a base64 string could not be decoded.
///
/// A named type rather than `()` so the failure has somewhere to be described,
/// and so a caller cannot accidentally treat "not valid base64" as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not valid base64")]
pub struct NotBase64;

/// The inverse of [`base64_encode`]. `Err(NotBase64)` covers anything Go's
/// decoder would also reject.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, NotBase64> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;

    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        let value = ALPHABET.iter().position(|&c| c == byte).ok_or(NotBase64)? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn decoding_is_the_inverse_of_encoding() {
        for value in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"a longer payload with \x00 and \xff in it",
        ] {
            assert_eq!(base64_decode(&base64_encode(value)).unwrap(), value);
        }
    }

    #[test]
    fn a_non_base64_character_is_rejected() {
        assert!(base64_decode("!!!!").is_err());
        assert!(base64_decode("aGk=").is_ok());
    }

    #[test]
    fn bytes_round_trip_as_a_base64_string() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrapper {
            c: GoBytes,
        }
        let wrapper = Wrapper {
            c: GoBytes::new(b"hi".to_vec()),
        };
        // The exact form Go's `encoding/json` produces for a `[]byte`.
        assert_eq!(serde_json::to_string(&wrapper).unwrap(), r#"{"c":"aGk="}"#);
        assert_eq!(
            serde_json::from_str::<Wrapper>(r#"{"c":"aGk="}"#).unwrap(),
            wrapper
        );
    }

    #[test]
    fn an_ip_round_trips_as_text() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrapper {
            #[serde(rename = "IP")]
            ip: GoIp,
        }
        let wrapper = Wrapper {
            ip: GoIp("192.0.2.10".parse().unwrap()),
        };
        assert_eq!(
            serde_json::to_string(&wrapper).unwrap(),
            r#"{"IP":"192.0.2.10"}"#
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>(r#"{"IP":"192.0.2.10"}"#).unwrap(),
            wrapper
        );
    }

    #[test]
    fn an_ipv6_address_is_written_without_brackets() {
        // Go's `net.IP.String()` has no brackets; only `AddrPort`-style output
        // adds them, and this field is a bare address.
        #[derive(Serialize)]
        struct Wrapper {
            #[serde(rename = "IP")]
            ip: GoIp,
        }
        let wrapper = Wrapper {
            ip: GoIp("2001:db8::1".parse().unwrap()),
        };
        assert_eq!(
            serde_json::to_string(&wrapper).unwrap(),
            r#"{"IP":"2001:db8::1"}"#
        );
    }

    #[test]
    fn a_payload_that_is_not_an_address_is_rejected() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[allow(dead_code)]
            #[serde(rename = "IP")]
            ip: GoIp,
        }
        assert!(serde_json::from_str::<Wrapper>(r#"{"IP":"example.com"}"#).is_err());
    }
}
