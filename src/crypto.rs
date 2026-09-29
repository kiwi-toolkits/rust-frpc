//! frp's application-layer crypto.
//!
//! This is *not* TLS and it is not optional: the frp control connection is
//! always wrapped in it, whatever `transport.tls.enable` says. Both sides derive
//! the key from the auth token, so the layer is integrity-adjacent rather than
//! secret — but a client that skips it cannot talk to `frps` at all.
//!
//! The Go side lives in `github.com/fatedier/golib/crypto`. Two details there
//! bite anyone reimplementing it:
//!
//! * `golib` defaults its PBKDF2 salt to `"crypto"`, but `frp` overrides it to
//!   `"frp"` in an `init()` on both sides (`server/service.go:71`,
//!   `client/service.go:48`). [`PBKDF2_SALT`] is the overridden one.
//! * The 16-byte IV is written lazily, on the first `Write`, so a connection that
//!   is opened but never written to transmits nothing.

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// The salt frp installs into `golib`'s package-level default.
pub const PBKDF2_SALT: &str = "frp";
/// PBKDF2 iteration count used by `golib`.
pub const PBKDF2_ITERATIONS: u32 = 64;
/// The AES block size, which is also the IV length and the key length (AES-128).
pub const IV_LENGTH: usize = 16;

/// CFB with *full block* feedback, which is what Go's `cipher.NewCFBEncrypter`
/// produces. The buffered variants are the ones that can be driven in arbitrary
/// chunks without losing the feedback position, so they are what the stream
/// wrappers use; they are also byte-compatible with the plain `Encryptor` /
/// `Decryptor` for a single whole-buffer call.
type Aes128CfbEnc = cfb_mode::BufEncryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::BufDecryptor<aes::Aes128>;
/// The one-shot variants, used by [`encode`] and [`decode`].
type Aes128CfbOneShotEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbOneShotDec = cfb_mode::Decryptor<aes::Aes128>;

/// Derives the AES-128 key from an frp secret (the auth token, or a proxy's
/// `secretKey` for visitor connections).
///
/// Matches `pbkdf2.Key(key, []byte(DefaultSalt), 64, aes.BlockSize, sha1.New)`.
pub fn derive_key(secret: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(secret, PBKDF2_SALT.as_bytes(), PBKDF2_ITERATIONS, &mut key);
    key
}

/// The `hex(md5(secret ‖ decimal(timestamp)))` signature frp uses for
/// `privilege_key`, `sign_key` and the visitor `sk` check.
///
/// There is deliberately no separator between the secret and the timestamp; the
/// decimal rendering is concatenated onto the raw secret bytes.
pub fn auth_key(secret: &str, timestamp: i64) -> String {
    let mut material = Vec::with_capacity(secret.len() + 20);
    material.extend_from_slice(secret.as_bytes());
    material.extend_from_slice(timestamp.to_string().as_bytes());
    hex::encode(md5::compute(&material).0)
}

/// A one-shot `golib/crypto.Encode`: `[16-byte IV][AES-128-CFB ciphertext]`.
///
/// Used for the `NatHoleSid` datagrams the xtcp hole-punching peers exchange
/// directly over UDP.
pub fn encode(plaintext: &[u8], secret: &[u8]) -> Vec<u8> {
    let key = derive_key(secret);
    let iv = random_iv();

    let mut out = Vec::with_capacity(IV_LENGTH + plaintext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(plaintext);
    Aes128CfbOneShotEnc::new(&key.into(), &iv.into()).encrypt(&mut out[IV_LENGTH..]);
    out
}

/// The inverse of [`encode`].
pub fn decode(ciphertext: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < IV_LENGTH {
        return Err(Error::protocol("ciphertext too short"));
    }
    let key = derive_key(secret);
    let (iv, body) = ciphertext.split_at(IV_LENGTH);
    let mut out = body.to_vec();
    Aes128CfbOneShotDec::new(&key.into(), iv.into()).decrypt(&mut out);
    Ok(out)
}

/// The write half of an frp-encrypted stream.
///
/// Split into [`Encryptor::header`] and [`Encryptor::apply_keystream`] rather
/// than a single "encrypt this buffer" call, because the IV has to reach the wire
/// ahead of the first ciphertext byte and only once.
#[derive(Debug)]
pub struct Encryptor {
    cipher: Aes128CfbEnc,
    iv: [u8; IV_LENGTH],
    iv_sent: bool,
}

impl Encryptor {
    pub fn new(secret: &[u8]) -> Self {
        let key = derive_key(secret);
        let iv = random_iv();
        Self {
            cipher: Aes128CfbEnc::new(&key.into(), &iv.into()),
            iv,
            iv_sent: false,
        }
    }

    /// The IV to send before the first ciphertext, exactly once per stream.
    pub fn header(&mut self) -> Option<[u8; IV_LENGTH]> {
        if self.iv_sent {
            None
        } else {
            self.iv_sent = true;
            Some(self.iv)
        }
    }

    /// Encrypts a payload in place.
    pub fn apply_keystream(&mut self, buffer: &mut [u8]) {
        self.cipher.encrypt(buffer);
    }
}

/// The read half of an frp-encrypted stream.
#[derive(Debug)]
pub struct Decryptor {
    cipher: Option<Aes128CfbDec>,
    key: [u8; 16],
}

impl Decryptor {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            cipher: None,
            key: derive_key(secret),
        }
    }

    /// Whether the IV has been read from the stream yet.
    pub fn iv_consumed(&self) -> bool {
        self.cipher.is_some()
    }

    /// Installs the IV read from the stream. Idempotent, so a reader that
    /// re-enters this path cannot desynchronize the cipher.
    pub fn set_iv(&mut self, iv: &[u8; IV_LENGTH]) {
        if self.cipher.is_none() {
            self.cipher = Some(Aes128CfbDec::new(&self.key.into(), iv.into()));
        }
    }

    /// Decrypts a payload in place. [`Self::set_iv`] must have run first.
    pub fn apply_keystream(&mut self, buffer: &mut [u8]) -> Result<()> {
        match self.cipher.as_mut() {
            Some(cipher) => {
                cipher.decrypt(buffer);
                Ok(())
            }
            None => Err(Error::protocol("frp stream IV not read yet")),
        }
    }
}

fn random_iv() -> [u8; IV_LENGTH] {
    let mut iv = [0u8; IV_LENGTH];
    rand::Rng::fill(&mut rand::thread_rng(), &mut iv);
    iv
}

/// frp's `secretKey` wrapper, which renders as `"***"` wherever it would reach a
/// log or the admin API, matching `types.Secret` on the Go side.
///
/// The wire messages carry the real value; this only guards human-facing output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The real value. Named loudly so call sites are obvious in review.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"***\"")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if self.0.is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str("***")
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Ok(Self(String::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hex(md5(token ‖ decimal(timestamp)))`. The expected value comes from
    /// `printf '12345678'; printf '1712345678' | md5sum`, so this pins the
    /// *absence* of a separator and the decimal rendering rather than merely
    /// agreeing with itself.
    #[test]
    fn auth_key_matches_the_go_implementation() {
        assert_eq!(
            auth_key("12345678", 1_712_345_678),
            "a94f1af410cc72197577d84d0e4672af"
        );
    }

    #[test]
    fn auth_key_is_lowercase_hex() {
        // `printf 'token0' | md5sum`, i.e. "token" with timestamp 0.
        assert_eq!(auth_key("token", 0), "52589a85f668e2db5db228619436e04c");
        assert!(auth_key("token", 0)
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let ciphertext = encode(b"hello frp", b"12345678");
        assert_eq!(ciphertext.len(), IV_LENGTH + 9);
        assert_eq!(decode(&ciphertext, b"12345678").unwrap(), b"hello frp");
    }

    #[test]
    fn decode_with_the_wrong_secret_does_not_return_the_plaintext() {
        let ciphertext = encode(b"hello frp", b"12345678");
        assert_ne!(decode(&ciphertext, b"87654321").unwrap(), b"hello frp");
    }

    #[test]
    fn decode_rejects_short_input() {
        assert!(decode(&[0u8; 8], b"k").is_err());
    }

    #[test]
    fn stream_encryptor_hands_out_one_header() {
        let mut encryptor = Encryptor::new(b"12345678");
        assert!(encryptor.header().is_some());
        assert!(encryptor.header().is_none());
    }

    #[test]
    fn stream_round_trips_across_split_writes() {
        // The reader must cope with payloads that do not land on 16-byte
        // boundaries, which is what a real socket delivers.
        let mut encryptor = Encryptor::new(b"12345678");
        let iv = encryptor.header().unwrap();

        let mut first = b"hello ".to_vec();
        encryptor.apply_keystream(&mut first);
        let mut second = b"world!".to_vec();
        encryptor.apply_keystream(&mut second);

        let mut decryptor = Decryptor::new(b"12345678");
        decryptor.set_iv(&iv);
        decryptor.apply_keystream(&mut first).unwrap();
        decryptor.apply_keystream(&mut second).unwrap();
        assert_eq!(&first, b"hello ");
        assert_eq!(&second, b"world!");
    }

    #[test]
    fn decrypting_before_the_iv_arrives_is_an_error() {
        let mut decryptor = Decryptor::new(b"k");
        assert!(!decryptor.iv_consumed());
        assert!(decryptor.apply_keystream(&mut [0u8; 4]).is_err());
    }

    #[test]
    fn derived_key_is_stable_and_secret_dependent() {
        assert_eq!(derive_key(b"12345678"), derive_key(b"12345678"));
        assert_ne!(derive_key(b"12345678"), derive_key(b"12345679"));
    }

    #[test]
    fn secret_renders_as_masked() {
        let secret = Secret::new("s3cret");
        assert_eq!(format!("{secret:?}"), "\"***\"");
        assert_eq!(secret.expose(), "s3cret");
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"***\"");
    }
}
