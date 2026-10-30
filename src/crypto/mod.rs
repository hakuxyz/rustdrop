//! Authenticated encryption for the RustDrop wire protocol.
//!
//! Session setup is a classic ephemeral X25519 exchange (Curve25519 ECDH):
//!
//! ```text
//! sender                                receiver
//!   |  Hello{v, name, eph_pub}            |
//!   | -----------------------------------> |
//!   |  HelloAck{v, name, eph_pub, ok}     |
//!   | <----------------------------------- |
//!   |          shared = DH(sk, pk)        |
//! ```
//!
//! The raw shared secret is never used directly. It is fed, together with an
//! optional user passphrase, into HKDF-SHA256 to derive *independent,
//! purpose-scoped* keys:
//!
//! | key | direction | nonce prefix | purpose |
//! |-----|-----------|--------------|---------|
//! | `manifest_key` | sender -> receiver | `MANI` | file list (sealed exactly once) |
//! | `data_key` | sender -> receiver | `SD01` | file chunks |
//! | `ack_key` | receiver -> sender | `RD01` | control / ack frames |
//! | `sas_key` | – | – | short auth string shown to both humans |
//!
//! Every frame is sealed with ChaCha20-Poly1305 in a strict sequence-numbered
//! fashion: `nonce = prefix(4) || seq(64-bit BE)`. Because each key is used in
//! exactly one direction within a single ephemeral session, nonces can never
//! repeat, which is the one hard rule of stream AEADs.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::error::{Result, RustDropError};

/// Wire protocol version carried in the handshake.
pub const PROTOCOL_VERSION: u8 = 2;

/// Default plaintext chunk size (64 KiB): large enough to keep syscall and
/// AEAD-per-chunk overhead negligible, small enough for smooth progress bars.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Upper bound accepted for a user supplied chunk size.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// HKDF salt that labels (and domain-separates) all derived key material.
const HKDF_SALT: &[u8] = b"rustdrop/v1/session";

/// Additional authenticated data bound into every frame.
const FRAME_AAD: &[u8] = b"rustdrop/v1/frame";

const NONCE_MANIFEST: [u8; 4] = *b"MANI";
const NONCE_DATA: [u8; 4] = *b"SD01";
const NONCE_ACK: [u8; 4] = *b"RD01";

/// Crockford-style alphabet (no `I`, `L`, `O`, `U`) for the trust code.
const SAS_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// One-shot, ephemeral X25519 key exchange.
///
/// The secret is zeroized on drop and consumed by [`KeyExchange::finalize`],
/// which makes accidental key reuse impossible at the type level.
pub struct KeyExchange {
    secret: EphemeralSecret,
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange {
    /// Generate a fresh ephemeral keypair from the OS CSPRNG.
    pub fn new() -> Self {
        Self {
            secret: EphemeralSecret::random(),
        }
    }

    /// Our Curve25519 public key, safe to transmit in the clear.
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Complete the exchange and return the raw shared secret.
    ///
    /// Rejects non-contributory results (all-zero shared secrets caused by
    /// low-order peer keys) – a cheap but important MITM mitigation.
    pub fn finalize(self, peer_public: &[u8; 32]) -> Result<SharedSecret> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(RustDropError::Crypto(
                "peer supplied a low-order public key (non-contributory key exchange)".into(),
            ));
        }
        Ok(shared)
    }
}

/// Purpose-scoped keys derived for a single transfer session.
pub struct SessionKeys {
    /// Seals the file manifest (sender -> receiver, single use).
    pub manifest_key: [u8; 32],
    /// Seals data frames (sender -> receiver).
    pub data_key: [u8; 32],
    /// Seals control/ack frames (receiver -> sender).
    pub ack_key: [u8; 32],
    /// Human-comparable trust code, identical on both peers.
    pub trust_code: String,
}

impl SessionKeys {
    /// Derive every session key from the ECDH output.
    ///
    /// When `passphrase` is set its SHA-256 is mixed into the HKDF input, so a
    /// passive *or* active attacker without the passphrase ends up with a
    /// different trust code on each side and the mismatch is visible to humans.
    pub fn derive(shared: &SharedSecret, passphrase: Option<&str>) -> Result<Self> {
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(shared.as_bytes());
        if let Some(pass) = passphrase {
            ikm.extend_from_slice(&Sha256::digest(pass.as_bytes()));
        }

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);

        let mut manifest_key = [0u8; 32];
        let mut data_key = [0u8; 32];
        let mut ack_key = [0u8; 32];
        let mut sas_key = [0u8; 32];

        hk.expand(b"manifest", &mut manifest_key)
            .map_err(|e| RustDropError::Crypto(format!("hkdf expand failed: {e}")))?;
        hk.expand(b"data", &mut data_key)
            .map_err(|e| RustDropError::Crypto(format!("hkdf expand failed: {e}")))?;
        hk.expand(b"ack", &mut ack_key)
            .map_err(|e| RustDropError::Crypto(format!("hkdf expand failed: {e}")))?;
        hk.expand(b"sas", &mut sas_key)
            .map_err(|e| RustDropError::Crypto(format!("hkdf expand failed: {e}")))?;

        let trust_code = trust_code(&sas_key, shared.as_bytes());

        Ok(Self {
            manifest_key,
            data_key,
            ack_key,
            trust_code,
        })
    }

    /// Channel used by the sender for file data.
    pub fn data_channel(&self) -> AeadChannel {
        AeadChannel::new(&self.data_key, NONCE_DATA)
    }

    /// Channel used by the receiver for acknowledgements.
    pub fn ack_channel(&self) -> AeadChannel {
        AeadChannel::new(&self.ack_key, NONCE_ACK)
    }

    /// Channel used to seal the manifest exactly once.
    pub fn manifest_channel(&self) -> AeadChannel {
        AeadChannel::new(&self.manifest_key, NONCE_MANIFEST)
    }
}

/// Sequence-numbered ChaCha20-Poly1305 channel.
///
/// Each channel owns one key, one nonce prefix and a monotonic counter, so a
/// (key, nonce) pair is used at most once by construction.
pub struct AeadChannel {
    cipher: ChaCha20Poly1305,
    prefix: [u8; 4],
    seq: u64,
}

impl AeadChannel {
    pub fn new(key: &[u8; 32], prefix: [u8; 4]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(*key)),
            prefix,
            seq: 0,
        }
    }

    fn current_nonce(&self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&self.prefix);
        bytes[4..].copy_from_slice(&self.seq.to_be_bytes());
        Nonce::from(bytes)
    }

    fn advance(&mut self) -> Result<()> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| RustDropError::Crypto("sequence number exhausted".into()))?;
        Ok(())
    }

    /// Encrypt `plaintext`, returning ciphertext with an appended Poly1305 tag.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.current_nonce();
        let out = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: FRAME_AAD,
                },
            )
            .map_err(|_| RustDropError::Crypto("encryption failed".into()))?;
        self.advance()?;
        Ok(out)
    }

    /// Decrypt and authenticate `ciphertext`.
    ///
    /// The counter only advances on success, so a forged or replayed frame can
    /// never desynchronise the stream silently.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.current_nonce();
        let out = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: FRAME_AAD,
                },
            )
            .map_err(|_| RustDropError::Decryption)?;
        self.advance()?;
        Ok(out)
    }

    /// Current sequence number (useful for diagnostics and tests).
    pub fn position(&self) -> u64 {
        self.seq
    }
}

/// Derive the short authentication string shown on both terminals.
///
/// Produces eight base32 characters (40 bits of entropy) split as `XXXX-XXXX`.
/// Both peers display it; a human compares the two strings out of band.
pub fn trust_code(sas_key: &[u8; 32], shared: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rustdrop/v1/trust-code");
    hasher.update(sas_key);
    hasher.update(shared);
    let digest = hasher.finalize();

    // 5 bytes = 40 bits -> exactly 8 base32 symbols.
    let bits = &digest[..5];
    let mut out = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            out.push('-');
        }
        let symbol = read_bits(bits, i * 5);
        out.push(SAS_ALPHABET[symbol as usize] as char);
    }
    out
}

/// Read `count` bits (big-endian) starting at `start` from `data`.
fn read_bits(data: &[u8], start: usize) -> u8 {
    let mut acc: u16 = 0;
    for bit in 0..5 {
        let idx = (start + bit) / 8;
        let shift = 7 - ((start + bit) % 8);
        let value = data.get(idx).map(|b| (b >> shift) & 1).unwrap_or(0);
        acc = (acc << 1) | u16::from(value);
    }
    acc as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_produces_matching_shared_secrets() {
        let a = KeyExchange::new();
        let b = KeyExchange::new();
        let a_pub = a.public();
        let b_pub = b.public();

        let shared_a = a.finalize(&b_pub).unwrap();
        let shared_b = b.finalize(&a_pub).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn key_derivation_is_deterministic_and_direction_separated() {
        let a = KeyExchange::new();
        let b = KeyExchange::new();
        let a_pub = a.public();
        let b_pub = b.public();
        let shared_a = a.finalize(&b_pub).unwrap();
        let shared_b = b.finalize(&a_pub).unwrap();

        let ka = SessionKeys::derive(&shared_a, None).unwrap();
        let kb = SessionKeys::derive(&shared_b, None).unwrap();

        assert_eq!(ka.data_key, kb.data_key);
        assert_eq!(ka.ack_key, kb.ack_key);
        assert_eq!(ka.trust_code, kb.trust_code);
        assert_ne!(ka.data_key, ka.ack_key);
        assert_ne!(ka.manifest_key, ka.data_key);
    }

    #[test]
    fn passphrase_changes_every_derived_key() {
        let a = KeyExchange::new();
        let b = KeyExchange::new();
        let shared_a = a.finalize(&b.public()).unwrap();

        let with_pass = SessionKeys::derive(&shared_a, Some("hunter2")).unwrap();
        let without = SessionKeys::derive(&shared_a, None).unwrap();
        let other_pass = SessionKeys::derive(&shared_a, Some("hunter3")).unwrap();

        assert_ne!(with_pass.data_key, without.data_key);
        assert_ne!(with_pass.trust_code, other_pass.trust_code);
        assert_ne!(with_pass.trust_code, without.trust_code);
    }

    #[test]
    fn aead_roundtrip_and_tamper_detection() {
        let keys = [7u8; 32];
        let mut tx = AeadChannel::new(&keys, NONCE_DATA);
        let mut rx = AeadChannel::new(&keys, NONCE_DATA);

        let ct = tx.seal(b"hello rustdrop").unwrap();
        let pt = rx.open(&ct).unwrap();
        assert_eq!(pt, b"hello rustdrop");

        let mut tampered = ct;
        tampered[0] ^= 0xff;
        assert!(matches!(rx.open(&tampered), Err(RustDropError::Decryption)));
    }

    #[test]
    fn nonce_misalignment_fails_closed() {
        let keys = [9u8; 32];
        let mut tx = AeadChannel::new(&keys, NONCE_DATA);
        let mut rx = AeadChannel::new(&keys, NONCE_ACK);

        let ct = tx.seal(b"frame").unwrap();
        // Different prefix -> different nonce -> decryption must fail.
        assert!(rx.open(&ct).is_err());
    }

    #[test]
    fn sequence_advances_only_after_success() {
        let keys = [3u8; 32];
        let mut ch = AeadChannel::new(&keys, NONCE_ACK);
        assert_eq!(ch.position(), 0);
        ch.seal(b"a").unwrap();
        assert_eq!(ch.position(), 1);
        assert!(ch.open(b"not ciphertext").is_err());
        assert_eq!(ch.position(), 1);
    }

    #[test]
    fn trust_codes_match_and_look_right() {
        let a = KeyExchange::new();
        let b = KeyExchange::new();
        let a_pub = a.public();
        let b_pub = b.public();
        let shared_a = a.finalize(&b_pub).unwrap();
        let shared_b = b.finalize(&a_pub).unwrap();

        let ca = SessionKeys::derive(&shared_a, None).unwrap();
        let cb = SessionKeys::derive(&shared_b, None).unwrap();

        assert_eq!(ca.trust_code, cb.trust_code);
        assert_eq!(ca.trust_code.len(), 9);
        assert_eq!(&ca.trust_code[4..5], "-");
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        // The all-zero public key is a known low-order Curve25519 point.
        let kx = KeyExchange::new();
        assert!(kx.finalize(&[0u8; 32]).is_err());
    }
}
