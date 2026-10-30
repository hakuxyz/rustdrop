//! Wire protocol: framing, handshake and control messages.
//!
//! The transport is a plain TCP stream organised into length-prefixed frames:
//!
//! ```text
//! +------------+----------------------+
//! | u32 length | payload (<= 4 MiB)   |
//! +------------+----------------------+
//! ```
//!
//! There are two families of payloads:
//!
//! * **Handshake frames** (`Hello`, `HelloAck`) travel in the clear – they
//!   carry public keys and must be verifiable before any secret exists.
//! * **Sealed frames** – everything else (manifest, chunks, acks) is the
//!   output of an [`AeadChannel`](crate::crypto::AeadChannel).
//!
//! The hot data path avoids serde entirely: chunk frames are hand-packed into a
//! fixed 13-byte header followed by raw bytes, so a 64 KiB chunk costs 13 bytes
//! of framing plus a 16 byte Poly1305 tag.

use std::io::ErrorKind;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, RustDropError};

/// Absolute upper bound for a single frame payload.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Tag byte for a data chunk frame.
pub const TAG_CHUNK: u8 = 0x01;
/// Tag byte for the per-file end marker (carries the BLAKE3 digest).
pub const TAG_FILE_END: u8 = 0x02;
/// Tag byte for the end-of-transfer marker.
pub const TAG_DONE: u8 = 0x03;

/// Chunk payload is raw deflate compressed (only set when it saved space).
pub const FLAG_COMPRESSED: u8 = 0x01;

/// `Hello`/`HelloAck` flag: the peer understands passphrase mixing.
pub const HS_FLAG_PASSPHRASE: u16 = 1 << 0;
/// `Hello`/`HelloAck` flag: the peer supports compressed chunk frames.
pub const HS_FLAG_COMPRESS: u16 = 1 << 1;
/// `Hello`/`HelloAck` flag: the peer supports mtime preservation.
pub const HS_FLAG_MTIME: u16 = 1 << 2;

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Write one length-prefixed frame.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_FRAME {
        return Err(RustDropError::Protocol(format!(
            "frame of {} bytes exceeds the {} byte limit",
            payload.len(),
            MAX_FRAME
        )));
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame.
///
/// Returns `Ok(None)` on a clean EOF *at a frame boundary*, which lets the
/// receiver distinguish "peer hung up politely" from "stream truncated".
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(reader, &mut len_buf).await? {
        return Ok(None);
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(RustDropError::Protocol(format!(
            "peer announced a {len} byte frame, over the {MAX_FRAME} byte limit"
        )));
    }

    let mut payload = vec![0u8; len];
    if !read_exact_or_eof(reader, &mut payload).await? {
        return Err(RustDropError::Disconnected);
    }
    Ok(Some(payload))
}

/// `read_exact` that treats a clean EOF before the *first* byte as success.
async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> Result<bool>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(false)
            } else {
                Err(RustDropError::Protocol(format!(
                    "stream truncated after {filled}/{} bytes",
                    buf.len()
                )))
            };
        }
        filled += n;
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Handshake messages (plaintext)
// ---------------------------------------------------------------------------

/// First frame, sent by the initiator (`send`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u8,
    pub sender_name: String,
    pub public_key: [u8; 32],
    /// Bit 0: sender offers a passphrase-authenticated session.
    pub flags: u16,
}

/// Response frame, sent by the listener (`receive`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub version: u8,
    pub receiver_name: String,
    pub public_key: [u8; 32],
    pub accepted: bool,
    pub reason: Option<String>,
    /// Echoed feature flags (what this side also supports).
    pub flags: u16,
}

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| RustDropError::Protocol(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| RustDropError::Handshake(e.to_string()))
    }
}

impl HelloAck {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| RustDropError::Protocol(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| RustDropError::Handshake(e.to_string()))
    }
}

/// Check that the peer speaks a protocol version we understand.
pub fn check_version(peer: u8) -> Result<()> {
    if peer != crate::crypto::PROTOCOL_VERSION {
        return Err(RustDropError::VersionMismatch {
            local: crate::crypto::PROTOCOL_VERSION,
            peer,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Control messages (sealed inside AEAD frames)
// ---------------------------------------------------------------------------

/// One file as it appears in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    /// Forward-slash relative path, sanitized by the receiver on arrival.
    pub path: String,
    pub size: u64,
    /// Unix permission bits (`0` on platforms without them).
    pub mode: u32,
    /// Modification time as nanoseconds since the Unix epoch (`0` = unknown).
    pub mtime: u64,
}

/// Encrypted inventory of everything the sender is about to stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub files: Vec<FileEntry>,
    pub total_bytes: u64,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| RustDropError::Protocol(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| RustDropError::Protocol(e.to_string()))
    }
}

/// Control frames sent by the receiver (sealed with the ack key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ack {
    /// Manifest validated, receiver is ready for bytes.
    ///
    /// `resume[i]` is how many plaintext bytes of file `i` the receiver
    /// already holds in its `.rustdrop-part` file (all zeros without
    /// `--resume`). The sender may skip those bytes; BLAKE3 verification
    /// still covers the whole file because both sides hash from offset 0.
    Ready {
        files: usize,
        bytes: u64,
        resume: Vec<u64>,
    },
    /// Transfer finished successfully.
    Complete { files: usize, bytes: u64 },
    /// Something went wrong; the sender aborts with `RustDropError::Rejected`.
    Abort { reason: String },

    /// Protocol v2, sent by the *sender* between `Ready` and the stream:
    /// one BLAKE3 digest per requested resume offset, covering exactly the
    /// first `resume[i]` bytes of file `i`. `None` means "no proof" and the
    /// receiver must treat the offset as zero. Lets a receiver detect
    /// leftovers whose contents no longer match the source.
    ResumeProof { hashes: Vec<Option<[u8; 32]>> },

    /// Protocol v2, sent by the *receiver* after verifying the proof: the
    /// final resume offsets the sender must stream from.
    ResumeAccepted { resume: Vec<u64> },
}

impl Ack {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| RustDropError::Protocol(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| RustDropError::Protocol(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Data frames (hand-packed, zero-copy decode)
// ---------------------------------------------------------------------------

/// Borrowed view over a decrypted data frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataFrame<'a> {
    /// Next slice of file `file_index`, starting at `offset`.
    Chunk {
        file_index: u32,
        offset: u64,
        flags: u8,
        data: &'a [u8],
    },
    /// File finished; `hash` is the sender's BLAKE3 digest of the whole file.
    FileEnd { file_index: u32, hash: [u8; 32] },
    /// All files finished; the receiver may finalise and ack.
    Done,
}

impl<'a> DataFrame<'a> {
    /// Serialize into `buf` (which is cleared first).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.clear();
        match self {
            DataFrame::Chunk {
                file_index,
                offset,
                flags,
                data,
            } => {
                buf.reserve(14 + data.len());
                buf.push(TAG_CHUNK);
                buf.push(*flags);
                buf.extend_from_slice(&file_index.to_be_bytes());
                buf.extend_from_slice(&offset.to_be_bytes());
                buf.extend_from_slice(data);
            }
            DataFrame::FileEnd { file_index, hash } => {
                buf.reserve(33);
                buf.push(TAG_FILE_END);
                buf.extend_from_slice(&file_index.to_be_bytes());
                buf.extend_from_slice(hash);
            }
            DataFrame::Done => buf.push(TAG_DONE),
        }
    }

    /// Parse a decrypted frame payload.
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let (tag, rest) = payload
            .split_first()
            .ok_or_else(|| RustDropError::Protocol("empty data frame".into()))?;

        match *tag {
            TAG_CHUNK => {
                if rest.len() < 13 {
                    return Err(RustDropError::Protocol("short chunk header".into()));
                }
                let flags = rest[0];
                let file_index = u32::from_be_bytes(rest[1..5].try_into().expect("4 bytes"));
                let offset = u64::from_be_bytes(rest[5..13].try_into().expect("8 bytes"));
                Ok(DataFrame::Chunk {
                    file_index,
                    offset,
                    flags,
                    data: &rest[13..],
                })
            }
            TAG_FILE_END => {
                if rest.len() < 36 {
                    return Err(RustDropError::Protocol("short file-end header".into()));
                }
                let file_index = u32::from_be_bytes(rest[0..4].try_into().expect("4 bytes"));
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&rest[4..36]);
                Ok(DataFrame::FileEnd { file_index, hash })
            }
            TAG_DONE => Ok(DataFrame::Done),
            other => Err(RustDropError::Protocol(format!(
                "unknown tag 0x{other:02x}"
            ))),
        }
    }
}

/// Map an `io::ErrorKind::UnexpectedEof` from the handshake reader onto our
/// `Disconnected` variant so error output stays uniform.
pub fn map_eof(e: std::io::Error) -> RustDropError {
    if e.kind() == ErrorKind::UnexpectedEof {
        RustDropError::Disconnected
    } else {
        RustDropError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"payload").await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame.as_deref(), Some(b"payload".as_slice()));
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clean_eof_yields_none() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_stream_errors() {
        // Announces 8 bytes but only delivers 3.
        let mut raw = 8u32.to_be_bytes().to_vec();
        raw.extend_from_slice(b"abc");
        let mut cursor = std::io::Cursor::new(raw);
        assert!(matches!(
            read_frame(&mut cursor).await,
            Err(RustDropError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn oversize_frame_is_rejected() {
        let mut raw = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        raw.extend_from_slice(&[0u8; 4]);
        let mut cursor = std::io::Cursor::new(raw);
        assert!(read_frame(&mut cursor).await.is_err());
    }

    #[test]
    fn handshake_serialization_roundtrip() {
        let hello = Hello {
            version: 1,
            sender_name: "alice".into(),
            public_key: [42u8; 32],
            flags: 1,
        };
        let bytes = hello.encode().unwrap();
        let back = Hello::decode(&bytes).unwrap();
        assert_eq!(back.sender_name, "alice");
        assert_eq!(back.public_key, [42u8; 32]);
    }

    #[test]
    fn data_frame_roundtrip_chunk() {
        let payload = vec![9u8; 300];
        let frame = DataFrame::Chunk {
            file_index: 3,
            offset: 1 << 40,
            flags: FLAG_COMPRESSED,
            data: &payload,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(buf.len(), 14 + 300);

        match DataFrame::decode(&buf).unwrap() {
            DataFrame::Chunk {
                file_index,
                offset,
                flags,
                data,
            } => {
                assert_eq!(file_index, 3);
                assert_eq!(offset, 1 << 40);
                assert_eq!(flags, FLAG_COMPRESSED);
                assert_eq!(data, payload.as_slice());
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn data_frame_roundtrip_end_markers() {
        let hash = [7u8; 32];
        let mut buf = Vec::new();

        DataFrame::FileEnd {
            file_index: 1,
            hash,
        }
        .encode(&mut buf);
        assert_eq!(
            DataFrame::decode(&buf).unwrap(),
            DataFrame::FileEnd {
                file_index: 1,
                hash
            }
        );

        DataFrame::Done.encode(&mut buf);
        assert_eq!(DataFrame::decode(&buf).unwrap(), DataFrame::Done);
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert!(DataFrame::decode(&[]).is_err());
        assert!(DataFrame::decode(&[TAG_CHUNK, 1, 2]).is_err());
        assert!(DataFrame::decode(&[TAG_FILE_END, 1]).is_err());
        assert!(DataFrame::decode(&[0xEE]).is_err());
    }

    #[test]
    fn version_check() {
        assert!(check_version(crate::crypto::PROTOCOL_VERSION).is_ok());
        assert!(matches!(
            check_version(99),
            Err(RustDropError::VersionMismatch { peer: 99, .. })
        ));
    }
}
