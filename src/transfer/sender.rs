//! Sender side: connect, negotiate, stream.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::crypto::{DEFAULT_CHUNK_SIZE, KeyExchange, PROTOCOL_VERSION, SessionKeys};
use crate::error::{Result, RustDropError};
use crate::protocol::{
    Ack, DataFrame, HS_FLAG_COMPRESS, HS_FLAG_MTIME, HS_FLAG_PASSPHRASE, Hello, HelloAck,
    check_version, read_frame, write_frame,
};
use crate::transfer::{
    ProgressSink, RateLimiter, TransferReport, collect_files_filtered, compress_chunk, human_bytes,
};

/// Everything the sender needs to run one transfer.
pub struct SendRequest {
    pub paths: Vec<PathBuf>,
    /// Candidate endpoints (from `--to`, or resolved via mDNS).
    pub targets: Vec<SocketAddr>,
    pub sender_name: String,
    pub passphrase: Option<String>,
    /// Plaintext chunk size (clamped to [`MAX_CHUNK_SIZE`](crate::crypto::MAX_CHUNK_SIZE)).
    pub chunk_size: usize,
    /// Expected trust code; when set, a mismatch aborts before any data flows.
    pub trust_code: Option<String>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    /// Additional connect attempts after the first failure.
    pub retries: u32,
    /// Offer per-chunk deflate compression (peer may decline).
    pub compress: bool,
    /// Optional send-rate cap in bytes/second.
    pub limit_bps: Option<u64>,
    pub excludes: Vec<String>,
}

impl Default for SendRequest {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            targets: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            sender_name: default_device_name(),
            passphrase: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
            trust_code: None,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(30),
            retries: 0,
            compress: false,
            limit_bps: None,
            excludes: Vec::new(),
        }
    }
}

/// Connect, handshake, stream everything, wait for the receiver's receipt.
pub async fn send(req: SendRequest, progress: &dyn ProgressSink) -> Result<TransferReport> {
    if req.chunk_size == 0 || req.chunk_size > crate::crypto::MAX_CHUNK_SIZE {
        return Err(RustDropError::Protocol(format!(
            "chunk size must be between 1 and {} bytes",
            crate::crypto::MAX_CHUNK_SIZE
        )));
    }

    let (files, manifest) = collect_files_filtered(&req.paths, &req.excludes)?;
    progress.status(&format!(
        "preparing {} file(s) ({})",
        files.len(),
        human_bytes(manifest.total_bytes)
    ));

    let (mut stream, target) = connect(&req.targets, req.connect_timeout, req.retries).await?;
    let _ = stream.set_nodelay(true);
    progress.connected(&target.to_string());

    let (keys, peer_name) = handshake(&mut stream, &req, progress).await?;
    let data_channel_key = keys;

    // ---- manifest -------------------------------------------------------
    let mut manifest_channel = data_channel_key.manifest_channel();
    let sealed = manifest_channel.seal(&manifest.encode()?)?;
    write_frame(&mut stream, &sealed).await?;

    let mut ack_channel = data_channel_key.ack_channel();
    match wait_ack(&mut stream, &mut ack_channel, req.handshake_timeout).await? {
        Ack::Ready { .. } => {}
        Ack::Abort { reason } => return Err(RustDropError::Rejected(reason)),
        Ack::Complete { .. } => {
            return Err(RustDropError::Protocol(
                "receiver completed before any data was sent".into(),
            ));
        }
    }

    // ---- stream ---------------------------------------------------------
    progress.begin(files.len(), manifest.total_bytes);
    let started = Instant::now();
    let mut data_channel = data_channel_key.data_channel();
    let mut limiter = req.limit_bps.map(RateLimiter::new);
    let mut plaintext = vec![0u8; req.chunk_size];
    let mut frame_buf: Vec<u8> = Vec::with_capacity(req.chunk_size + 64);
    for (index, file) in files.iter().enumerate() {
        progress.file(&file.entry.path, file.entry.size);
        stream_file(
            &mut stream,
            &mut data_channel,
            &mut limiter,
            file,
            index as u32,
            req.compress,
            &mut plaintext,
            &mut frame_buf,
            progress,
        )
        .await?;
    }

    DataFrame::Done.encode(&mut frame_buf);
    let sealed = data_channel.seal(&frame_buf)?;
    write_frame(&mut stream, &sealed).await?;

    // ---- receipt --------------------------------------------------------
    match wait_ack(&mut stream, &mut ack_channel, req.handshake_timeout).await? {
        Ack::Complete { files: n, bytes } => {
            let elapsed = started.elapsed();
            let report = TransferReport {
                peer: peer_name,
                files: n,
                bytes,
                elapsed,
            };
            progress.finish(&report);
            Ok(report)
        }
        Ack::Abort { reason } => Err(RustDropError::Rejected(reason)),
        Ack::Ready { .. } => Err(RustDropError::Protocol(
            "receiver sent a second readiness ack".into(),
        )),
    }
}

/// Full handshake: version negotiation, ECDH, trust code, optional passphrase.
async fn handshake(
    stream: &mut TcpStream,
    req: &SendRequest,
    progress: &dyn ProgressSink,
) -> Result<(SessionKeys, String)> {
    let mut flags: u16 = HS_FLAG_MTIME;
    if req.passphrase.is_some() {
        flags |= HS_FLAG_PASSPHRASE;
    }
    if req.compress {
        flags |= HS_FLAG_COMPRESS;
    }

    let key_exchange = KeyExchange::new();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        sender_name: req.sender_name.clone(),
        public_key: key_exchange.public(),
        flags,
    };
    write_frame(stream, &hello.encode()?).await?;

    let ack_bytes = timeout(req.handshake_timeout, read_frame(stream))
        .await
        .map_err(|_| RustDropError::Timeout("waiting for the receiver's reply".into()))??
        .ok_or(RustDropError::Disconnected)?;
    let ack = HelloAck::decode(&ack_bytes)?;
    check_version(ack.version)?;

    if !ack.accepted {
        return Err(RustDropError::Rejected(
            ack.reason.unwrap_or_else(|| "declined".into()),
        ));
    }

    let shared = key_exchange.finalize(&ack.public_key)?;
    let keys = SessionKeys::derive(&shared, req.passphrase.as_deref())?;
    progress.trust_code(&keys.trust_code);

    if let Some(expected) = &req.trust_code
        && !trust_codes_match(expected, &keys.trust_code)
    {
        return Err(RustDropError::TrustCodeMismatch {
            expected: expected.clone(),
            actual: keys.trust_code.clone(),
        });
    }

    Ok((keys, ack.receiver_name))
}

/// Constant-time-ish comparison of trust codes (both are public values once
/// derived, but we avoid leaking a byte-index to keep habits honest).
fn trust_codes_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Read one sealed control frame and decode it as an [`Ack`].
async fn wait_ack(
    stream: &mut TcpStream,
    channel: &mut crate::crypto::AeadChannel,
    limit: Duration,
) -> Result<Ack> {
    let frame = timeout(limit, read_frame(stream))
        .await
        .map_err(|_| RustDropError::Timeout("waiting for the receiver's acknowledgement".into()))??
        .ok_or(RustDropError::Disconnected)?;
    // A frame we cannot open means our key schedule disagrees with the peer's:
    // almost always a wrong passphrase (or an interrupted/corrupted stream).
    let plain = channel.open(&frame).map_err(|_| {
        RustDropError::Handshake(
            "received a frame this session cannot decrypt (wrong passphrase?)".into(),
        )
    })?;
    Ack::decode(&plain)
}

/// Open one file, stream it as sealed chunks, return its BLAKE3 digest.
#[allow(clippy::too_many_arguments)]
async fn stream_file(
    stream: &mut TcpStream,
    channel: &mut crate::crypto::AeadChannel,
    limiter: &mut Option<RateLimiter>,
    file: &crate::transfer::LocalFile,
    index: u32,
    compress: bool,
    plaintext: &mut [u8],
    frame_buf: &mut Vec<u8>,
    progress: &dyn ProgressSink,
) -> Result<[u8; 32]> {
    let mut source = tokio::fs::File::open(&file.source).await?;

    // Catch "file changed on disk after manifest collection" early.
    let actual_size = source.metadata().await?.len();
    if actual_size != file.entry.size {
        return Err(RustDropError::Protocol(format!(
            "'{}' changed size after the manifest was built ({} -> {}); aborting",
            file.entry.path,
            human_bytes(file.entry.size),
            human_bytes(actual_size)
        )));
    }

    let mut hasher = blake3::Hasher::new();
    let mut offset: u64 = 0;

    loop {
        let n = fill(&mut source, plaintext).await?;
        if n == 0 {
            break;
        }
        hasher.update(&plaintext[..n]);

        let (payload, flags) = if compress {
            compress_chunk(&plaintext[..n])
        } else {
            (plaintext[..n].to_vec(), 0)
        };

        DataFrame::Chunk {
            file_index: index,
            offset,
            flags,
            data: &payload,
        }
        .encode(frame_buf);

        if let Some(rl) = limiter.as_mut() {
            rl.consume(n as u64).await;
        }

        let sealed = channel.seal(frame_buf)?;
        write_frame(stream, &sealed).await?;
        progress.advance(n as u64);
        offset += n as u64;
    }

    if offset != file.entry.size {
        return Err(RustDropError::Protocol(format!(
            "'{}' shrank while being read ({} -> {})",
            file.entry.path,
            human_bytes(file.entry.size),
            human_bytes(offset)
        )));
    }

    let hash = *hasher.finalize().as_bytes();
    progress.file_hash(&file.entry.path, &hex::encode(&hash[..8]));
    DataFrame::FileEnd {
        file_index: index,
        hash,
    }
    .encode(frame_buf);
    let sealed = channel.seal(frame_buf)?;
    write_frame(stream, &sealed).await?;

    Ok(hash)
}

/// Fill `buf` completely unless EOF is reached; returns bytes read.
async fn fill(file: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize> {
    use tokio::io::AsyncReadExt;
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// TCP connect across every candidate address, with backoff between rounds.
async fn connect(
    targets: &[SocketAddr],
    limit: Duration,
    retries: u32,
) -> Result<(TcpStream, SocketAddr)> {
    if targets.is_empty() {
        return Err(RustDropError::Protocol("no target address".into()));
    }

    let mut last_err = None;
    for attempt in 0..=retries {
        if attempt > 0 {
            let backoff = Duration::from_millis(200u64.saturating_mul(1 << attempt.min(4)));
            sleep(backoff).await;
        }
        for target in targets {
            match timeout(limit, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => return Ok((stream, *target)),
                Ok(Err(e)) => last_err = Some(RustDropError::Io(e)),
                Err(_) => {
                    last_err = Some(RustDropError::Timeout(format!(
                        "connecting to {target} (attempt {}/{})",
                        attempt + 1,
                        retries + 1
                    )));
                }
            }
        }
    }
    Err(last_err.unwrap_or(RustDropError::Disconnected))
}

/// Host name used in the handshake when the user did not override it.
pub fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "rustdrop-peer".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_code_comparison_handles_mismatch() {
        assert!(trust_codes_match("ABCD-EFGH", "ABCD-EFGH"));
        assert!(!trust_codes_match("ABCD-EFGH", "ABCD-EFGI"));
        assert!(!trust_codes_match("ABCD", "ABCD-EFGH"));
        assert!(!trust_codes_match("", "ABCD-EFGH"));
    }

    #[tokio::test]
    async fn connect_to_dead_port_fails_after_retries() {
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap(); // discard port, closed
        let err = connect(&[target], Duration::from_millis(300), 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RustDropError::Io(_) | RustDropError::Timeout(_)
        ));
    }

    #[tokio::test]
    async fn connect_requires_a_target() {
        let err = connect(&[], Duration::from_millis(50), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, RustDropError::Protocol(_)));
    }

    #[test]
    fn default_device_name_is_never_empty() {
        assert!(!default_device_name().is_empty());
    }
}
