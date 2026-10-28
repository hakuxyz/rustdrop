//! Receiver side: listen, accept, decrypt, verify, write.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::crypto::{AeadChannel, KeyExchange, PROTOCOL_VERSION, SessionKeys};
use crate::error::{Result, RustDropError};
use crate::protocol::{
    Ack, DataFrame, FileEntry, HS_FLAG_COMPRESS, HS_FLAG_MTIME, HS_FLAG_PASSPHRASE, Hello,
    HelloAck, Manifest, check_version, read_frame, write_frame,
};
use crate::transfer::{
    ProgressSink, TransferReport, decompress_chunk, human_bytes, sanitize_incoming_path,
};

/// What the receiver does when a sender shows up.
///
/// `confirm` runs after the manifest is known and *before* any byte is
/// accepted – it receives the peer name and a [`TransferPreview`] so the CLI
/// can render a proper interactive prompt.
pub type ConfirmFn = Arc<dyn Fn(&str, &TransferPreview) -> bool + Send + Sync>;

#[derive(Debug, Clone)]
pub struct TransferPreview {
    pub files: usize,
    pub bytes: u64,
    pub first_paths: Vec<String>,
}

#[derive(Clone)]
pub struct ReceiveRequest {
    pub out_dir: PathBuf,
    pub passphrase: Option<String>,
    /// When set, the transfer is only accepted if the derived trust code
    /// equals this value.
    pub trust_code: Option<String>,
    pub confirm: Option<ConfirmFn>,
    /// Keep listening for further senders after a transfer finishes.
    pub keep_open: bool,
    /// Refuse (rather than overwrite) destinations that already exist.
    pub no_clobber: bool,
    /// Restore mtime/permissions on written files.
    pub preserve_attrs: bool,
    /// How long to wait for a sender before giving up.
    ///
    /// Applied to the first accept in single-shot mode and to *every* accept
    /// in `keep_open` mode (i.e. it doubles as an idle timeout).
    /// `None` means wait forever (`--timeout 0`).
    pub wait_timeout: Option<Duration>,
    pub handshake_timeout: Duration,
    pub receiver_name: String,
}

impl Default for ReceiveRequest {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("."),
            passphrase: None,
            trust_code: None,
            confirm: None,
            keep_open: false,
            no_clobber: false,
            preserve_attrs: true,
            wait_timeout: Some(Duration::from_secs(600)),
            handshake_timeout: Duration::from_secs(30),
            receiver_name: crate::transfer::sender::default_device_name(),
        }
    }
}

/// A bound listener ready to accept senders.
pub struct Receiver {
    listener: TcpListener,
}

impl Receiver {
    /// Bind to `addr` (port `0` picks an ephemeral port, see [`Self::local_addr`]).
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept senders until interrupted.
    ///
    /// Returns one [`TransferReport`] per completed transfer. In single-shot
    /// mode (`keep_open == false`) exactly one report is produced or an error
    /// is returned.
    pub async fn run(
        &self,
        req: ReceiveRequest,
        progress: &dyn ProgressSink,
    ) -> Result<Vec<TransferReport>> {
        let mut reports = Vec::new();

        loop {
            let port = self.local_addr()?.port();
            let msg = if req.keep_open {
                format!("waiting for a sender on port {port} (Ctrl-C to stop)")
            } else {
                format!("waiting for a sender on port {port}")
            };

            let incoming = match req.wait_timeout {
                None => {
                    progress.status(&msg);
                    self.listener.accept().await?
                }
                Some(limit) => {
                    progress.status(&msg);
                    timeout(limit, self.listener.accept()).await.map_err(|_| {
                        RustDropError::Timeout(format!(
                            "no sender connected within {}s",
                            limit.as_secs()
                        ))
                    })??
                }
            };

            match self.handle(incoming, &req, progress).await {
                Ok(report) => reports.push(report),
                Err(err) => {
                    if req.keep_open && is_benign_disconnect(&err) {
                        progress.status(&format!("sender went away: {err}"));
                        continue;
                    }
                    return Err(err);
                }
            }

            if !req.keep_open {
                return Ok(reports);
            }
        }
    }

    /// Run one full session on an already accepted connection.
    async fn handle(
        &self,
        (mut stream, addr): (TcpStream, SocketAddr),
        req: &ReceiveRequest,
        progress: &dyn ProgressSink,
    ) -> Result<TransferReport> {
        let _ = stream.set_nodelay(true);

        // ---- handshake ---------------------------------------------------
        let hello = match timeout(req.handshake_timeout, read_frame(&mut stream)).await {
            Ok(Ok(Some(bytes))) => Hello::decode(&bytes)?,
            Ok(Ok(None)) => return Err(RustDropError::Disconnected),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(RustDropError::Timeout(
                    "waiting for a sender's hello".into(),
                ));
            }
        };
        check_version(hello.version)?;

        let key_exchange = KeyExchange::new();
        let flags: u16 = HS_FLAG_MTIME
            | HS_FLAG_COMPRESS
            | if req.passphrase.is_some() {
                HS_FLAG_PASSPHRASE
            } else {
                0
            };
        let ack = HelloAck {
            version: PROTOCOL_VERSION,
            receiver_name: req.receiver_name.clone(),
            public_key: key_exchange.public(),
            accepted: true,
            reason: None,
            flags,
        };
        write_frame(&mut stream, &ack.encode()?).await?;

        let shared = key_exchange.finalize(&hello.public_key)?;
        let keys = SessionKeys::derive(&shared, req.passphrase.as_deref())?;

        let peer = format!("{} ({addr})", hello.sender_name);
        progress.connected(&peer);
        progress.trust_code(&keys.trust_code);

        let mut ack_channel = keys.ack_channel();

        // ---- manifest ----------------------------------------------------
        // The frame is pulled in *before* any policy decision so the sender is
        // never left racing against a half-closed socket: whichever way we
        // decide, it gets a well-formed Ack (Ready or Abort).
        let sealed = read_sealed(&mut stream, req.handshake_timeout).await?;

        // Trust code first: a mismatch means nothing else on this wire is
        // trustworthy, and we must not leak whether the payload parses.
        if let Some(expected) = &req.trust_code
            && !codes_equal(expected, &keys.trust_code)
        {
            let reason = format!("trust code mismatch (expected {expected})");
            send_abort(&mut stream, &mut ack_channel, &reason).await;
            return Err(RustDropError::TrustCodeMismatch {
                expected: expected.clone(),
                actual: keys.trust_code.clone(),
            });
        }

        let mut manifest_channel = keys.manifest_channel();
        let plain = match manifest_channel.open(&sealed) {
            Ok(plain) => plain,
            Err(err) => {
                send_abort(
                    &mut stream,
                    &mut ack_channel,
                    "cannot decrypt the manifest (wrong passphrase?)",
                )
                .await;
                return Err(err);
            }
        };
        let manifest = match Manifest::decode(&plain) {
            Ok(manifest) => manifest,
            Err(err) => {
                send_abort(&mut stream, &mut ack_channel, "malformed manifest").await;
                return Err(err);
            }
        };

        let preview = TransferPreview {
            files: manifest.files.len(),
            bytes: manifest.total_bytes,
            first_paths: manifest
                .files
                .iter()
                .take(3)
                .map(|f| f.path.clone())
                .collect(),
        };

        // ---- user consent + destination preflight -------------------------
        if let Some(confirm) = &req.confirm {
            let peer_name = hello.sender_name.clone();
            let preview_clone = preview.clone();
            // Blocking on purpose: an interactive prompt owns the terminal.
            let accepted = confirm(&peer_name, &preview_clone);
            if !accepted {
                let reason = "declined by user".to_string();
                send_abort(&mut stream, &mut ack_channel, &reason).await;
                return Err(RustDropError::Rejected(reason));
            }
        }

        let destinations = match resolve_destinations(&manifest.files, &req.out_dir) {
            Ok(destinations) => destinations,
            Err(err) => {
                send_abort(&mut stream, &mut ack_channel, &err.to_string()).await;
                return Err(err);
            }
        };

        if req.no_clobber {
            for (entry, dest) in manifest.files.iter().zip(destinations.iter()) {
                if dest.exists() {
                    let reason = format!(
                        "'{}' already exists; drop --no-clobber to overwrite",
                        entry.path
                    );
                    send_abort(&mut stream, &mut ack_channel, &reason).await;
                    return Err(RustDropError::Rejected(reason));
                }
            }
        }

        for dest in &destinations {
            if let Some(parent) = dest.parent()
                && let Err(err) = tokio::fs::create_dir_all(parent).await
            {
                let reason = format!("cannot create '{}': {err}", parent.display());
                send_abort(&mut stream, &mut ack_channel, &reason).await;
                return Err(RustDropError::Io(err));
            }
        }

        let ready = Ack::Ready {
            files: manifest.files.len(),
            bytes: manifest.total_bytes,
        };
        write_frame(&mut stream, &ack_channel.seal(&ready.encode()?)?).await?;

        // ---- data --------------------------------------------------------
        progress.begin(manifest.files.len(), manifest.total_bytes);
        let started = std::time::Instant::now();
        let mut data_channel = keys.data_channel();
        let mut session = WriteSession::new(destinations.clone());

        let outcome = receive_data(
            &mut stream,
            &mut data_channel,
            &manifest,
            &mut session,
            progress,
        )
        .await;

        if let Err(err) = outcome {
            session.cleanup().await;
            send_abort(
                &mut stream,
                &mut ack_channel,
                &format!("transfer failed: {err}"),
            )
            .await;
            return Err(err);
        }

        let received = session.total_written;
        session.final_flush().await?;

        let report = TransferReport {
            peer,
            files: manifest.files.len(),
            bytes: received,
            elapsed: started.elapsed(),
        };
        let complete = Ack::Complete {
            files: report.files,
            bytes: report.bytes,
        };
        write_frame(&mut stream, &ack_channel.seal(&complete.encode()?)?).await?;

        progress.finish(&report);
        Ok(report)
    }
}

/// Consume data frames until `Done`, writing and verifying as we go.
async fn receive_data(
    stream: &mut TcpStream,
    channel: &mut AeadChannel,
    manifest: &Manifest,
    session: &mut WriteSession,
    progress: &dyn ProgressSink,
) -> Result<()> {
    loop {
        let frame = read_frame(stream)
            .await?
            .ok_or(RustDropError::Disconnected)?;
        let plain = channel.open(&frame)?;

        match DataFrame::decode(&plain)? {
            DataFrame::Chunk {
                file_index,
                offset,
                flags,
                data,
            } => {
                let payload = if flags & crate::protocol::FLAG_COMPRESSED != 0 {
                    Cow::Owned(decompress_chunk(data)?)
                } else {
                    Cow::Borrowed(data)
                };
                session
                    .write_chunk(manifest, file_index, offset, &payload, progress)
                    .await?;
            }
            DataFrame::FileEnd { file_index, hash } => {
                session
                    .finish_file(manifest, file_index, &hash, progress)
                    .await?;
            }
            DataFrame::Done => {
                if session.finished_files() != manifest.files.len() {
                    return Err(RustDropError::Protocol(format!(
                        "sender declared completion after {}/{} file(s)",
                        session.finished_files(),
                        manifest.files.len()
                    )));
                }
                return Ok(());
            }
        }
    }
}

/// Tracks the file currently being written plus every temp path still open.
struct WriteSession {
    current: Option<OpenFile>,
    next_index: u32,
    finished: usize,
    tmp_paths: Vec<PathBuf>,
    destinations: Vec<PathBuf>,
    total_written: u64,
    complete: bool,
}

struct OpenFile {
    index: u32,
    entry: FileEntry,
    tmp: PathBuf,
    file: tokio::fs::File,
    hasher: blake3::Hasher,
    received: u64,
}

impl WriteSession {
    fn new(destinations: Vec<PathBuf>) -> Self {
        Self {
            current: None,
            next_index: 0,
            finished: 0,
            tmp_paths: Vec::new(),
            destinations,
            total_written: 0,
            complete: false,
        }
    }

    fn finished_files(&self) -> usize {
        self.finished
    }

    async fn write_chunk(
        &mut self,
        manifest: &Manifest,
        index: u32,
        offset: u64,
        payload: &[u8],
        progress: &dyn ProgressSink,
    ) -> Result<()> {
        self.ensure_open(manifest, index).await?;

        let open = self
            .current
            .as_mut()
            .ok_or_else(|| RustDropError::Protocol("no open file".into()))?;

        if offset != open.received {
            return Err(RustDropError::Protocol(format!(
                "'{}': out-of-order chunk at offset {offset} (expected {})",
                open.entry.path, open.received
            )));
        }

        use tokio::io::AsyncWriteExt;
        open.file.write_all(payload).await?;
        open.hasher.update(payload);
        open.received += payload.len() as u64;
        self.total_written += payload.len() as u64;
        progress.advance(payload.len() as u64);
        Ok(())
    }

    async fn finish_file(
        &mut self,
        manifest: &Manifest,
        index: u32,
        expected_hash: &[u8; 32],
        progress: &dyn ProgressSink,
    ) -> Result<()> {
        self.ensure_open(manifest, index).await?;

        let mut open = self
            .current
            .take()
            .ok_or_else(|| RustDropError::Protocol("no open file".into()))?;

        if open.received != open.entry.size {
            return Err(RustDropError::Protocol(format!(
                "'{}' ended at {} of {} bytes",
                open.entry.path,
                human_bytes(open.received),
                human_bytes(open.entry.size)
            )));
        }

        let actual = open.hasher.finalize();
        if actual.as_bytes() != expected_hash {
            let expected = hex::encode(expected_hash);
            let actual_hex = hex::encode(actual.as_bytes());
            let _ = tokio::fs::remove_file(&open.tmp).await;
            return Err(RustDropError::Integrity {
                file: open.entry.path.clone(),
                expected,
                actual: actual_hex,
            });
        }

        use tokio::io::AsyncWriteExt;
        open.file.flush().await?;
        open.file.sync_all().await?;
        drop(open.file);

        let dest = self.destinations[index as usize].clone();
        tokio::fs::rename(&open.tmp, &dest).await?;

        self.tmp_paths.retain(|p| p != &open.tmp);

        let entry = open.entry.clone();
        let digest = hex::encode(actual.as_bytes());

        // Attribute restoration is best effort: a failure must not corrupt an
        // otherwise verified transfer.
        apply_attributes(&dest, &entry, progress);

        progress.file_hash(&entry.path, &digest[..16]);
        progress.verify(&entry.path, true);
        self.finished += 1;
        Ok(())
    }

    /// Open `manifest.files[index]` if it is not the current file.
    async fn ensure_open(&mut self, manifest: &Manifest, index: u32) -> Result<()> {
        if let Some(open) = &self.current {
            if open.index == index {
                return Ok(());
            }
            return Err(RustDropError::Protocol(format!(
                "unexpected switch from file {} to {index} without an end marker",
                open.index
            )));
        }

        if index != self.next_index {
            return Err(RustDropError::Protocol(format!(
                "received file {index}, expected {}",
                self.next_index
            )));
        }

        let entry = manifest.files[index as usize].clone();
        let dest = self.destinations[index as usize].clone();
        let tmp = tmp_path(&dest);

        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::File::create(&tmp).await?;

        self.tmp_paths.push(tmp.clone());
        self.current = Some(OpenFile {
            index,
            entry,
            tmp,
            file,
            hasher: blake3::Hasher::new(),
            received: 0,
        });
        self.next_index = index + 1;
        Ok(())
    }

    /// Flush the last open file (defensive; normally everything is closed).
    async fn final_flush(&mut self) -> Result<()> {
        if let Some(open) = self.current.take() {
            let mut open = open;
            use tokio::io::AsyncWriteExt;
            open.file.flush().await?;
            drop(open.file);
            let _ = tokio::fs::remove_file(&open.tmp).await;
        }
        self.complete = true;
        Ok(())
    }

    /// Remove every temp file that has not been renamed into place.
    async fn cleanup(&mut self) {
        if let Some(open) = self.current.take() {
            drop(open.file);
            let _ = tokio::fs::remove_file(&open.tmp).await;
        }
        for tmp in std::mem::take(&mut self.tmp_paths) {
            let _ = tokio::fs::remove_file(tmp).await;
        }
    }
}

impl Drop for WriteSession {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        // Synchronous fallback so a panic path still leaves no `.part` litter.
        for tmp in self.tmp_paths.drain(..) {
            let _ = std::fs::remove_file(tmp);
        }
        if let Some(open) = self.current.take() {
            let _ = std::fs::remove_file(&open.tmp);
        }
    }
}

/// `dest` + `.rustdrop-part` – sibling of the final path so rename is atomic.
fn tmp_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".rustdrop-part");
    PathBuf::from(name)
}

/// Map manifest entries onto safe absolute destinations under `out_dir`.
fn resolve_destinations(entries: &[FileEntry], out_dir: &Path) -> Result<Vec<PathBuf>> {
    entries
        .iter()
        .map(|entry| {
            let rel = sanitize_incoming_path(&entry.path)?;
            Ok(out_dir.join(rel))
        })
        .collect()
}

/// Restore mode + mtime; never fails the transfer on its own.
fn apply_attributes(dest: &Path, entry: &FileEntry, progress: &dyn ProgressSink) {
    #[cfg(unix)]
    if entry.mode != 0 {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(entry.mode));
    }

    if entry.mtime != 0 {
        let ftime = filetime::FileTime::from_unix_time(
            (entry.mtime / 1_000_000_000) as i64,
            (entry.mtime % 1_000_000_000) as u32,
        );
        if let Err(e) = filetime::set_file_mtime(dest, ftime) {
            progress.status(&format!(
                "warning: could not restore mtime of {}: {e}",
                entry.path
            ));
        }
    }
}

async fn send_abort(stream: &mut TcpStream, channel: &mut AeadChannel, reason: &str) {
    let abort = Ack::Abort {
        reason: reason.to_string(),
    };
    if let Ok(encoded) = abort.encode()
        && let Ok(sealed) = channel.seal(&encoded)
    {
        let _ = write_frame(stream, &sealed).await;
    }
}

async fn read_sealed(stream: &mut TcpStream, limit: Duration) -> Result<Vec<u8>> {
    let frame = timeout(limit, read_frame(stream))
        .await
        .map_err(|_| RustDropError::Timeout("waiting for the file manifest".into()))??;
    frame.ok_or(RustDropError::Disconnected)
}

fn codes_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Disconnects that are normal in `--keep-open` mode and should not stop us.
fn is_benign_disconnect(err: &RustDropError) -> bool {
    matches!(
        err,
        RustDropError::Disconnected
            | RustDropError::Handshake(_)
            | RustDropError::Timeout(_)
            | RustDropError::Rejected(_)
            | RustDropError::TrustCodeMismatch { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmp_path_stays_a_sibling() {
        let dest = PathBuf::from("/out/dir/file.txt");
        let tmp = tmp_path(&dest);
        assert_eq!(tmp, PathBuf::from("/out/dir/file.txt.rustdrop-part"));
    }

    #[test]
    fn destinations_cannot_escape_out_dir() {
        let entries = vec![FileEntry {
            path: "../evil.txt".into(),
            size: 1,
            mode: 0o644,
            mtime: 0,
        }];
        assert!(resolve_destinations(&entries, Path::new("/out")).is_err());
    }

    #[test]
    fn destinations_join_cleanly() {
        let entries = vec![FileEntry {
            path: "a/b/c.txt".into(),
            size: 1,
            mode: 0o644,
            mtime: 0,
        }];
        let out = resolve_destinations(&entries, Path::new("/out")).unwrap();
        assert_eq!(out, vec![PathBuf::from("/out/a/b/c.txt")]);
    }

    #[test]
    fn benign_disconnect_classification() {
        assert!(is_benign_disconnect(&RustDropError::Disconnected));
        assert!(is_benign_disconnect(&RustDropError::Rejected("x".into())));
        assert!(!is_benign_disconnect(&RustDropError::Decryption));
    }
}
