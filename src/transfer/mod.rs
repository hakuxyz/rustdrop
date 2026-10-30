//! Transfer orchestration shared by the sender and the receiver.

pub mod receiver;
pub mod sender;

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use walkdir::WalkDir;

use crate::error::{Result, RustDropError};
use crate::protocol::{FileEntry, Manifest};

/// Summary produced once a transfer finishes (or fails).
#[derive(Debug, Clone)]
pub struct TransferReport {
    /// Human readable peer identity (host or IP:port).
    pub peer: String,
    pub files: usize,
    pub bytes: u64,
    pub elapsed: Duration,
    /// Bytes the receiver already had and did not receive again (resume).
    /// Not included in `bytes`.
    pub resumed: u64,
}

impl TransferReport {
    /// Aggregate throughput in megabits per second.
    pub fn mbps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        (self.bytes as f64 * 8.0) / secs / 1_000_000.0
    }
}

impl std::fmt::Display for TransferReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let resumed = if self.resumed > 0 {
            format!(", {} resumed", human_bytes(self.resumed))
        } else {
            String::new()
        };
        write!(
            f,
            "{} file(s){resumed}, {} in {} ({}/s)",
            self.files,
            human_bytes(self.bytes),
            human_duration(self.elapsed),
            human_bytes((self.bytes as f64 / self.elapsed.as_secs_f64().max(1e-9)) as u64),
        )
    }
}

/// BLAKE3 over the first `len` bytes of `path`.
///
/// Both sides hash the same prefix during a resume: the sender proves what
/// it is about to skip, the receiver verifies its `.part` leftovers against
/// that proof before a single chunk is skipped.
pub async fn hash_file_prefix(path: &Path, len: u64) -> Result<[u8; 32]> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let take = left.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..take]).await?;
        if n == 0 {
            return Err(RustDropError::Protocol(format!(
                "'{}' is shorter than the resume offset ({left} byte(s) missing)",
                path.display()
            )));
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

/// A file queued for transfer: on-disk source plus its wire metadata.
#[derive(Debug, Clone)]
pub struct LocalFile {
    pub source: PathBuf,
    pub entry: FileEntry,
}

/// Progress reporting surface.
///
/// Kept as a trait so the transfer core never depends on a concrete terminal
/// implementation: the CLI plugs in [`crate::ui::CliProgress`], tests plug in
/// [`NullProgress`].
pub trait ProgressSink: Send + Sync {
    fn status(&self, _msg: &str) {}
    fn discovered(&self, _name: &str, _addr: &str) {}
    fn connected(&self, _peer: &str) {}
    fn trust_code(&self, _code: &str) {}
    fn begin(&self, _files: usize, _bytes: u64) {}
    fn file(&self, _path: &str, _size: u64) {}
    fn advance(&self, _bytes: u64) {}
    fn file_hash(&self, _path: &str, _hash: &str) {}
    fn verify(&self, _path: &str, _ok: bool) {}
    fn finish(&self, _report: &TransferReport) {}
}

/// No-op progress sink used by tests and library consumers.
pub struct NullProgress;

impl ProgressSink for NullProgress {}

/// Raw-deflate compress a chunk, but only when it actually shrinks.
///
/// Returns the payload to transmit plus the
/// [`FLAG_COMPRESSED`](crate::protocol::FLAG_COMPRESSED) marker (0 for
/// stored/uncompressed data). Incompressible data costs nothing but a flag bit.
pub fn compress_chunk(data: &[u8]) -> (Vec<u8>, u8) {
    use std::io::Write;

    let mut out = Vec::with_capacity(data.len() / 2 + 32);
    let mut encoder = flate2::write::DeflateEncoder::new(&mut out, flate2::Compression::fast());
    if encoder.write_all(data).is_ok() && encoder.finish().is_ok() && out.len() < data.len() {
        (out, crate::protocol::FLAG_COMPRESSED)
    } else {
        (data.to_vec(), 0)
    }
}

/// Inverse of [`compress_chunk`]; fails loudly on truncated/corrupt payloads.
pub fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut out = Vec::with_capacity(data.len() * 3);
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| RustDropError::Protocol(format!("decompression failed: {e}")))?;
    Ok(out)
}

/// Simple token-bucket rate limiter for `--limit`.
pub struct RateLimiter {
    bytes_per_sec: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    pub fn new(bytes_per_sec: u64) -> Self {
        let bps = bytes_per_sec.max(1) as f64;
        Self {
            bytes_per_sec: bps,
            // Allow a small burst so small files are not pointlessly stalled.
            tokens: bps,
            last: std::time::Instant::now(),
        }
    }

    /// Consume `n` bytes, sleeping the caller until the budget allows it.
    pub async fn consume(&mut self, n: u64) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.bytes_per_sec).min(self.bytes_per_sec * 2.0);
        self.tokens -= n as f64;

        if self.tokens < 0.0 {
            let wait_secs = -self.tokens / self.bytes_per_sec;
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait_secs)).await;
            self.tokens = 0.0;
        }
    }
}

/// Build a [`Manifest`] and the list of local files to stream.
///
/// Paths are canonicalised first so that relative inputs (`.`) behave
/// predictably, then walked without following symlinks – symlinks, sockets and
/// devices are skipped rather than silently turned into regular files.
pub fn collect_files(paths: &[PathBuf]) -> Result<(Vec<LocalFile>, Manifest)> {
    collect_files_filtered(paths, &[])
}

/// Like [`collect_files`], but drops every file matching one of the `excludes`
/// glob patterns (matched against the transfer-relative path).
pub fn collect_files_filtered(
    paths: &[PathBuf],
    excludes: &[String],
) -> Result<(Vec<LocalFile>, Manifest)> {
    if paths.is_empty() {
        return Err(RustDropError::Protocol("no input paths given".into()));
    }

    let matcher = if excludes.is_empty() {
        None
    } else {
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in excludes {
            let glob = globset::Glob::new(pattern)
                .map_err(|e| RustDropError::Protocol(format!("bad --exclude '{pattern}': {e}")))?;
            builder.add(glob);
        }
        Some(
            builder
                .build()
                .map_err(|e| RustDropError::Protocol(format!("--exclude: {e}")))?,
        )
    };

    let mut files = Vec::new();

    for raw in paths {
        let source = raw.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RustDropError::NotFound(raw.display().to_string())
            } else {
                RustDropError::Io(e)
            }
        })?;

        let name = source.file_name().map(PathBuf::from).ok_or_else(|| {
            RustDropError::Protocol(format!("cannot transfer '{}': no file name", raw.display()))
        })?;

        let base = source.parent().unwrap_or(Path::new("")).to_path_buf();

        if source.is_file() {
            let entry = entry_for(&source, &name, &base)?;
            if is_excluded(&matcher, &entry.path) {
                continue;
            }
            files.push(LocalFile {
                source: source.clone(),
                entry,
            });
            continue;
        }

        for dent in WalkDir::new(&source)
            .follow_links(false)
            .sort_by_file_name()
        {
            let dent = dent.map_err(|e| RustDropError::Io(std::io::Error::other(e)))?;
            let ft = dent.file_type();
            if !ft.is_file() {
                // Directories are implied by file paths; symlinks are skipped.
                continue;
            }
            let entry = entry_for(dent.path(), &name, &base)?;
            if is_excluded(&matcher, &entry.path) {
                continue;
            }
            files.push(LocalFile {
                source: dent.path().to_path_buf(),
                entry,
            });
        }
    }

    if files.is_empty() {
        return Err(RustDropError::Protocol(
            "the given paths contain no transferable regular files".into(),
        ));
    }

    let total_bytes = files.iter().map(|f| f.entry.size).sum();
    let manifest = Manifest {
        files: files.iter().map(|f| f.entry.clone()).collect(),
        total_bytes,
    };
    Ok((files, manifest))
}

/// Returns true when `rel` matches one of the configured exclude globs.
fn is_excluded(matcher: &Option<globset::GlobSet>, rel: &str) -> bool {
    matches!(matcher, Some(m) if m.is_match(rel))
}

/// Build a [`FileEntry`] whose `path` is relative to `base`, normalised to
/// forward slashes on every platform.
fn entry_for(path: &Path, top_name: &Path, base: &Path) -> Result<FileEntry> {
    let rel = path.strip_prefix(base).unwrap_or(path);
    let mut components = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => components.push(c.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => {
                return Err(RustDropError::Protocol(format!(
                    "unexpected path component in '{}'",
                    path.display()
                )));
            }
        }
    }

    // Guarantee the top-level name survives even for odd inputs.
    if components.first().map(String::as_str) != top_name.to_str()
        && let Some(first) = components.first_mut()
        && !path.starts_with(base)
    {
        *first = top_name.to_string_lossy().into_owned();
    }

    let meta = std::fs::metadata(path).map_err(RustDropError::Io)?;
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o7777
        }
        #[cfg(not(unix))]
        {
            let _ = &meta;
            0o644
        }
    };
    // Nanosecond precision: sub-second files must round-trip exactly.
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0);

    Ok(FileEntry {
        path: components.join("/"),
        size: meta.len(),
        mode,
        mtime,
    })
}

/// Validate a path announced by a peer.
///
/// Everything that is not a chain of plain normal components (`..`, absolute
/// paths, drive prefixes) is rejected: this is the entire defence against
/// path-traversal writes.
pub fn sanitize_incoming_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        return Err(RustDropError::UnsafePath("empty path".into()));
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(RustDropError::UnsafePath(format!("'{raw}' is absolute")));
    }

    let mut clean = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            other => {
                return Err(RustDropError::UnsafePath(format!(
                    "'{raw}' contains a forbidden component ({other:?})"
                )));
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err(RustDropError::UnsafePath(format!("'{raw}' is empty")));
    }
    Ok(clean)
}

/// Format a byte count with binary units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Compact duration formatting (`1.2s`, `3m 12s`, `1h 04m`).
pub fn human_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        return format!("{}ms", d.as_millis());
    }
    if secs < 60.0 {
        return format!("{secs:.1}s");
    }
    let mins = d.as_secs() / 60;
    let rem = d.as_secs() % 60;
    if mins < 60 {
        return format!("{mins}m {rem:02}s");
    }
    format!("{}h {:02}m", mins / 60, mins % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_is_rejected() {
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "foo/../../bar",
            "a/./../../b",
            "",
        ] {
            assert!(
                sanitize_incoming_path(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn normal_paths_pass() {
        assert_eq!(
            sanitize_incoming_path("photos/2026/holiday.jpg").unwrap(),
            PathBuf::from("photos/2026/holiday.jpg")
        );
        assert_eq!(
            sanitize_incoming_path("./notes/todo.txt").unwrap(),
            PathBuf::from("notes/todo.txt")
        );
    }

    #[test]
    fn collect_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, b"hello world").unwrap();

        let (files, manifest) = collect_files(&[file]).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(manifest.files[0].path, "hello.txt");
        assert_eq!(manifest.total_bytes, 11);
    }

    #[test]
    fn collect_directory_walks_and_prefixes_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("bundle");
        std::fs::create_dir_all(root.join("nested/deep")).unwrap();
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("nested/deep/b.txt"), b"bb").unwrap();

        let (files, manifest) = collect_files(&[root]).unwrap();
        assert_eq!(files.len(), 2);
        let mut paths: Vec<_> = manifest.files.iter().map(|f| f.path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec!["bundle/a.txt", "bundle/nested/deep/b.txt"]);
        assert_eq!(manifest.total_bytes, 5);
    }

    #[test]
    fn missing_path_reports_not_found() {
        let err = collect_files(&[PathBuf::from("/definitely/not/here-42")]).unwrap_err();
        assert!(matches!(err, RustDropError::NotFound(_)));
    }

    #[test]
    fn human_format_helpers() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_duration(Duration::from_millis(250)), "250ms");
        assert_eq!(human_duration(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn compression_roundtrip_shrinks_and_flags() {
        let text = b"rustdrop rustdrop rustdrop rustdrop ".repeat(200);
        let (payload, flags) = compress_chunk(&text);
        assert_eq!(flags, crate::protocol::FLAG_COMPRESSED);
        assert!(payload.len() < text.len());
        let back = decompress_chunk(&payload).unwrap();
        assert_eq!(back, text);
    }

    #[test]
    fn compression_is_skipped_when_it_does_not_help() {
        // 64 random-ish bytes are effectively incompressible.
        let noise: Vec<u8> = (0..64u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let (payload, flags) = compress_chunk(&noise);
        assert_eq!(flags, 0);
        assert_eq!(payload, noise);
    }

    #[test]
    fn exclude_globs_filter_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("main.rs"), b"fn main(){}").unwrap();
        std::fs::write(root.join("src/lib.rs"), b"pub fn x(){}").unwrap();
        std::fs::write(root.join("target/debug/app"), b"\x7fELF").unwrap();

        let excludes = vec!["**/target/**".to_string()];
        let (files, manifest) = collect_files_filtered(&[root], &excludes).unwrap();
        let paths: Vec<_> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(files.len(), 2);
        assert!(paths.iter().all(|p| !p.contains("target")), "{paths:?}");
    }
}
