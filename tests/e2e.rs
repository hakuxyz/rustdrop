//! End-to-end tests: a real sender talking to a real receiver over localhost.
//!
//! Discovery (mDNS) is deliberately bypassed with an explicit target address so
//! the suite runs hermetically in CI sandboxes; the discovery layer has its own
//! unit tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustdrop::transfer::NullProgress;
use rustdrop::transfer::receiver::{ReceiveRequest, Receiver};
use rustdrop::transfer::sender::{SendRequest, send};

const WAIT: Duration = Duration::from_secs(15);

fn receiver_request(out: &Path) -> ReceiveRequest {
    ReceiveRequest {
        out_dir: out.to_path_buf(),
        wait_timeout: Some(WAIT),
        handshake_timeout: Duration::from_secs(10),
        ..ReceiveRequest::default()
    }
}

fn sender_request(paths: Vec<PathBuf>, target: std::net::SocketAddr) -> SendRequest {
    SendRequest {
        paths,
        targets: vec![target],
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(10),
        retries: 1,
        ..SendRequest::default()
    }
}

async fn spawn_receiver(
    request: ReceiveRequest,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<
        std::result::Result<Vec<rustdrop::transfer::TransferReport>, rustdrop::RustDropError>,
    >,
) {
    let receiver = Receiver::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let addr = receiver.local_addr().expect("local addr");
    let handle = tokio::spawn(async move { receiver.run(request, &NullProgress).await });
    (addr, handle)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read back")
}

#[tokio::test]
async fn single_file_roundtrip_preserves_bytes() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");

    assert_eq!(report.files, 1);
    assert_eq!(report.bytes, payload.len() as u64);

    let landed = dst.path().join("payload.bin");
    assert_eq!(read(&landed), payload);

    let reports = handle.await.unwrap().expect("receive");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].bytes, payload.len() as u64);
}

#[tokio::test]
async fn directory_tree_and_metadata_survive() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let root = src.path().join("bundle");
    std::fs::create_dir_all(root.join("nested/deep")).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    std::fs::write(root.join("nested/b.txt"), b"beta-beta").unwrap();
    std::fs::write(root.join("nested/deep/c.txt"), b"gamma").unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![root.clone()], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(report.files, 3);

    assert_eq!(read(&dst.path().join("bundle/a.txt")), b"alpha");
    assert_eq!(read(&dst.path().join("bundle/nested/b.txt")), b"beta-beta");
    assert_eq!(read(&dst.path().join("bundle/nested/deep/c.txt")), b"gamma");

    handle.await.unwrap().expect("receive");

    // Modification time must be restored on the copy.
    let source_mtime = std::fs::metadata(root.join("a.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let copied_mtime = std::fs::metadata(dst.path().join("bundle/a.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(source_mtime, copied_mtime, "mtime was not preserved");

    // Source side must not have been disturbed.
    assert_eq!(read(&root.join("a.txt")), b"alpha");
}

#[tokio::test]
async fn compression_negotiation_roundtrips() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let text = "the quick brown fox jumps over the lazy dog. ".repeat(20_000);
    let source_file = src.path().join("repetitive.txt");
    std::fs::write(&source_file, &text).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let mut request = sender_request(vec![source_file], addr);
    request.compress = true;
    let report = send(request, &NullProgress).await.expect("send");

    assert_eq!(report.bytes, text.len() as u64);
    assert_eq!(
        String::from_utf8(read(&dst.path().join("repetitive.txt"))).unwrap(),
        text
    );
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn empty_files_are_created() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("empty.dat");
    std::fs::write(&source_file, b"").unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;
    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(report.bytes, 0);

    let landed = dst.path().join("empty.dat");
    assert!(landed.exists());
    assert_eq!(read(&landed), b"");
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn passphrase_mismatch_fails_loudly() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("secret.txt");
    std::fs::write(&source_file, b"classified").unwrap();

    let mut rx_req = receiver_request(dst.path());
    rx_req.passphrase = Some("right horse".into());
    let (addr, handle) = spawn_receiver(rx_req).await;

    let mut request = sender_request(vec![source_file], addr);
    request.passphrase = Some("wrong horse".into());

    let send_err = send(request, &NullProgress).await.unwrap_err();
    assert!(
        matches!(
            send_err,
            rustdrop::RustDropError::Rejected(_) | rustdrop::RustDropError::Handshake(_)
        ),
        "unexpected sender error: {send_err}"
    );

    let rx_err = handle.await.unwrap().unwrap_err();
    assert!(
        matches!(rx_err, rustdrop::RustDropError::Decryption),
        "unexpected receiver error: {rx_err}"
    );
    assert!(!dst.path().join("secret.txt").exists());
}

#[tokio::test]
async fn matching_passphrase_succeeds() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("secret.txt");
    std::fs::write(&source_file, b"classified").unwrap();

    let mut rx_req = receiver_request(dst.path());
    rx_req.passphrase = Some("correct horse battery staple".into());
    let (addr, handle) = spawn_receiver(rx_req).await;

    let mut request = sender_request(vec![source_file], addr);
    request.passphrase = Some("correct horse battery staple".into());

    send(request, &NullProgress).await.expect("send");
    assert_eq!(read(&dst.path().join("secret.txt")), b"classified");
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn trust_code_enforcement_aborts_before_data() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("file.txt");
    std::fs::write(&source_file, b"payload").unwrap();

    let mut rx_req = receiver_request(dst.path());
    rx_req.trust_code = Some("0000-0000".into());
    let (addr, handle) = spawn_receiver(rx_req).await;

    let send_err = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .unwrap_err();
    // Receiver aborts the session during the trust-code check.
    assert!(
        matches!(send_err, rustdrop::RustDropError::Rejected(_)),
        "unexpected sender error: {send_err}"
    );
    let rx_err = handle.await.unwrap().unwrap_err();
    assert!(matches!(
        rx_err,
        rustdrop::RustDropError::TrustCodeMismatch { .. }
    ));
    assert!(!dst.path().join("file.txt").exists());
}

#[tokio::test]
async fn no_clobber_refuses_to_overwrite() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("existing.txt");
    std::fs::write(&source_file, b"new content").unwrap();
    std::fs::write(dst.path().join("existing.txt"), b"original content").unwrap();

    let mut rx_req = receiver_request(dst.path());
    rx_req.no_clobber = true;
    let (addr, handle) = spawn_receiver(rx_req).await;

    let err = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .unwrap_err();
    assert!(matches!(err, rustdrop::RustDropError::Rejected(_)));

    // A refused session is a *policy* outcome for the receiver, but the
    // single-shot listener still reports it as an error to the caller.
    let rx_err = handle.await.unwrap().unwrap_err();
    assert!(matches!(rx_err, rustdrop::RustDropError::Rejected(_)));
    // Original file untouched.
    assert_eq!(read(&dst.path().join("existing.txt")), b"original content");
}

#[tokio::test]
async fn overwriting_is_allowed_by_default() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("existing.txt");
    std::fs::write(&source_file, b"new content").unwrap();
    std::fs::write(dst.path().join("existing.txt"), b"old").unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;
    send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    handle.await.unwrap().expect("receive");
    assert_eq!(read(&dst.path().join("existing.txt")), b"new content");
}

#[tokio::test]
async fn exclusion_globs_drop_files() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let root = src.path().join("tree");
    std::fs::create_dir_all(root.join("logs")).unwrap();
    std::fs::write(root.join("keep.txt"), b"keep").unwrap();
    std::fs::write(root.join("logs/drop.log"), b"drop").unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let mut request = sender_request(vec![root], addr);
    request.excludes = vec!["**/*.log".into()];
    let report = send(request, &NullProgress).await.expect("send");
    assert_eq!(report.files, 1);

    assert!(dst.path().join("tree/keep.txt").exists());
    assert!(!dst.path().join("tree/logs/drop.log").exists());
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn rate_limited_transfer_still_completes() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let source_file = src.path().join("small.bin");
    std::fs::write(&source_file, vec![7u8; 32 * 1024]).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let mut request = sender_request(vec![source_file], addr);
    request.limit_bps = Some(64 * 1024);
    send(request, &NullProgress).await.expect("send");

    assert_eq!(read(&dst.path().join("small.bin")), vec![7u8; 32 * 1024]);
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn receiver_survives_a_protocol_error_in_keep_open_mode() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    // First: a declined-by-policy transfer (trust code mismatch).
    let bad = src.path().join("bad.txt");
    std::fs::write(&bad, b"bad").unwrap();
    let mut rx_req = receiver_request(dst.path());
    rx_req.keep_open = true;
    rx_req.trust_code = Some("1111-1111".into());
    let (addr, handle) = spawn_receiver(rx_req).await;

    let err = send(sender_request(vec![bad], addr), &NullProgress)
        .await
        .unwrap_err();
    assert!(matches!(err, rustdrop::RustDropError::Rejected(_)));

    // Second: a trusted transfer cannot be accepted because the trust code is
    // pinned to a constant, so simply prove the listener is still alive by
    // connecting to it (it must accept and then fail the handshake check).
    let probe = tokio::net::TcpStream::connect(addr).await;
    assert!(
        probe.is_ok(),
        "keep-open listener should still be accepting"
    );

    // Tear the task down; drop closes the listener.
    handle.abort();
}

// ---------------------------------------------------------------------------
// binary-level smoke tests
// ---------------------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rustdrop")
}

#[test]
fn help_and_version_work() {
    let help = std::process::Command::new(bin())
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("Privacy-first"));
    assert!(text.contains("send") && text.contains("receive"));
}

#[test]
fn completions_are_generated() {
    let out = std::process::Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .expect("run completions");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("rustdrop"));
    assert!(text.contains("receive"));
}

#[test]
fn dry_run_prints_a_preview_and_touches_no_network() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let out = std::process::Command::new(bin())
        .args(["send", "--dry-run"])
        .arg(&file)
        .output()
        .expect("run dry-run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("notes.txt"));
    assert!(stdout.contains("dry run"));
}

#[test]
fn send_fails_cleanly_when_discovery_finds_nothing() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("x.txt");
    std::fs::write(&file, b"x").unwrap();

    let out = std::process::Command::new(bin())
        .args(["send", "--discovery-timeout", "1", "--quiet"])
        .arg(&file)
        .output()
        .expect("run send");
    // Either no receiver was found (exit 1) or a receiver happened to exist on
    // this LAN (exit 0); both are acceptable, but it must never panic.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[tokio::test]
async fn resume_continues_a_partial_download() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| i.wrapping_mul(7) % 251)
        .map(|i| i as u8)
        .collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    // Simulate an interrupted transfer: 123_456 bytes already on disk.
    let have = 123_456usize;
    let part = dst.path().join("payload.bin.rustdrop-part");
    std::fs::write(&part, &payload[..have]).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(
        report.bytes,
        (payload.len() - have) as u64,
        "sender must skip the prefix the receiver already holds"
    );
    assert_eq!(
        report.resumed, have as u64,
        "report must count resumed bytes"
    );

    assert_eq!(read(&dst.path().join("payload.bin")), payload);
    assert!(!part.exists(), "part file must be renamed away");
    let reports = handle.await.unwrap().expect("receive");
    assert_eq!(reports[0].bytes, (payload.len() - have) as u64);
}

#[tokio::test]
async fn resume_restarts_when_the_leftover_cannot_belong() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 249) as u8).collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    // Leftover larger than the manifest entry: must be discarded, not trusted.
    let part = dst.path().join("payload.bin.rustdrop-part");
    std::fs::write(&part, vec![0u8; payload.len() + 999]).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(report.bytes, payload.len() as u64, "full re-send expected");

    assert_eq!(read(&dst.path().join("payload.bin")), payload);
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn resume_of_a_complete_part_writes_no_bytes() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..20_000u32)
        .map(|i| (i.wrapping_mul(3) % 250) as u8)
        .collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    let part = dst.path().join("payload.bin.rustdrop-part");
    std::fs::write(&part, &payload).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(report.bytes, 0, "everything already present: rename only");

    assert_eq!(read(&dst.path().join("payload.bin")), payload);
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn session_filter_sends_only_requested_files() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let keep = src.path().join("keep.txt");
    let picked = src.path().join("picked.txt");
    std::fs::write(&keep, b"stay put").unwrap();
    std::fs::write(&picked, b"payload").unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    // Full input set, but the session is restricted to `picked.txt`.
    let mut request = sender_request(vec![keep.clone(), picked.clone()], addr);
    request.only = Some(vec![picked.canonicalize().unwrap()]);
    let report = send(request, &NullProgress).await.expect("send");

    assert_eq!(report.files, 1);
    assert_eq!(read(&dst.path().join("picked.txt")), b"payload");
    assert!(
        !dst.path().join("keep.txt").exists(),
        "files outside the filter must not cross the wire"
    );

    handle.await.unwrap().expect("receive");
}

/// A live `send --watch` child process against a keep-open receiver:
/// initial transfer, then an added file, then a modified file.
#[test]
fn watch_loop_sends_new_and_changed_files() {
    use std::time::Instant;

    struct KillChild(std::process::Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out waiting for {what}");
    }

    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("first.txt"), b"one").unwrap();

    // Multi-thread runtime: it keeps driving the receiver while this thread
    // polls the filesystem and supervises the sender child process.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (addr, rx_task) = rt.block_on(async {
        let receiver = rustdrop::transfer::receiver::Receiver::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let addr = receiver.local_addr().expect("local addr");
        let request = ReceiveRequest {
            out_dir: dst.path().to_path_buf(),
            wait_timeout: Some(Duration::from_secs(60)),
            handshake_timeout: Duration::from_secs(10),
            keep_open: true,
            ..ReceiveRequest::default()
        };
        let task = tokio::spawn(async move { receiver.run(request, &NullProgress).await });
        (addr, task)
    });

    let mut sender = KillChild(
        std::process::Command::new(bin())
            .args([
                "send",
                "--watch",
                "--interval",
                "1",
                "--to",
                &addr.to_string(),
                "--quiet",
            ])
            .arg(src.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn watch sender"),
    );

    // Entries keep their input layout: `<dst>/<src-dir-name>/<file>`.
    let landed = |name: &str| {
        dst.path()
            .join(src.path().file_name().expect("src dir name"))
            .join(name)
    };
    let get = |name: &str| -> Vec<u8> { std::fs::read(landed(name)).unwrap_or_default() };

    // 1) first poll transfers the initial snapshot.
    wait_for("initial file", Duration::from_secs(20), || {
        get("first.txt") == b"one"
    });

    // 2) a new file appears at the next poll.
    std::fs::write(src.path().join("second.txt"), b"two").unwrap();
    wait_for("added file", Duration::from_secs(20), || {
        get("second.txt") == b"two"
    });

    // 3) a changed file is re-sent (size grows, so the diff cannot miss it).
    std::fs::write(src.path().join("first.txt"), b"one plus edits").unwrap();
    wait_for("modified file", Duration::from_secs(20), || {
        get("first.txt") == b"one plus edits"
    });

    // Sender must still be running (watch mode never exits on its own).
    assert!(
        sender.0.try_wait().unwrap().is_none(),
        "watch sender exited early"
    );

    drop(sender);
    rt.block_on(async { rx_task.abort() });
}

#[tokio::test]
async fn stale_resume_prefix_is_rejected_by_the_proof() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(11) % 250) as u8)
        .collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    // Same length as a legitimate prefix, but different content: only the
    // resume proof can catch this (a size clamp cannot).
    let have = 123_456usize;
    let part = dst.path().join("payload.bin.rustdrop-part");
    std::fs::write(&part, vec![0xAB; have]).unwrap();

    let (addr, handle) = spawn_receiver(receiver_request(dst.path())).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(
        report.bytes,
        payload.len() as u64,
        "stale leftover must trigger a full re-send"
    );
    assert_eq!(report.resumed, 0);
    assert_eq!(read(&dst.path().join("payload.bin")), payload);
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn no_resume_discards_valid_leftovers() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let payload: Vec<u8> = (0..90_000u32).map(|i| (i % 247) as u8).collect();
    let source_file = src.path().join("payload.bin");
    std::fs::write(&source_file, &payload).unwrap();

    let part = dst.path().join("payload.bin.rustdrop-part");
    std::fs::write(&part, &payload[..40_000]).unwrap();

    let mut request = receiver_request(dst.path());
    request.resume = false;
    let (addr, handle) = spawn_receiver(request).await;

    let report = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect("send");
    assert_eq!(
        report.bytes,
        payload.len() as u64,
        "--no-resume must re-send everything"
    );
    assert_eq!(report.resumed, 0);
    assert_eq!(read(&dst.path().join("payload.bin")), payload);
    handle.await.unwrap().expect("receive");
}

#[tokio::test]
async fn max_file_size_rejects_before_any_byte_flows() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let source_file = src.path().join("big.bin");
    std::fs::write(&source_file, vec![1u8; 100_000]).unwrap();

    let mut request = receiver_request(dst.path());
    request.max_file_size = Some(1024);
    let (addr, handle) = spawn_receiver(request).await;

    let err = send(sender_request(vec![source_file], addr), &NullProgress)
        .await
        .expect_err("oversized file must be refused");
    let text = err.to_string();
    assert!(
        text.contains("--max-file-size") && text.contains("big.bin"),
        "clear refusal, got: {text}"
    );
    assert!(!dst.path().join("big.bin").exists());
    let rx_err = handle.await.unwrap().unwrap_err();
    assert!(
        matches!(rx_err, rustdrop::RustDropError::Rejected(_)),
        "unexpected receiver error: {rx_err}"
    );
}

#[tokio::test]
async fn max_total_size_rejects_the_session() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    let a = src.path().join("a.bin");
    let b = src.path().join("b.bin");
    std::fs::write(&a, vec![1u8; 60_000]).unwrap();
    std::fs::write(&b, vec![2u8; 60_000]).unwrap();

    let mut request = receiver_request(dst.path());
    request.max_total_size = Some(100_000);
    let (addr, handle) = spawn_receiver(request).await;

    let err = send(sender_request(vec![a, b], addr), &NullProgress)
        .await
        .expect_err("oversized session must be refused");
    let text = err.to_string();
    assert!(
        text.contains("--max-total-size"),
        "clear refusal, got: {text}"
    );
    let rx_err = handle.await.unwrap().unwrap_err();
    assert!(
        matches!(rx_err, rustdrop::RustDropError::Rejected(_)),
        "unexpected receiver error: {rx_err}"
    );
}
