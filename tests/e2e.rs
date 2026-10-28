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
