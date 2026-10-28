//! Command handlers – the glue between [`crate::cli`] and the core library.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::cli::{CompletionsArgs, ListArgs, ReceiveArgs, SendArgs};
use crate::discovery::{self, Announcement, DiscoveredReceiver};
use crate::protocol::Manifest;
use crate::transfer::receiver::{ConfirmFn, ReceiveRequest, Receiver, TransferPreview};
use crate::transfer::sender::{SendRequest, default_device_name};
use crate::transfer::{LocalFile, ProgressSink, collect_files_filtered, human_bytes};
use crate::ui::CliProgress;

/// `rustdrop send`
pub async fn send(args: SendArgs, verbose: bool, quiet: bool) -> Result<()> {
    if args.dry_run {
        let (files, manifest) = collect_files_filtered(&args.paths, &args.exclude)?;
        print_dry_run(&files, &manifest);
        return Ok(());
    }

    if args.no_mdns && args.to.is_none() {
        bail!("--no-mdns requires an explicit --to ADDR");
    }

    let progress = CliProgress::new(quiet, verbose);
    let targets = resolve_targets(&args, &progress).await?;
    let limit_bps = args
        .limit
        .as_deref()
        .map(parse_rate)
        .transpose()
        .context("--limit")?;

    let request = SendRequest {
        paths: args.paths.clone(),
        targets,
        sender_name: default_device_name(),
        passphrase: args.passphrase.clone(),
        chunk_size: args.chunk_size as usize,
        trust_code: args.trust.clone(),
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(30),
        retries: args.retries,
        compress: args.compress,
        limit_bps,
        excludes: args.exclude.clone(),
    };

    let report = crate::transfer::sender::send(request, &progress).await?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "role": "sender",
                "peer": report.peer,
                "files": report.files,
                "bytes": report.bytes,
                "elapsed_secs": report.elapsed.as_secs_f64(),
                "mbps": report.mbps(),
            })
        );
    }
    Ok(())
}

/// `rustdrop receive`
pub async fn receive(args: ReceiveArgs, verbose: bool, quiet: bool) -> Result<()> {
    let progress = CliProgress::new(quiet, verbose);
    let listener = Receiver::bind(SocketAddr::new(args.listen, args.port)).await?;
    let local = listener.local_addr()?;

    // Keep the announcement alive for as long as the listener runs.
    let _announcement = if args.no_mdns {
        None
    } else {
        match Announcement::start(&default_device_name(), local.port(), &default_device_name()) {
            Ok(announcement) => {
                progress.status(&format!(
                    "announced as '{}' on _rustdrop._tcp",
                    announcement.instance()
                ));
                Some(announcement)
            }
            Err(err) => {
                progress.status(&format!("mDNS unavailable ({err}); share {local} manually"));
                None
            }
        }
    };

    progress.line(&format!("  listening on {local}"));

    let confirm: Option<ConfirmFn> = if args.yes {
        None
    } else {
        Some(Arc::new(|peer: &str, preview: &TransferPreview| {
            crate::ui::confirm_transfer(peer, preview)
        }))
    };

    let request = ReceiveRequest {
        out_dir: args.out.clone(),
        passphrase: args.passphrase.clone(),
        trust_code: args.trust.clone(),
        confirm,
        keep_open: args.keep_open,
        no_clobber: args.no_clobber,
        preserve_attrs: !args.no_preserve_time,
        wait_timeout: if args.timeout == 0 {
            None
        } else {
            Some(Duration::from_secs(args.timeout))
        },
        handshake_timeout: Duration::from_secs(30),
        receiver_name: default_device_name(),
    };

    let reports = listener.run(request, &progress).await?;

    if args.json {
        let entries: Vec<serde_json::Value> = reports
            .iter()
            .map(|r| {
                serde_json::json!({
                    "ok": true,
                    "role": "receiver",
                    "peer": r.peer,
                    "files": r.files,
                    "bytes": r.bytes,
                    "elapsed_secs": r.elapsed.as_secs_f64(),
                    "mbps": r.mbps(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&entries)?);
    } else if reports.len() > 1 {
        let total: u64 = reports.iter().map(|r| r.bytes).sum();
        let files: usize = reports.iter().map(|r| r.files).sum();
        progress.line(&format!(
            "  received {files} file(s), {} across {} session(s)",
            human_bytes(total),
            reports.len()
        ));
    }
    Ok(())
}

/// `rustdrop list`
pub async fn list(args: ListArgs, verbose: bool, _quiet: bool) -> Result<()> {
    let receivers =
        discovery::discover(args.name.as_deref(), Duration::from_secs(args.timeout)).await?;

    if args.json {
        let entries: Vec<serde_json::Value> = receivers.iter().map(describe_receiver).collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if receivers.is_empty() {
        eprintln!(
            "no receivers found in the last {}s — is `rustdrop receive` running?",
            args.timeout
        );
        return Ok(());
    }

    println!(
        "  {:<20} {:<16} {:<22} PROTO",
        "NAME", "INSTANCE", "ADDRESS"
    );
    for r in &receivers {
        let addr = r
            .addresses
            .first()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "  {:<20} {:<16} {:<22} v{}",
            truncate(&r.device_name, 20),
            truncate(&r.instance, 16),
            addr,
            r.version
        );
    }

    if verbose {
        println!("\n  {} receiver(s) total", receivers.len());
    }
    Ok(())
}

/// `rustdrop completions <shell>`
pub fn completions(args: CompletionsArgs) -> Result<()> {
    use clap::CommandFactory;
    let mut command = crate::cli::Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Direct `--to` wins; otherwise browse mDNS and (interactively) pick one.
async fn resolve_targets(args: &SendArgs, progress: &CliProgress) -> Result<Vec<SocketAddr>> {
    if let Some(addr) = args.to {
        return Ok(vec![addr]);
    }

    progress.status(&format!(
        "browsing for receivers (up to {}s)",
        args.discovery_timeout
    ));

    let found = discovery::discover(
        args.name.as_deref(),
        Duration::from_secs(args.discovery_timeout),
    )
    .await?;

    if found.is_empty() {
        bail!(
            "no receivers found — start `rustdrop receive` on the other machine, \
             or pass --to ip:port"
        );
    }

    for r in &found {
        let addr = r
            .addresses
            .first()
            .map(|a| a.to_string())
            .unwrap_or_default();
        progress.discovered(&r.device_name, &addr);
    }

    let chosen = crate::ui::select_receiver(&found).context("no receiver selected")?;
    if chosen.addresses.is_empty() {
        bail!(
            "receiver '{}' advertised no usable address",
            chosen.device_name
        );
    }
    Ok(chosen.addresses)
}

fn describe_receiver(r: &DiscoveredReceiver) -> serde_json::Value {
    serde_json::json!({
        "instance": r.instance,
        "name": r.device_name,
        "version": r.version,
        "addresses": r.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
    })
}

/// Render the `--dry-run` preview table.
fn print_dry_run(files: &[LocalFile], manifest: &Manifest) {
    println!("  {:<56} {:>12}", "PATH", "SIZE");
    println!("  {:<56} {:>12}", "-".repeat(56), "-".repeat(12));
    for file in files {
        println!(
            "  {:<56} {:>12}",
            truncate(&file.entry.path, 56),
            human_bytes(file.entry.size)
        );
    }
    println!(
        "\n  {} file(s), {} total (dry run — nothing was sent)",
        files.len(),
        human_bytes(manifest.total_bytes)
    );
}

/// `10M`, `512k`, `1.5M`, `1048576` -> bytes per second.
fn parse_rate(input: &str) -> Result<u64> {
    let trimmed = input.trim().to_uppercase().replace('_', "");
    if trimmed.is_empty() {
        bail!("empty rate");
    }
    let text = trimmed.as_str();

    const K: u64 = 1024;
    const M: u64 = 1024 * 1024;
    const G: u64 = 1024 * 1024 * 1024;

    let (number, multiplier): (&str, u64) = if let Some(v) = text
        .strip_suffix("GIB")
        .or_else(|| text.strip_suffix("GB"))
        .or_else(|| text.strip_suffix('G'))
    {
        (v, G)
    } else if let Some(v) = text
        .strip_suffix("MIB")
        .or_else(|| text.strip_suffix("MB"))
        .or_else(|| text.strip_suffix('M'))
    {
        (v, M)
    } else if let Some(v) = text
        .strip_suffix("KIB")
        .or_else(|| text.strip_suffix("KB"))
        .or_else(|| text.strip_suffix('K'))
    {
        (v, K)
    } else if let Some(v) = text.strip_suffix('B') {
        (v, 1)
    } else {
        (text, 1)
    };

    let value: f64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("not a number: '{number}'"))?;
    let bps = (value * multiplier as f64).round() as u64;
    if bps == 0 {
        bail!("rate must be greater than zero");
    }
    Ok(bps)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_parsing_accepts_common_spellings() {
        assert_eq!(parse_rate("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_rate("1M").unwrap(), 1_048_576);
        assert_eq!(parse_rate("1.5M").unwrap(), 1_572_864);
        assert_eq!(parse_rate("512k").unwrap(), 524_288);
        assert_eq!(parse_rate("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_rate("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_rate("fast").is_err());
        assert!(parse_rate("0").is_err());
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        assert_eq!(truncate("übermäßig", 5).chars().count(), 5);
    }
}
