//! Command line surface (definitions only – logic lives in [`crate::commands`]).

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rustdrop",
    version,
    about = "Privacy-first, blazing-fast peer-to-peer file transfer for your local network",
    long_about = "Privacy-first, blazing-fast peer-to-peer file transfer for your local network.\n\nRustDrop moves files across your LAN directly – no cloud, no account, \
no telemetry. Peers find each other with mDNS, negotiate an ephemeral X25519 key \
exchange, agree on a short trust code you can compare out of band, and stream \
ChaCha20-Poly1305 encrypted chunks with BLAKE3 end-to-end verification.\n\n\
EXAMPLES:\n  \
  rustdrop receive                      # wait for incoming files\n  \
  rustdrop send photo.jpg               # auto-discover and push\n  \
  rustdrop send --to 192.168.1.20:9000 ./build/\n  \
  rustdrop send -p 'correct horse' --trust 7GKM-2XQ4 secret.tar\n  \
  rustdrop list                         # show receivers on this network",
    arg_required_else_help = true,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Print diagnostics on stderr (repeat not needed: it is a switch)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress progress output (the trust code is still printed)
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Send files or directories to a receiver on this network
    Send(SendArgs),

    /// Accept incoming files
    Receive(ReceiveArgs),

    /// List receivers advertising themselves on the local network
    List(ListArgs),

    /// Print a shell completion script
    Completions(CompletionsArgs),

    /// Generate a pairing code (and a scannable QR) for shared -p passphrases
    Pair(PairArgs),
}

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Encode this text into the QR instead of generating a passphrase
    #[arg(long, value_name = "TEXT")]
    pub show: Option<String>,

    /// Emit a machine-readable JSON summary on stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Files and/or directories to send
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Connect straight to ADDR (skips mDNS discovery), e.g. 192.168.1.20:9000
    #[arg(short = 't', long, value_name = "ADDR")]
    pub to: Option<std::net::SocketAddr>,

    /// Ignore mDNS entirely (requires --to)
    #[arg(long)]
    pub no_mdns: bool,

    /// Only consider receivers whose name contains PATTERN
    #[arg(short = 'n', long, value_name = "PATTERN")]
    pub name: Option<String>,

    /// Shared passphrase mixed into the key exchange
    #[arg(short = 'p', long, env = "RUSTDROP_PASSPHRASE", hide_env_values = true)]
    pub passphrase: Option<String>,

    /// Abort unless the peer displays this trust code
    #[arg(long, value_name = "CODE")]
    pub trust: Option<String>,

    /// Seconds to keep browsing for receivers
    #[arg(long, default_value_t = 3, value_name = "SECS")]
    pub discovery_timeout: u64,

    /// Extra connection attempts after the first failure
    #[arg(long, default_value_t = 2)]
    pub retries: u32,

    /// Plaintext chunk size in bytes (1 ..= 1048576)
    #[arg(
        long,
        default_value_t = 65536,
        value_name = "BYTES",
        value_parser = clap::value_parser!(u64).range(1..=1_048_576)
    )]
    pub chunk_size: u64,

    /// Deflate-compress chunks when that actually shrinks them
    #[arg(long)]
    pub compress: bool,

    /// Cap the send rate, e.g. 10M, 512K or 1.5M (bytes/second)
    #[arg(long, value_name = "RATE")]
    pub limit: Option<String>,

    /// Skip files matching GLOB (repeatable), e.g. --exclude '**/*.log'
    #[arg(long = "exclude", value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Show what would be sent and exit without touching the network
    #[arg(long)]
    pub dry_run: bool,

    /// Emit a machine-readable JSON summary on stdout
    #[arg(long)]
    pub json: bool,

    /// Keep polling the inputs and re-send new or changed files
    /// (the receiver should run with --keep-open)
    #[arg(long)]
    pub watch: bool,

    /// Seconds between watch-mode polls
    #[arg(long, default_value_t = 2, value_name = "SECS", requires = "watch")]
    pub interval: u64,
}

#[derive(Debug, Args)]
pub struct ReceiveArgs {
    /// Directory incoming files are written into
    #[arg(short = 'o', long, value_name = "DIR", default_value = ".")]
    pub out: PathBuf,

    /// Local address to bind (default: all interfaces)
    #[arg(long, value_name = "IP", default_value = "0.0.0.0")]
    pub listen: IpAddr,

    /// TCP port to listen on (0 = pick one and announce it)
    #[arg(long, value_name = "PORT", default_value_t = 0)]
    pub port: u16,

    /// Shared passphrase mixed into the key exchange
    #[arg(short = 'p', long, env = "RUSTDROP_PASSPHRASE", hide_env_values = true)]
    pub passphrase: Option<String>,

    /// Only accept senders that present this trust code
    #[arg(long, value_name = "CODE")]
    pub trust: Option<String>,

    /// Accept every transfer without asking
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Keep listening for more senders after each transfer
    #[arg(long)]
    pub keep_open: bool,

    /// Refuse files that already exist instead of overwriting them
    #[arg(long)]
    pub no_clobber: bool,

    /// Discard .rustdrop-part leftovers and restart every file from scratch
    /// (resuming with prefix verification is the default)
    #[arg(long)]
    pub no_resume: bool,

    /// Compatibility no-op: resuming is on by default
    #[arg(long, hide = true)]
    pub resume: bool,

    /// Refuse single files larger than this (accepts 500M, 1.5G, ...)
    #[arg(long, value_name = "BYTES")]
    pub max_file_size: Option<String>,

    /// Refuse sessions whose combined size exceeds this (accepts 500M, 1.5G)
    #[arg(long, value_name = "BYTES")]
    pub max_total_size: Option<String>,

    /// Do not restore modification times on received files
    #[arg(long)]
    pub no_preserve_time: bool,

    /// Skip mDNS announcement (use the printed ip:port manually)
    #[arg(long)]
    pub no_mdns: bool,

    /// Seconds to wait for a sender (idle timeout with --keep-open, 0 = forever)
    #[arg(long, default_value_t = 600, value_name = "SECS")]
    pub timeout: u64,

    /// Emit a machine-readable JSON summary on stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// How long to browse before printing results
    #[arg(long, default_value_t = 3, value_name = "SECS")]
    pub timeout: u64,

    /// Only list receivers whose name contains PATTERN
    #[arg(short = 'n', long, value_name = "PATTERN")]
    pub name: Option<String>,

    /// Print JSON instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to generate a script for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_send_with_features() {
        let cli = Cli::parse_from([
            "rustdrop",
            "send",
            "--compress",
            "--limit",
            "10M",
            "--trust",
            "7GKM-2XQ4",
            "--exclude",
            "**/*.tmp",
            "-p",
            "hunter2",
            "a.txt",
            "dir/",
        ]);
        match cli.command {
            Command::Send(args) => {
                assert!(args.compress);
                assert_eq!(args.limit.as_deref(), Some("10M"));
                assert_eq!(args.trust.as_deref(), Some("7GKM-2XQ4"));
                assert_eq!(args.exclude, vec!["**/*.tmp"]);
                assert_eq!(args.paths.len(), 2);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_receive_flags() {
        let cli = Cli::parse_from([
            "rustdrop",
            "receive",
            "-o",
            "/tmp/in",
            "--yes",
            "--keep-open",
            "--no-clobber",
            "--port",
            "9000",
        ]);
        match cli.command {
            Command::Receive(args) => {
                assert!(args.yes);
                assert!(args.keep_open);
                assert!(args.no_clobber);
                assert_eq!(args.port, 9000);
                assert_eq!(args.out, PathBuf::from("/tmp/in"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn chunk_size_is_bounded() {
        assert!(
            Cli::try_parse_from(["rustdrop", "send", "--chunk-size", "99999999", "a.txt"]).is_err()
        );
        assert!(Cli::try_parse_from(["rustdrop", "send", "--chunk-size", "0", "a.txt"]).is_err());
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        assert!(Cli::try_parse_from(["rustdrop", "--quiet", "--verbose", "list"]).is_err());
    }
}
