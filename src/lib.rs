//! RustDrop – privacy-first, lightning-fast peer-to-peer file transfer for
//! local networks.
//!
//! # Crate layout
//!
//! | module | responsibility |
//! |--------|----------------|
//! | [`crypto`] | X25519 key exchange, HKDF key schedule, ChaCha20-Poly1305 channels, trust codes |
//! | [`discovery`] | mDNS/Zeroconf announce + browse |
//! | [`protocol`] | length-prefixed framing, handshake & control messages, data frames |
//! | [`transfer`] | sender/receiver state machines, manifests, progress reporting |
//! | [`ui`] | indicatif progress bars and dialoguer prompts (CLI only) |
//! | [`cli`] / [`commands`] | argument parsing and command handlers |
//! | [`error`] | the crate-wide [`RustDropError`] |
//!
//! The binary in `src/main.rs` is a thin wrapper: parse args, pick a command,
//! print errors. Everything interesting lives here so it can be unit-tested
//! and reused.

pub mod cli;
pub mod commands;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod protocol;
pub mod transfer;
pub mod ui;

pub use error::{Result, RustDropError};
