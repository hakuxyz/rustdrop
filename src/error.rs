use thiserror::Error;

/// Convenient alias used across the crate.
pub type Result<T> = std::result::Result<T, RustDropError>;

/// Errors produced by the RustDrop core library.
///
/// The CLI boundary converts these into [`anyhow::Error`] so that command
/// handlers can add context, while library consumers get a stable, matchable
/// error surface.
#[derive(Debug, Error)]
pub enum RustDropError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cryptography failed: {0}")]
    Crypto(String),

    #[error("authentication tag verification failed")]
    Decryption,

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("trust code mismatch: expected {expected}, peer presented {actual}")]
    TrustCodeMismatch { expected: String, actual: String },

    #[error("peer rejected the transfer: {0}")]
    Rejected(String),

    #[error("service discovery failed: {0}")]
    Discovery(String),

    #[error("integrity check failed for '{file}': expected {expected}, got {actual}")]
    Integrity {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("path not found: {0}")]
    NotFound(String),

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("peer disconnected before the transfer completed")]
    Disconnected,

    #[error("unsupported protocol version (peer speaks v{peer}, this build speaks v{local})")]
    VersionMismatch { local: u8, peer: u8 },

    #[error("no receivers found on the local network")]
    NoReceivers,

    #[error("unsafe path rejected: {0}")]
    UnsafePath(String),
}

impl From<chacha20poly1305::aead::Error> for RustDropError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        RustDropError::Decryption
    }
}

impl From<mdns_sd::Error> for RustDropError {
    fn from(e: mdns_sd::Error) -> Self {
        RustDropError::Discovery(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_human_readable() {
        let e = RustDropError::TrustCodeMismatch {
            expected: "ABCD-EFGH".into(),
            actual: "WXYZ-1234".into(),
        };
        assert!(e.to_string().contains("ABCD-EFGH"));
    }

    #[test]
    fn io_error_converts() {
        let e: RustDropError = std::io::Error::other("boom").into();
        assert!(matches!(e, RustDropError::Io(_)));
    }
}
