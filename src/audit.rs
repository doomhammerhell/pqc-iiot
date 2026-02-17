use log::{error, info, warn};
use serde::Serialize;

/// Security events that can be audited.
#[derive(Debug, Serialize)]
pub enum SecurityEvent<'a> {
    /// Identity file loaded from disk.
    IdentityLoaded {
        /// Client ID
        client_id: &'a str,
        /// Path to identity file
        path: &'a str,
    },
    /// New identity generated.
    IdentityGenerated {
        /// Client ID
        client_id: &'a str,
    },
    /// Peer identity mismatch detected (Strict Mode).
    IdentityMismatch {
        /// Peer ID
        peer_id: &'a str,
        /// Reason for mismatch
        reason: &'a str,
    },
    /// Trust revoked for a peer.
    TrustRevoked {
        /// Peer ID
        peer_id: &'a str,
        /// Reason for revocation
        reason: &'a str,
    },
    /// Replay attack detected.
    ReplayDetected {
        /// Peer ID
        peer_id: &'a str,
        /// Sequence number
        seq: u64,
        /// Last seen sequence number
        last_seq: u64,
    },
    /// Encryption/Decryption failure.
    EncryptionFailure {
        /// Peer ID
        peer_id: &'a str,
        /// Error message
        error: &'a str,
    },
}

/// Log a security event to the audit log.
pub fn log_security_event(event: &SecurityEvent<'_>) {
    // Log as structured JSON or Key-Value
    // For now, use a consistent prefix [AUDIT] and debug info
    match event {
        SecurityEvent::IdentityLoaded { .. } | SecurityEvent::IdentityGenerated { .. } => {
            info!("[AUDIT] {:?}", event);
        }
        SecurityEvent::IdentityMismatch { .. } | SecurityEvent::EncryptionFailure { .. } => {
            error!("[AUDIT] {:?}", event);
        }
        SecurityEvent::TrustRevoked { .. } | SecurityEvent::ReplayDetected { .. } => {
            warn!("[AUDIT] {:?}", event);
        }
    }
}
