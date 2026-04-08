/// Structured and Chained Audit Logging.
pub mod audit;
/// Denial of Service (DoS) Protection mechanisms (Client Puzzles, Rate Limiting).
pub mod dos;
/// Hybrid encryption (KEM + AES-GCM)
pub mod hybrid;
/// Key storage and management
pub mod keystore;
/// Anomaly Detection Counters and Metrics.
pub mod metrics;
/// Sealed monotonic counters and helpers.
#[cfg(feature = "std")]
pub mod monotonic;
/// Signed fleet policy updates (CA-distributed).
pub mod policy;
/// Abstraction for security providers (Hardware/Software)
pub mod provider;
/// Signed revocation updates (CA-distributed).
pub mod revocation;
/// Secure time / monotonic floor helpers (best-effort without TPM/HSM).
#[cfg(feature = "std")]
pub mod time;
/// TPM 2.0 implementation (Software-backed for Linux/Gateway)
#[cfg(feature = "std")]
pub mod tpm;
