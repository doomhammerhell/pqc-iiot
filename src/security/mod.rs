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
/// Abstraction for security providers (Hardware/Software)
pub mod provider;
/// TPM 2.0 implementation (Software-backed for Linux/Gateway)
#[cfg(feature = "std")]
pub mod tpm;
