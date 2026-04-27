/// Structured and Chained Audit Logging.
pub mod audit;
/// Denial of Service (DoS) Protection mechanisms (Client Puzzles, Rate Limiting).
pub mod dos;
/// Gateway hardware security module integration (PQC in HSM + RoT-backed persistence).
pub mod hsm;
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
/// Root-of-trust boundary (TPM/TEE/HSM) and composite providers.
pub mod root_of_trust;
/// Remote append-only root-of-trust backend (anchor for anti-rollback).
pub mod rot_remote;
/// TEE root-of-trust backend interface (TrustZone/OP-TEE/SGX).
pub mod rot_tee;
/// TPM2 root-of-trust backend interface (TPM NV counters / sealing).
pub mod rot_tpm2;
/// Secure time / monotonic floor helpers (best-effort without TPM/HSM).
#[cfg(feature = "std")]
pub mod time;
/// TPM 2.0 implementation (Software-backed for Linux/Gateway)
#[cfg(feature = "std")]
pub mod tpm;

/// PKCS#11 HSM backend (vendor-specific PQC mechanisms).
#[cfg(feature = "hsm-pkcs11")]
pub mod hsm_pkcs11;
