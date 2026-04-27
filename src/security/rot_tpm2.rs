use crate::security::root_of_trust::RootOfTrust;
use crate::Result;
use std::sync::Arc;

/// TPM 2.0 backend boundary (tss-esapi / resource manager).
///
/// This abstraction exists to keep the **Root-of-Trust** contract explicit:
/// - sealed storage (confidentiality + integrity)
/// - rollback-resistant monotonic counters (TPM NV counters / NV indices)
///
/// A production implementation typically:
/// - talks to `/dev/tpmrm0` via `tss-esapi`
/// - uses an NV counter index per label namespace (or a keyed mapping)
/// - binds sealed blobs to the NV counter value (anti-rollback)
pub trait Tpm2Backend: Send + Sync {
    /// Human-readable kind string for observability.
    fn tpm_kind(&self) -> &'static str;

    /// Whether this backend provides rollback-resistant storage/counters.
    fn is_rollback_resistant_storage(&self) -> bool;

    /// Seal data to persistent storage under `label`.
    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()>;
    /// Unseal data from persistent storage under `label`.
    fn unseal_data(&self, label: &str) -> Result<Vec<u8>>;

    /// Read the current TPM NV counter value, or `None` when unset.
    fn nv_counter_get(&self, label: &str) -> Result<Option<u64>>;
    /// Advance the TPM NV counter to `candidate` when `candidate > current`.
    fn nv_counter_advance_to(&self, label: &str, candidate: u64) -> Result<bool>;
    /// Increment the TPM NV counter and return the new value.
    fn nv_counter_increment(&self, label: &str) -> Result<u64>;
}

/// Root-of-trust wrapper that delegates to a TPM2 backend.
pub struct Tpm2RootOfTrust {
    backend: Arc<dyn Tpm2Backend>,
}

impl Tpm2RootOfTrust {
    /// Create a `RootOfTrust` wrapper around a concrete TPM2 backend.
    pub fn new(backend: Arc<dyn Tpm2Backend>) -> Self {
        Self { backend }
    }

    /// Observability: underlying TPM backend kind string.
    pub fn tpm_kind(&self) -> &'static str {
        self.backend.tpm_kind()
    }
}

impl RootOfTrust for Tpm2RootOfTrust {
    fn rot_kind(&self) -> &'static str {
        "tpm2"
    }

    fn is_rollback_resistant_storage(&self) -> bool {
        self.backend.is_rollback_resistant_storage()
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        self.backend.seal_data(label, data)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        self.backend.unseal_data(label)
    }

    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
        self.backend.nv_counter_get(label)
    }

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        self.backend.nv_counter_advance_to(label, candidate)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        self.backend.nv_counter_increment(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[derive(Default)]
    struct MockTpm2 {
        blobs: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        counters: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    }

    impl Tpm2Backend for MockTpm2 {
        fn tpm_kind(&self) -> &'static str {
            "mock-tpm2"
        }

        fn is_rollback_resistant_storage(&self) -> bool {
            true
        }

        fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
            let mut blobs = self
                .blobs
                .lock()
                .map_err(|_| Error::ClientError("mock tpm2 blobs mutex poisoned".into()))?;
            blobs.insert(label.to_string(), data.to_vec());
            Ok(())
        }

        fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
            let blobs = self
                .blobs
                .lock()
                .map_err(|_| Error::ClientError("mock tpm2 blobs mutex poisoned".into()))?;
            blobs.get(label).cloned().ok_or_else(|| {
                Error::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "blob missing",
                ))
            })
        }

        fn nv_counter_get(&self, label: &str) -> Result<Option<u64>> {
            let counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tpm2 counters mutex poisoned".into()))?;
            Ok(counters.get(label).copied())
        }

        fn nv_counter_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tpm2 counters mutex poisoned".into()))?;
            let current = counters.get(label).copied().unwrap_or(0);
            if candidate > current {
                counters.insert(label.to_string(), candidate);
                return Ok(true);
            }
            Ok(false)
        }

        fn nv_counter_increment(&self, label: &str) -> Result<u64> {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tpm2 counters mutex poisoned".into()))?;
            let current = counters.get(label).copied().unwrap_or(0);
            let next = current.saturating_add(1).max(1);
            counters.insert(label.to_string(), next);
            Ok(next)
        }
    }

    #[test]
    fn tpm2_rot_delegates() {
        let tpm = Arc::new(MockTpm2::default());
        let rot = Tpm2RootOfTrust::new(tpm);

        rot.seal_data("x", b"y").unwrap();
        assert_eq!(rot.unseal_data("x").unwrap(), b"y");
        assert_eq!(rot.sealed_monotonic_u64_get("c").unwrap(), None);
        assert_eq!(rot.sealed_monotonic_u64_increment("c").unwrap(), 1);
        assert_eq!(rot.sealed_monotonic_u64_get("c").unwrap(), Some(1));
    }
}
