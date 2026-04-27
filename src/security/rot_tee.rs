use crate::security::root_of_trust::RootOfTrust;
use crate::Result;
use std::sync::Arc;

/// TEE backend boundary (TrustZone/OP-TEE/SGX style).
///
/// Production implementations typically cross an FFI boundary (TEE Client API) and provide:
/// - sealed storage bound to the TEE root key
/// - a rollback-resistant monotonic counter (TEE monotonic storage / RPMB-backed counter)
///
/// This crate intentionally keeps the interface minimal and deterministic.
pub trait TeeBackend: Send + Sync {
    /// Human-readable kind string for observability.
    fn tee_kind(&self) -> &'static str;

    /// Whether the TEE provides rollback-resistant storage/counters.
    fn is_rollback_resistant_storage(&self) -> bool;

    /// Seal data to persistent storage under `label`.
    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()>;
    /// Unseal data from persistent storage under `label`.
    fn unseal_data(&self, label: &str) -> Result<Vec<u8>>;

    /// Read the current monotonic counter value, or `None` when unset.
    fn monotonic_u64_get(&self, label: &str) -> Result<Option<u64>>;
    /// Advance the monotonic counter to `candidate` when `candidate > current`.
    fn monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool>;
    /// Increment the monotonic counter and return the new value.
    fn monotonic_u64_increment(&self, label: &str) -> Result<u64>;
}

/// Root-of-trust wrapper that delegates to a TEE backend.
pub struct TeeRootOfTrust {
    backend: Arc<dyn TeeBackend>,
}

impl TeeRootOfTrust {
    /// Create a `RootOfTrust` wrapper around a concrete TEE backend.
    pub fn new(backend: Arc<dyn TeeBackend>) -> Self {
        Self { backend }
    }

    /// Observability: underlying TEE backend kind string.
    pub fn tee_kind(&self) -> &'static str {
        self.backend.tee_kind()
    }
}

impl RootOfTrust for TeeRootOfTrust {
    fn rot_kind(&self) -> &'static str {
        "tee"
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
        self.backend.monotonic_u64_get(label)
    }

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        self.backend.monotonic_u64_advance_to(label, candidate)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        self.backend.monotonic_u64_increment(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[derive(Default)]
    struct MockTee {
        blobs: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        counters: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    }

    impl TeeBackend for MockTee {
        fn tee_kind(&self) -> &'static str {
            "mock-tee"
        }

        fn is_rollback_resistant_storage(&self) -> bool {
            true
        }

        fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
            let mut blobs = self
                .blobs
                .lock()
                .map_err(|_| Error::ClientError("mock tee blobs mutex poisoned".into()))?;
            blobs.insert(label.to_string(), data.to_vec());
            Ok(())
        }

        fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
            let blobs = self
                .blobs
                .lock()
                .map_err(|_| Error::ClientError("mock tee blobs mutex poisoned".into()))?;
            blobs.get(label).cloned().ok_or_else(|| {
                Error::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "blob missing",
                ))
            })
        }

        fn monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
            let counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tee counters mutex poisoned".into()))?;
            Ok(counters.get(label).copied())
        }

        fn monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tee counters mutex poisoned".into()))?;
            let current = counters.get(label).copied().unwrap_or(0);
            if candidate > current {
                counters.insert(label.to_string(), candidate);
                return Ok(true);
            }
            Ok(false)
        }

        fn monotonic_u64_increment(&self, label: &str) -> Result<u64> {
            let mut counters = self
                .counters
                .lock()
                .map_err(|_| Error::ClientError("mock tee counters mutex poisoned".into()))?;
            let current = counters.get(label).copied().unwrap_or(0);
            let next = current.saturating_add(1).max(1);
            counters.insert(label.to_string(), next);
            Ok(next)
        }
    }

    #[test]
    fn tee_rot_delegates() {
        let tee = Arc::new(MockTee::default());
        let rot = TeeRootOfTrust::new(tee);

        rot.seal_data("x", b"y").unwrap();
        assert_eq!(rot.unseal_data("x").unwrap(), b"y");
        assert_eq!(rot.sealed_monotonic_u64_get("c").unwrap(), None);
        assert_eq!(rot.sealed_monotonic_u64_increment("c").unwrap(), 1);
        assert_eq!(rot.sealed_monotonic_u64_get("c").unwrap(), Some(1));
    }
}
