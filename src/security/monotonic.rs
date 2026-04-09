use crate::security::provider::SecurityProvider;
use crate::{Error, Result};
use std::sync::Arc;

/// Unseal a `u64` value from the `SecurityProvider` under `label`.
///
/// Returns `Ok(None)` when the sealed blob does not exist.
pub fn unseal_u64(provider: &Arc<dyn SecurityProvider>, label: &str) -> Result<Option<u64>> {
    match provider.unseal_data(label) {
        Ok(blob) => {
            if blob.len() != 8 {
                return Err(Error::CryptoError(format!(
                    "Invalid sealed u64 length for {}: {}",
                    label,
                    blob.len()
                )));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&blob);
            Ok(Some(u64::from_be_bytes(buf)))
        }
        Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Seal a `u64` value behind the `SecurityProvider` under `label`.
pub fn seal_u64(provider: &Arc<dyn SecurityProvider>, label: &str, value: u64) -> Result<()> {
    provider.seal_data(label, &value.to_be_bytes())
}

/// A monotonic u64 counter persisted behind `SecurityProvider::seal_data`.
///
/// Security notes:
/// - This counter is only rollback-resistant when `SecurityProvider::is_rollback_resistant_storage() == true`.
///   Otherwise, an attacker with filesystem write access can restore an older sealed blob.
/// - Persist on every update. For embedded flash, callers should tune usage (batching counters at a higher layer).
pub struct SealedMonotonicU64 {
    provider: Arc<dyn SecurityProvider>,
    label: String,
    value: u64,
}

impl SealedMonotonicU64 {
    /// Load a counter from sealed storage or initialize it to `initial` and seal it immediately.
    pub fn load(
        provider: Arc<dyn SecurityProvider>,
        label: impl Into<String>,
        initial: u64,
    ) -> Result<Self> {
        let label = label.into();
        let persisted = unseal_u64(&provider, &label)?;
        let value = persisted.unwrap_or(initial);
        if persisted.is_none() {
            seal_u64(&provider, &label, value)?;
        }
        Ok(Self {
            provider,
            label,
            value,
        })
    }

    /// Return the current value (last persisted).
    pub fn current(&self) -> u64 {
        self.value
    }

    /// Persist a new value if it strictly advances the counter.
    ///
    /// Returns `Ok(true)` when the counter advanced, `Ok(false)` otherwise.
    pub fn advance_to(&mut self, candidate: u64) -> Result<bool> {
        if candidate > self.value {
            self.value = candidate;
            seal_u64(&self.provider, &self.label, self.value)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Increment the counter by 1, persist, and return the new value.
    pub fn increment(&mut self) -> Result<u64> {
        let next = self.value.saturating_add(1).max(1);
        self.value = next;
        seal_u64(&self.provider, &self.label, self.value)?;
        Ok(self.value)
    }

    /// Return the backing seal label (observability/debug only).
    pub fn label(&self) -> &str {
        &self.label
    }
}
