use crate::security::root_of_trust::{RootOfTrust, SoftwareRootOfTrust};
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Remote append-only monotonic counter store.
///
/// This represents an external *anti-rollback anchor* (HSM-backed service, WORM/append-only store,
/// etc). The semantics must be:
/// - values are monotonic per key
/// - rollback is not possible for an attacker with local filesystem access
///
/// If this assumption is false, `RemoteAppendOnlyRootOfTrust` becomes best-effort and must not be
/// used to satisfy `require_rollback_resistant_storage` fleet policy.
pub trait AppendOnlyCounterStore: Send + Sync {
    /// Human-readable store kind string for observability.
    fn store_kind(&self) -> &'static str;

    /// Return the current counter value for `key`, or `None` when unset.
    fn get(&self, key: &str) -> Result<Option<u64>>;

    /// Advance the counter to `candidate` if `candidate > current`.
    ///
    /// Returns `Ok(true)` when advanced, `Ok(false)` otherwise.
    fn advance_to(&self, key: &str, candidate: u64) -> Result<bool>;

    /// Increment the counter by 1 and return the new value.
    fn increment(&self, key: &str) -> Result<u64>;
}

/// A reference RoT that uses:
/// - local sealed blobs (confidentiality + integrity) and
/// - a remote append-only counter (anti-rollback anchor).
///
/// Threat model and failure semantics:
/// - If the remote store is unreachable, sealing/unsealing and monotonic counter ops fail.
/// - A local attacker who rolls back `pqc-data/` blobs will be detected on `unseal_data()`.
/// - A local attacker who deletes blobs will induce a fail-closed condition.
pub struct RemoteAppendOnlyRootOfTrust {
    local: SoftwareRootOfTrust,
    remote: Arc<dyn AppendOnlyCounterStore>,
    namespace: String,
}

impl RemoteAppendOnlyRootOfTrust {
    /// Construct a remote-anchored RoT.
    ///
    /// `namespace` is a logical partitioning label (e.g. deployment/fleet id) and is incorporated
    /// into remote keys to avoid collisions across environments.
    pub fn new(
        local_master_key: [u8; 32],
        remote: Arc<dyn AppendOnlyCounterStore>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            local: SoftwareRootOfTrust::new(local_master_key),
            remote,
            namespace: namespace.into(),
        }
    }

    fn remote_key(&self, kind: &str, label: &str) -> String {
        // Hash the label to avoid exposing potentially sensitive path/id material to the remote
        // store and to ensure a stable, bounded key.
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(b":");
        hasher.update(kind.as_bytes());
        hasher.update(b":");
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        format!("pqc-iiot:rot:{}:{}", kind, hex::encode(digest))
    }

    fn local_label_for_seal(&self, label: &str) -> String {
        // Keep a stable domain-separated label namespace for local sealing keys.
        format!("pqc-iiot:rot-remote-seal:v1:{}", label)
    }

    fn encode_envelope_v1(gen: u64, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > u32::MAX as usize {
            return Err(Error::InvalidInput("sealed data too large".into()));
        }
        let mut out = Vec::with_capacity(1 + 8 + 4 + data.len());
        out.push(1u8);
        out.extend_from_slice(&gen.to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        Ok(out)
    }

    fn decode_envelope_v1(blob: &[u8]) -> Result<(u64, Vec<u8>)> {
        const MIN: usize = 1 + 8 + 4;
        if blob.len() < MIN {
            return Err(Error::CryptoError("sealed envelope too short".into()));
        }
        if blob[0] != 1u8 {
            return Err(Error::CryptoError(format!(
                "unsupported sealed envelope version: {}",
                blob[0]
            )));
        }
        let mut gen_bytes = [0u8; 8];
        gen_bytes.copy_from_slice(&blob[1..9]);
        let gen = u64::from_be_bytes(gen_bytes);
        let len = u32::from_be_bytes([blob[9], blob[10], blob[11], blob[12]]) as usize;
        if blob.len() != MIN + len {
            return Err(Error::CryptoError("sealed envelope length mismatch".into()));
        }
        Ok((gen, blob[13..].to_vec()))
    }
}

impl RootOfTrust for RemoteAppendOnlyRootOfTrust {
    fn rot_kind(&self) -> &'static str {
        "remote-append-only"
    }

    fn is_rollback_resistant_storage(&self) -> bool {
        true
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        let remote_key = self.remote_key("seal", label);

        // Two-phase update:
        // 1) compute candidate generation (monotonic)
        // 2) write local sealed blob tagged with candidate generation
        // 3) advance remote floor to candidate generation
        //
        // If the process crashes between (2) and (3), `unseal_data()` will self-heal by advancing
        // the remote floor to the local generation.
        let current = self.remote.get(&remote_key)?.unwrap_or(0);
        let candidate = current.saturating_add(1).max(1);

        let envelope = Self::encode_envelope_v1(candidate, data)?;
        let local_label = self.local_label_for_seal(label);
        self.local.seal_data(&local_label, &envelope)?;

        // Now commit the remote floor.
        let _ = self.remote.advance_to(&remote_key, candidate)?;
        Ok(())
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        let remote_key = self.remote_key("seal", label);
        let remote_gen = self.remote.get(&remote_key)?.ok_or_else(|| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "remote sealed generation missing",
            ))
        })?;

        let local_label = self.local_label_for_seal(label);
        let blob = self.local.unseal_data(&local_label)?;
        let (local_gen, data) = Self::decode_envelope_v1(&blob)?;

        if local_gen > remote_gen {
            // Crash between local seal and remote floor update: self-heal by advancing remote.
            let _ = self.remote.advance_to(&remote_key, local_gen)?;
            let healed = self.remote.get(&remote_key)?.unwrap_or(remote_gen);
            if healed == local_gen {
                return Ok(data);
            }
        }

        if local_gen != remote_gen {
            return Err(Error::CryptoError(format!(
                "sealed blob generation mismatch (rollback?): local_gen={} remote_gen={}",
                local_gen, remote_gen
            )));
        }

        Ok(data)
    }

    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
        let key = self.remote_key("monotonic", label);
        self.remote.get(&key)
    }

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        let key = self.remote_key("monotonic", label);
        self.remote.advance_to(&key, candidate)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        let key = self.remote_key("monotonic", label);
        self.remote.increment(&key)
    }
}

/// In-memory append-only counter store (for tests/demos).
#[derive(Default)]
pub struct InMemoryAppendOnlyCounterStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl InMemoryAppendOnlyCounterStore {
    /// Create a new in-memory append-only counter store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AppendOnlyCounterStore for InMemoryAppendOnlyCounterStore {
    fn store_kind(&self) -> &'static str {
        "in-memory"
    }

    fn get(&self, key: &str) -> Result<Option<u64>> {
        let map = self.inner.lock().map_err(|_| {
            Error::ClientError("InMemoryAppendOnlyCounterStore mutex poisoned".into())
        })?;
        Ok(map.get(key).copied())
    }

    fn advance_to(&self, key: &str, candidate: u64) -> Result<bool> {
        let mut map = self.inner.lock().map_err(|_| {
            Error::ClientError("InMemoryAppendOnlyCounterStore mutex poisoned".into())
        })?;
        let current = map.get(key).copied().unwrap_or(0);
        if candidate > current {
            map.insert(key.to_string(), candidate);
            return Ok(true);
        }
        Ok(false)
    }

    fn increment(&self, key: &str) -> Result<u64> {
        let mut map = self.inner.lock().map_err(|_| {
            Error::ClientError("InMemoryAppendOnlyCounterStore mutex poisoned".into())
        })?;
        let current = map.get(key).copied().unwrap_or(0);
        let next = current.saturating_add(1).max(1);
        map.insert(key.to_string(), next);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sealed_blob_path(label: &str) -> std::path::PathBuf {
        let digest = Sha256::digest(label.as_bytes());
        Path::new("pqc-data").join(format!("sealed_{}.bin", hex::encode(digest)))
    }

    #[test]
    fn remote_rot_seal_unseal_roundtrip_and_rollback_detection() {
        let remote = Arc::new(InMemoryAppendOnlyCounterStore::new());
        let rot = RemoteAppendOnlyRootOfTrust::new([0x11u8; 32], remote, "fleet-a");

        let label = "pqc-iiot:test:remote-rot:blob";
        let local_label = rot.local_label_for_seal(label);
        let path = sealed_blob_path(&local_label);

        // First seal.
        rot.seal_data(label, b"v1").expect("seal v1");
        let first_blob = std::fs::read(&path).expect("read v1 blob");
        assert_eq!(rot.unseal_data(label).unwrap(), b"v1");

        // Second seal advances remote generation.
        rot.seal_data(label, b"v2").expect("seal v2");
        assert_eq!(rot.unseal_data(label).unwrap(), b"v2");

        // Roll back local file: restore v1 blob.
        std::fs::write(&path, first_blob).expect("rollback local blob");
        let err = rot
            .unseal_data(label)
            .expect_err("rollback must be detected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("generation mismatch"),
            "unexpected error: {msg}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remote_rot_monotonic_counters_are_monotonic() {
        let remote = Arc::new(InMemoryAppendOnlyCounterStore::new());
        let rot = RemoteAppendOnlyRootOfTrust::new([0x22u8; 32], remote, "fleet-b");

        let label = "pqc-iiot:test:remote-rot:counter";
        assert_eq!(rot.sealed_monotonic_u64_get(label).unwrap(), None);
        assert_eq!(rot.sealed_monotonic_u64_increment(label).unwrap(), 1);
        assert_eq!(rot.sealed_monotonic_u64_get(label).unwrap(), Some(1));
        assert!(rot.sealed_monotonic_u64_advance_to(label, 10).unwrap());
        assert_eq!(rot.sealed_monotonic_u64_get(label).unwrap(), Some(10));
        assert!(!rot.sealed_monotonic_u64_advance_to(label, 9).unwrap());
        assert_eq!(rot.sealed_monotonic_u64_increment(label).unwrap(), 11);
    }
}
