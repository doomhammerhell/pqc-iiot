use crate::security::provider::SecurityProvider;
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn ensure_pqc_data_dir() -> Result<()> {
    let dir = Path::new("pqc-data");
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(Error::IoError)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            return Err(Error::IoError(e));
        }
    }
    Ok(())
}

fn sealed_blob_path(label: &str) -> PathBuf {
    // Never use `label` as a path fragment directly: it may carry path separators and trigger
    // traversal/overwrite. Hash it into a stable, filesystem-safe name.
    let digest = Sha256::digest(label.as_bytes());
    Path::new("pqc-data").join(format!("sealed_{}.bin", hex::encode(digest)))
}

/// Hardware Root of Trust (RoT) boundary.
///
/// This is the interface we *actually* need for IIoT-critical anti-rollback:
/// - rollback-resistant monotonic counters (TPM NV counters / TEE monotonic storage / HSM)
/// - rollback-resistant sealing (eg. TPM sealed objects bound to NV counters)
///
/// Invariant: When `is_rollback_resistant_storage() == true`, callers may treat
/// `seal_data/unseal_data` and `sealed_monotonic_u64_*` as **anti-rollback** primitives.
/// When `false`, these are best-effort and can be rolled back by restoring older blobs.
pub trait RootOfTrust: Send + Sync {
    /// Human-readable kind string for observability.
    fn rot_kind(&self) -> &'static str;

    /// Whether the RoT provides rollback-resistant storage/counters.
    fn is_rollback_resistant_storage(&self) -> bool;

    /// Seal data to persistent storage under `label`.
    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()>;

    /// Unseal data from persistent storage under `label`.
    fn unseal_data(&self, label: &str) -> Result<Vec<u8>>;

    /// Read a sealed monotonic `u64` counter.
    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>>;

    /// Advance a sealed monotonic counter if `candidate > current`.
    ///
    /// Returns `Ok(true)` when the counter advanced, `Ok(false)` otherwise.
    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool>;

    /// Increment a sealed monotonic counter by 1, persist it, and return the new value.
    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64>;
}

/// Best-effort RoT implementation for dev/test: AES-GCM sealed blobs on the filesystem.
///
/// This does **not** provide rollback resistance.
///
/// Intended usage:
/// - In production, replace this with a TPM/TEE/HSM-backed RoT.
/// - In tests/demos, this gives deterministic semantics for the RoT boundary without pretending to
///   provide anti-rollback.
pub struct SoftwareRootOfTrust {
    master_key: [u8; 32],
}

impl SoftwareRootOfTrust {
    /// Create a new RoT instance with an explicit master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    fn sealing_key(&self, label: &str) -> aes_gcm::Key<Aes256Gcm> {
        let mut hasher = Sha256::new();
        hasher.update(self.master_key);
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        *aes_gcm::Key::<Aes256Gcm>::from_slice(&digest)
    }
}

impl RootOfTrust for SoftwareRootOfTrust {
    fn rot_kind(&self) -> &'static str {
        "software-rot"
    }

    fn is_rollback_resistant_storage(&self) -> bool {
        false
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        ensure_pqc_data_dir()?;
        let path = sealed_blob_path(label);
        let key = self.sealing_key(label);
        let cipher = Aes256Gcm::new(&key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| Error::CryptoError("RoT seal encryption failed".into()))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        crate::persistence::AtomicFileStore::write(&path, &out)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        const MAX_SEALED_BYTES: usize = 1024 * 1024; // 1 MiB anti-OOM guardrail

        if !Path::new("pqc-data").exists() {
            return Err(Error::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "pqc-data missing",
            )));
        }

        let path = sealed_blob_path(label);
        let blob = crate::persistence::AtomicFileStore::read_with_limit(&path, MAX_SEALED_BYTES)?;
        if blob.len() < 12 {
            return Err(Error::CryptoError("Sealed data too short".into()));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let key = self.sealing_key(label);
        let cipher = Aes256Gcm::new(&key);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| Error::CryptoError("Sealed data authentication failed".into()))
    }

    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
        match self.unseal_data(label) {
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

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        let current = self.sealed_monotonic_u64_get(label)?.unwrap_or(0);
        if candidate > current {
            self.seal_data(label, &candidate.to_be_bytes())?;
            return Ok(true);
        }
        Ok(false)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        let current = self.sealed_monotonic_u64_get(label)?.unwrap_or(0);
        let next = current.saturating_add(1).max(1);
        self.seal_data(label, &next.to_be_bytes())?;
        Ok(next)
    }
}

/// Composite `SecurityProvider` that delegates:
/// - long-term cryptographic operations to `crypto`
/// - sealing and monotonic state to a `RootOfTrust` (`rot`)
///
/// This models the production reality where PQC primitives may live in software today, while
/// anti-rollback and key-wrapping are anchored in a TPM/TEE/HSM.
pub struct CompositeSecurityProvider {
    crypto: Arc<dyn SecurityProvider>,
    rot: Arc<dyn RootOfTrust>,
}

impl CompositeSecurityProvider {
    /// Construct a composite provider from:
    /// - a cryptographic provider (`crypto`) for signatures/KEM/X25519, and
    /// - a root-of-trust (`rot`) for rollback-resistant sealing and monotonic counters.
    pub fn new(crypto: Arc<dyn SecurityProvider>, rot: Arc<dyn RootOfTrust>) -> Self {
        Self { crypto, rot }
    }

    /// Observability: the underlying crypto provider kind string.
    pub fn crypto_kind(&self) -> &'static str {
        self.crypto.provider_kind()
    }

    /// Observability: the underlying root-of-trust kind string.
    pub fn rot_kind(&self) -> &'static str {
        self.rot.rot_kind()
    }
}

impl SecurityProvider for CompositeSecurityProvider {
    fn kem_public_key(&self) -> &[u8] {
        self.crypto.kem_public_key()
    }

    fn sig_public_key(&self) -> &[u8] {
        self.crypto.sig_public_key()
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.crypto.decrypt(ciphertext)
    }

    fn kem_decapsulate(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.crypto.kem_decapsulate(kem_ciphertext)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.crypto.sign(message)
    }

    fn export_secret_keys(&self) -> Option<crate::security::provider::ExportedIdentitySecrets> {
        self.crypto.export_secret_keys()
    }

    fn provider_kind(&self) -> &'static str {
        "composite"
    }

    fn is_rollback_resistant_storage(&self) -> bool {
        self.rot.is_rollback_resistant_storage()
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        self.rot.seal_data(label, data)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        self.rot.unseal_data(label)
    }

    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
        self.rot.sealed_monotonic_u64_get(label)
    }

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        self.rot.sealed_monotonic_u64_advance_to(label, candidate)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        self.rot.sealed_monotonic_u64_increment(label)
    }

    fn generate_quote(
        &self,
        pcr_indices: &[u32],
        nonce: &[u8],
    ) -> Result<crate::attestation::quote::AttestationQuote> {
        self.crypto.generate_quote(pcr_indices, nonce)
    }

    fn x25519_public_key(&self) -> [u8; 32] {
        self.crypto.x25519_public_key()
    }

    fn x25519_exchange(&self, peer_pk: [u8; 32]) -> Result<[u8; 32]> {
        self.crypto.x25519_exchange(peer_pk)
    }
}
