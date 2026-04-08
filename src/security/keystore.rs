// use crate::crypto::traits::{PqcKEM, PqcSignature};
// use crate::kem::{MAX_PUBLIC_KEY_SIZE, Kyber};
// use crate::sign::{MAX_SIGNATURE_SIZE, Falcon};
// use heapless::String;
// use heapless::FnvIndexMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// ... imports ...
use std::path::Path;

/// Structure representing a peer's public keys and security state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerKeys {
    /// KEM Public Key (Kyber)
    #[serde(with = "base64_serde")]
    pub kem_pk: Vec<u8>,
    /// Signature Public Key (Falcon)
    #[serde(with = "base64_serde")]
    pub sig_pk: Vec<u8>,
    /// X25519 static public key (for Hybrid KEM).
    #[serde(default, with = "base64_serde")]
    pub x25519_pk: Vec<u8>,
    /// Monotonic key epoch (anti-rollback).
    #[serde(default)]
    pub key_epoch: u64,
    /// Key identifier (first 16 bytes of SHA-256 over certified identity material).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "base64_serde_opt")]
    pub key_id: Option<Vec<u8>>,
    /// Operational certificate (factory -> operational identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational_cert: Option<crate::provisioning::OperationalCertificate>,
    /// Last seen sequence number for replay protection
    #[serde(default)] // Default to 0 for compatibility
    pub last_sequence: u64,
    /// Sliding replay window bitmap relative to `last_sequence`.
    ///
    /// Bit `i` corresponds to sequence `last_sequence - i` for `i in 0..64`.
    /// This enables bounded out-of-order delivery while still rejecting replays.
    #[serde(default)]
    pub replay_window: u64,
    /// Whether this peer is trusted (Identity Verified)
    #[serde(default)] // Default to false
    pub is_trusted: bool,
    /// Remote Attestation Quote.
    pub quote: Option<crate::attestation::quote::AttestationQuote>,
    /// Detached signature over the key announcement payload (Falcon).
    /// Optional for backward compatibility; new messages must set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "base64_serde_opt")]
    pub key_signature: Option<Vec<u8>>,
}

/// Storage for known peer keys
#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    // Map client_id -> PeerKeys
    keys: std::collections::HashMap<std::string::String, PeerKeys>,
    /// Monotonic generation counter used for rollback detection.
    ///
    /// This value is persisted inside the keystore file and is expected to match a sealed counter
    /// stored behind `SecurityProvider::seal_data`. In deployments with a TPM/HSM-backed provider,
    /// this becomes a hard anti-rollback primitive for replay state and revocation state.
    #[serde(default)]
    generation: u64,
    /// Local revocation list: peer_id -> key_ids (opaque 16-byte identifiers).
    /// Used to prevent rollback to compromised identities and to support emergency revocation.
    #[serde(default)]
    revoked: std::collections::HashMap<std::string::String, Vec<Vec<u8>>>,
    /// Monotonic revocation sequence applied to this keystore (anti-rollback/replay for CRL updates).
    #[serde(default)]
    revocation_seq: u64,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    /// Create a new empty KeyStore.
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            generation: 0,
            revoked: std::collections::HashMap::new(),
            revocation_seq: 0,
        }
    }

    /// Current persisted generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Set the persisted generation counter.
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Bump the persisted generation counter, saturating on overflow.
    pub fn bump_generation(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.generation
    }

    /// Insert a peer into the store.
    pub fn insert(&mut self, client_id: &str, keys: PeerKeys) {
        self.keys.insert(client_id.to_string(), keys);
    }

    /// Get a peer's keys.
    pub fn get(&self, client_id: &str) -> Option<&PeerKeys> {
        self.keys.get(client_id)
    }

    /// Get mutable access to a peer's keys (e.g., to update sequence number).
    pub fn get_mut(&mut self, client_id: &str) -> Option<&mut PeerKeys> {
        self.keys.get_mut(client_id)
    }

    /// Check if a peer exists.
    pub fn contains(&self, client_id: &str) -> bool {
        self.keys.contains_key(client_id)
    }

    /// Revoke a specific key_id for a peer.
    pub fn revoke_key_id(&mut self, client_id: &str, key_id: &[u8]) {
        let entry = self.revoked.entry(client_id.to_string()).or_default();
        if !entry.iter().any(|k| k.as_slice() == key_id) {
            entry.push(key_id.to_vec());
        }
    }

    /// Check whether a specific key_id is revoked for a peer.
    pub fn is_key_id_revoked(&self, client_id: &str, key_id: &[u8]) -> bool {
        self.revoked
            .get(client_id)
            .map(|list| list.iter().any(|k| k.as_slice() == key_id))
            .unwrap_or(false)
    }

    /// Current monotonic revocation sequence applied to this keystore.
    pub fn revocation_seq(&self) -> u64 {
        self.revocation_seq
    }

    /// Set the revocation sequence applied to this keystore.
    pub fn set_revocation_seq(&mut self, seq: u64) {
        self.revocation_seq = seq;
    }

    /// Save the keystore to a file (JSON)
    #[cfg(feature = "std")]
    pub fn save_to_file(&self, path: &str) -> crate::Result<()> {
        let data = serde_json::to_vec_pretty(&self)
            .map_err(|e| crate::Error::ClientError(format!("Serialization error: {}", e)))?;

        crate::persistence::AtomicFileStore::write(std::path::Path::new(path), &data)?;
        Ok(())
    }

    /// Load the keystore from a file (JSON)
    pub fn load_from_file(path: &str) -> crate::Result<Self> {
        let path = Path::new(path);
        if !path.exists() {
            return Ok(Self::new());
        }
        const MAX_KEYSTORE_BYTES: usize = 8 * 1024 * 1024; // 8 MiB anti-OOM guardrail
        let blob = crate::persistence::AtomicFileStore::read_with_limit(path, MAX_KEYSTORE_BYTES)?;
        let keystore = serde_json::from_slice(&blob)
            .map_err(|e| crate::Error::ClientError(format!("Deserialization error: {}", e)))?;
        Ok(keystore)
    }
}

/// Helper for Base64 serialization
pub mod base64_serde {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    /// Serialize bytes to Base64 string
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = general_purpose::STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    /// Deserialize Base64 string to bytes
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        general_purpose::STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Optional Base64 helper
pub mod base64_serde_opt {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize optional bytes to a Base64 string.
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => {
                let b64 = general_purpose::STANDARD.encode(bytes);
                serde::Serialize::serialize(&b64, s)
            }
            None => s.serialize_none(),
        }
    }

    /// Deserialize an optional Base64 string into bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        opt.map(|s| general_purpose::STANDARD.decode(s.as_bytes()))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
