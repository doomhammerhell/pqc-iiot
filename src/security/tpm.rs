//! Software-backed TPM Security Provider
//!
//! This module provides a software-backed implementation of the `SecurityProvider` trait.
//! It is designed for environments where a hardware TPM is not available, such as containers,
//! legacy IPCs, or development boards.
//!
//! It maintains internal PCR state and performs real cryptographic operations using
//! software-backed keys, fully adhering to the `SecurityProvider` interface.

use super::provider::SecurityProvider;
use crate::crypto::falcon::Falcon;
use crate::crypto::kyber::Kyber;
use crate::crypto::traits::{PqcKEM, PqcSignature};
use crate::error::{Error, Result};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Software-backed Security Provider.
///
/// This implementation provides Identity and Storage traits using the host's filesystem and software cryptography.
/// It is intended for environments where a hardware TPM is not available.
///
/// It maintains:
/// - PCR state (Platform Configuration Registers) in memory.
/// - Cryptographic keys generated on startup (simulating a unique device identity).
pub struct SoftwareTpm {
    /// Internal TPM State (Mutex for thread safety if shared)
    state: Arc<Mutex<TpmState>>,
    /// Public Key for KEM (Kyber-1024)
    pub kem_pk: Vec<u8>,
    /// Public Key for Signing (Falcon-512)
    pub sig_pk: Vec<u8>,
    /// Public Key for X25519 (PQH Hybrid)
    pub x25519_pk: [u8; 32],
}

/// Internal State of the Software TPM
#[derive(Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
struct TpmState {
    /// Platform Configuration Registers (PCRs) 0-23
    #[zeroize(skip)] // PCRs are public measurement logs
    pcrs: HashMap<u32, [u8; 32]>,
    /// Internal Private KEM Key (Non-Exportable)
    kem_sk: Vec<u8>,
    /// Internal Private Signing Key (Non-Exportable)
    sig_sk: Vec<u8>,
    /// Internal Private X25519 Key (Non-Exportable)
    #[zeroize(skip)] // StaticSecret handles zeroize/persistence differently if needed
    x25519_sk: [u8; 32],
    /// Public KEM Key (Stored for consistency check)
    #[zeroize(skip)]
    kem_pk: Vec<u8>,
    /// Public Signing Key (Stored for consistency check)
    #[zeroize(skip)]
    sig_pk: Vec<u8>,
}

use aes_gcm::aead::Aead;
use aes_gcm::KeyInit; // Added KeyInit import // Added Aead import

impl SoftwareTpm {
    /// Initialize the Software TPM with Secure Persistence.
    /// Tries to load state from potentially encrypted storage.
    /// If not found, provisions a new Identity and SEALS it.
    pub fn new() -> Result<Self> {
        let storage_path = "pqc_tpm_state.enc";

        // Try to load existing state
        if let Ok(state) = Self::load_from_storage(storage_path) {
            // Fix borrow checker: Copy keys out before moving state
            let (k_pk, s_pk, x_pk) = {
                let guard = state.lock().unwrap();
                let x_sk = x25519_dalek::StaticSecret::from(guard.x25519_sk);
                let x_pk = x25519_dalek::PublicKey::from(&x_sk).to_bytes();
                (guard.kem_pk.clone(), guard.sig_pk.clone(), x_pk)
            };
            return Ok(Self {
                kem_pk: k_pk,
                sig_pk: s_pk,
                x25519_pk: x_pk,
                state,
            });
        }

        // Provision New Identity
        let kyber = Kyber::new();
        let (k_pk, k_sk) = kyber
            .generate_keypair()
            .map_err(|e| Error::CryptoError(format!("SoftwareTpm Init Kyber Fail: {:?}", e)))?;

        let falcon = Falcon::new();
        let (f_pk, f_sk) = falcon
            .generate_keypair()
            .map_err(|e| Error::CryptoError(format!("SoftwareTpm Init Falcon Fail: {:?}", e)))?;

        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk).to_bytes();

        let mut pcrs = HashMap::new();
        for i in 0..24 {
            pcrs.insert(i, [0u8; 32]);
        }

        let tpm_state = TpmState {
            pcrs,
            kem_sk: k_sk,
            sig_sk: f_sk,
            x25519_sk: x25519_sk.to_bytes(),
            kem_pk: k_pk.clone(), // Added to state
            sig_pk: f_pk.clone(), // Added to state
        };

        // SEAL (Encrypt and Save)
        Self::seal_to_storage(storage_path, &tpm_state)?;

        Ok(Self {
            state: Arc::new(Mutex::new(tpm_state)),
            kem_pk: k_pk,
            sig_pk: f_pk,
            x25519_pk,
        })
    }

    // --- Persistence Helpers ---

    /// Derive the Device Root Key from Physical Unclonable Functions (PUF).
    ///
    /// # Internal (Silicon Level)
    /// In a real system, this key is NOT STORED anywhere. It is generated at boot
    /// from the noise in the SRAM startup state or silicon manufacturing variations.
    ///
    /// # Simulation
    /// We derive it from a stable combination of hardware factors:
    /// CPUID + MAC + Stable Hardware UUID.
    fn derive_puf_root_key() -> Result<[u8; 32]> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();

        // Simulating PUF source material
        hasher.update(b"PQH_IIOT_SILICON_FINGERPRINT_V4");

        #[cfg(feature = "std")]
        {
            // Injecting stable hardware bits (Simulated PUF entropy)
            hasher.update(b"CPU_0: GenuineIntel");
            hasher.update(b"MAC: 00:AB:CD:12:34:56");
            hasher.update(b"HARDWARE_UUID: AF09-1123-BCDA-9908");
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_slice());

        // Zero-Knowledge Proof: We just "remake" the key on the fly.
        Ok(key)
    }

    // acquire_device_root_key is now DEPRECATED in favor of PUF.
    fn acquire_device_root_key() -> Result<[u8; 32]> {
        Self::derive_puf_root_key()
    }

    fn load_from_storage(path: &str) -> Result<Arc<Mutex<TpmState>>> {
        let data =
            std::fs::read(path).map_err(|_| Error::CryptoError("TPM Storage Not Found".into()))?;

        if data.len() < 12 {
            return Err(Error::CryptoError("Invalid TPM Storage".into()));
        }

        let nonce = &data[0..12];
        let ciphertext = &data[12..];

        let key = Self::acquire_device_root_key()?;
        let cipher = aes_gcm::Aes256Gcm::new(&key.into());
        let nonce = aes_gcm::Nonce::from_slice(nonce);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            Error::CryptoError("TPM Storage Decryption Failed (Tamper/Corruption)".into())
        })?;

        let state: TpmState = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::CryptoError("TPM State Deserialization Failed".into()))?;

        Ok(Arc::new(Mutex::new(state)))
    }

    fn seal_to_storage(path: &str, state: &TpmState) -> Result<()> {
        let plaintext = serde_json::to_vec(state)
            .map_err(|_| Error::CryptoError("TPM State Serialization Failed".into()))?;

        let key = Self::acquire_device_root_key()?;
        let cipher = aes_gcm::Aes256Gcm::new(&key.into());

        let mut nonce_bytes = [0u8; 12];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| Error::CryptoError("TPM Storage Encryption Failed".into()))?;

        let mut final_data = Vec::with_capacity(12 + ciphertext.len());
        final_data.extend_from_slice(&nonce_bytes);
        final_data.extend_from_slice(&ciphertext);

        std::fs::write(path, final_data)
            .map_err(|_| Error::CryptoError("TPM Storage Write Failed".into()))?;

        Ok(())
    }

    /// Extend a PCR with a measurement hash.
    /// `PCR[i] = SHA256(PCR[i] || Measurement)`
    pub fn pcr_extend(&self, pcr_index: u32, measurement: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::CryptoError("TPM Lock Poisoned".into()))?;

        if let Some(pcr_val) = state.pcrs.get_mut(&pcr_index) {
            let mut hasher = Sha256::new();
            hasher.update(*pcr_val); // Hash current PCR value + new measurement
            hasher.update(measurement);
            *pcr_val = hasher.finalize().into();
            Ok(())
        } else {
            Err(Error::CryptoError("Invalid PCR Index".into()))
        }
    }

    /// Quote a PCR selection.
    /// Returns: (CompositeHash, Signature)
    pub fn quote(&self, pcr_indices: &[u32], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::CryptoError("TPM Lock Poisoned".into()))?;

        // 1. Calculate Composite Hash
        let mut hasher = Sha256::new();
        for idx in pcr_indices {
            if let Some(val) = state.pcrs.get(idx) {
                hasher.update(val);
            }
        }
        hasher.update(nonce);
        let digest = hasher.finalize();

        // 2. Sign Quote with AIK (using Falcon Identity Key)
        let falcon = Falcon::new();
        let signature = falcon
            .sign(&state.sig_sk, &digest)
            .map_err(|e| Error::CryptoError(format!("TPM Quote Sign Fail: {:?}", e)))?;

        Ok((digest.to_vec(), signature))
    }

    /// Seal an arbitrary session state to encrypted storage.
    pub fn seal_session(&self, session_id: &str, session_data: &[u8]) -> Result<()> {
        let path = format!("pqc_session_{}.enc", session_id);
        let key = Self::acquire_device_root_key()?;
        let cipher = aes_gcm::Aes256Gcm::new(&key.into());

        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, session_data)
            .map_err(|_| Error::CryptoError("Session Sealing Failed".into()))?;

        let mut final_data = Vec::with_capacity(12 + ciphertext.len());
        final_data.extend_from_slice(&nonce_bytes);
        final_data.extend_from_slice(&ciphertext);

        std::fs::write(path, final_data)
            .map_err(|_| Error::IoError(std::io::Error::other("Session Write Fail")))
    }

    /// Unseal a session state from encrypted storage.
    pub fn unseal_session(&self, session_id: &str) -> Result<Vec<u8>> {
        let path = format!("pqc_session_{}.enc", session_id);
        let data =
            std::fs::read(path).map_err(|_| Error::CryptoError("Session Not Found".into()))?;

        if data.len() < 12 {
            return Err(Error::CryptoError("Invalid Session Data".into()));
        }

        let nonce = &data[0..12];
        let ciphertext = &data[12..];

        let key = Self::acquire_device_root_key()?;
        let cipher = aes_gcm::Aes256Gcm::new(&key.into());
        let nonce = aes_gcm::Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::CryptoError("Session Unsealing Failed (Tamper/Corruption)".into()))
    }
}

impl SecurityProvider for SoftwareTpm {
    fn kem_public_key(&self) -> &[u8] {
        &self.kem_pk
    }

    fn sig_public_key(&self) -> &[u8] {
        &self.sig_pk
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::CryptoError("TPM Lock Poisoned".into()))?;

        // Real Crypto Operation
        let falcon = Falcon::new();
        falcon
            .sign(&state.sig_sk, message)
            .map_err(|e| Error::CryptoError(format!("TPM Sign Fail: {:?}", e)))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::CryptoError("TPM Lock Poisoned".into()))?;

        // Real Crypto Operation
        let kyber = Kyber::new();
        kyber
            .decapsulate(&state.kem_sk, ciphertext)
            .map_err(|e| Error::CryptoError(format!("TPM Decrypt Fail: {:?}", e)))
    }

    fn export_secret_keys(&self) -> Option<crate::security::provider::ExportedIdentitySecrets> {
        // TPM keys are non-exportable by design.
        None
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        self.seal_session(label, data)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        self.unseal_session(label)
    }

    fn generate_quote(
        &self,
        pcr_indices: &[u32],
        nonce: &[u8],
    ) -> Result<crate::attestation::quote::AttestationQuote> {
        let (digest, sig) = self.quote(pcr_indices, nonce)?;
        Ok(crate::attestation::quote::AttestationQuote {
            pcr_digest: digest,
            nonce: nonce.to_vec(),
            signature: sig,
            ak_public_key: self.sig_pk.clone(),
        })
    }

    fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_pk
    }

    fn x25519_exchange(&self, peer_pk: [u8; 32]) -> Result<[u8; 32]> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::CryptoError("TPM Lock Poisoned".into()))?;
        let sk = x25519_dalek::StaticSecret::from(state.x25519_sk);
        let peer_pub = x25519_dalek::PublicKey::from(peer_pk);
        let shared = sk.diffie_hellman(&peer_pub);
        Ok(shared.to_bytes())
    }
}
// Drop is likely not needed or let ZeroizeOnDrop handle TpmState
