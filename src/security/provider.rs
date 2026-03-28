use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pqcrypto_falcon::falcon1024::{detached_sign, SecretKey as FalconSecretKey};
use pqcrypto_falcon::falcon512::{
    detached_sign as detached_sign_512, SecretKey as FalconSecretKey512,
};
use pqcrypto_traits::sign::{DetachedSignature, SecretKey as _};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Trait for abstracting cryptographic operations.
/// This allows integrating Hardware Security Modules (HSM), TPMs, or TEEs.
#[derive(Clone, Debug)]
pub struct ExportedIdentitySecrets {
    /// Kyber (KEM) secret key bytes.
    pub kem_sk: Vec<u8>,
    /// Falcon (signature) secret key bytes.
    pub sig_sk: Vec<u8>,
    /// X25519 static secret (classical side of the hybrid scheme).
    pub x25519_sk: [u8; 32],
}

/// Abstract cryptographic provider boundary.
///
/// This trait defines a strict trust boundary: implementors may hold long-term secrets and must
/// protect them against disclosure and misuse. Production deployments are expected to back this
/// with a TPM/HSM/TEE. The software implementation exists for tests and demos.
pub trait SecurityProvider: Send + Sync {
    /// Get the Kyber Public Key (KEM)
    fn kem_public_key(&self) -> &[u8];

    /// Get the Falcon Public Key (Signature)
    fn sig_public_key(&self) -> &[u8];

    /// Decrypt a ciphertext using the internal Kyber Secret Key.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Sign a message using the internal Falcon Secret Key.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Export identity secret keys if allowed by the provider.
    /// Returns None for hardware providers (TPM/HSM).
    fn export_secret_keys(&self) -> Option<ExportedIdentitySecrets>;

    /// Seal data to persistent storage (e.g. encrypted with Root Key if available).
    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()>;

    /// Unseal data from persistent storage.
    fn unseal_data(&self, label: &str) -> Result<Vec<u8>>;

    /// Generate an Attestation Quote.
    fn generate_quote(
        &self,
        pcr_indices: &[u32],
        nonce: &[u8],
    ) -> Result<crate::attestation::quote::AttestationQuote>;

    /// Get X25519 Public Key.
    fn x25519_public_key(&self) -> [u8; 32];

    /// Perform X25519 Key Exchange.
    fn x25519_exchange(&self, peer_pk: [u8; 32]) -> Result<[u8; 32]>;
}

/// Default software-based security provider.
/// Holds keys in memory but uses `Zeroize` to wipe them on drop.
pub struct SoftwareSecurityProvider {
    kyber_sk: zeroize::Zeroizing<Vec<u8>>,
    kyber_pk: Vec<u8>,
    falcon_sk: zeroize::Zeroizing<Vec<u8>>,
    falcon_pk: Vec<u8>,
    x25519_sk: x25519_dalek::StaticSecret,
    exportable: bool,
}

use x25519_dalek::PublicKey as XPublicKey;
use x25519_dalek::StaticSecret;

impl SoftwareSecurityProvider {
    /// Create a new Software (In-Memory) Security Provider.
    ///
    /// The secret keys are wrapped in `Zeroizing` to ensure they are wiped from memory on drop.
    pub fn new(
        kyber_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        falcon_pk: Vec<u8>,
    ) -> Self {
        Self::new_with_export_flag(kyber_sk, kyber_pk, falcon_sk, falcon_pk, None, false)
    }

    /// Create a provider that allows secret key export (needed for identity persistence).
    /// Prefer using encrypted persistence; keep this opt-in.
    pub fn new_exportable(
        kyber_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        falcon_pk: Vec<u8>,
    ) -> Self {
        Self::new_with_export_flag(kyber_sk, kyber_pk, falcon_sk, falcon_pk, None, true)
    }

    /// Create a provider that pins a persisted X25519 static secret.
    pub fn new_exportable_with_x25519(
        kyber_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        falcon_pk: Vec<u8>,
        x25519_sk: [u8; 32],
    ) -> Self {
        Self::new_with_export_flag(
            kyber_sk,
            kyber_pk,
            falcon_sk,
            falcon_pk,
            Some(x25519_sk),
            true,
        )
    }

    /// Create a provider with a caller-supplied X25519 static secret, without enabling key export.
    pub fn new_with_x25519(
        kyber_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        falcon_pk: Vec<u8>,
        x25519_sk: [u8; 32],
    ) -> Self {
        Self::new_with_export_flag(
            kyber_sk,
            kyber_pk,
            falcon_sk,
            falcon_pk,
            Some(x25519_sk),
            false,
        )
    }

    fn new_with_export_flag(
        kyber_sk: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_sk: Vec<u8>,
        falcon_pk: Vec<u8>,
        x25519_sk: Option<[u8; 32]>,
        exportable: bool,
    ) -> Self {
        Self {
            kyber_sk: zeroize::Zeroizing::new(kyber_sk),
            kyber_pk,
            falcon_sk: zeroize::Zeroizing::new(falcon_sk),
            falcon_pk,
            x25519_sk: match x25519_sk {
                Some(bytes) => StaticSecret::from(bytes),
                None => StaticSecret::random_from_rng(rand_core::OsRng),
            },
            exportable,
        }
    }

    fn sealing_key(&self, label: &str) -> aes_gcm::Key<Aes256Gcm> {
        let mut hasher = Sha256::new();
        hasher.update(&self.falcon_sk);
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        *aes_gcm::Key::<Aes256Gcm>::from_slice(&digest)
    }
}

impl SecurityProvider for SoftwareSecurityProvider {
    fn kem_public_key(&self) -> &[u8] {
        &self.kyber_pk
    }

    fn sig_public_key(&self) -> &[u8] {
        &self.falcon_pk
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Hybrid decrypt (v1 Kyber+X25519; legacy Kyber-only supported for transition).
        crate::security::hybrid::decrypt_with_exchange(&self.kyber_sk, ciphertext, |peer_pk| {
            self.x25519_exchange(peer_pk)
        })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        if self.falcon_sk.len() == 1281 {
            let sk = FalconSecretKey512::from_bytes(&self.falcon_sk)
                .map_err(|e| Error::CryptoError(format!("Invalid Falcon-512 SK: {}", e)))?;
            let signature = detached_sign_512(message, &sk);
            return Ok(signature.as_bytes().to_vec());
        }

        let sk = FalconSecretKey::from_bytes(&self.falcon_sk).map_err(|e| {
            Error::CryptoError(format!(
                "Invalid Falcon-1024 SK lengths {}: {}",
                self.falcon_sk.len(),
                e
            ))
        })?;
        let signature = detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    fn export_secret_keys(&self) -> Option<ExportedIdentitySecrets> {
        if self.exportable {
            Some(ExportedIdentitySecrets {
                kem_sk: (*self.kyber_sk).clone(),
                sig_sk: (*self.falcon_sk).clone(),
                x25519_sk: self.x25519_sk.to_bytes(),
            })
        } else {
            None
        }
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        let path = format!("pqc_sealed_{}.bin", label);
        let key = self.sealing_key(label);
        let cipher = Aes256Gcm::new(&key);
        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| crate::Error::CryptoError("Seal encryption failed".into()))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        std::fs::write(path, out).map_err(crate::Error::IoError)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        let path = format!("pqc_sealed_{}.bin", label);
        let blob = std::fs::read(path)
            .map_err(|_| crate::Error::CryptoError("Sealed data not found".into()))?;
        if blob.len() < 12 {
            return Err(crate::Error::CryptoError("Sealed data too short".into()));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let key = self.sealing_key(label);
        let cipher = Aes256Gcm::new(&key);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| crate::Error::CryptoError("Sealed data authentication failed".into()))
    }

    fn generate_quote(
        &self,
        _pcr_indices: &[u32],
        nonce: &[u8],
    ) -> Result<crate::attestation::quote::AttestationQuote> {
        // Software provider uses empty PCRs (all zeros) for the demo snapshot.
        // We still sign the quote to keep the verification chain functional.
        use sha2::{Digest, Sha256};
        let pcr_digest = vec![0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&pcr_digest);
        hasher.update(nonce);
        let digest = hasher.finalize();
        let signature = self.sign(digest.as_slice())?;
        Ok(crate::attestation::quote::AttestationQuote {
            pcr_digest,
            nonce: nonce.to_vec(),
            signature,
            ak_public_key: self.falcon_pk.clone(),
        })
    }

    fn x25519_public_key(&self) -> [u8; 32] {
        XPublicKey::from(&self.x25519_sk).to_bytes()
    }

    fn x25519_exchange(&self, peer_pk: [u8; 32]) -> Result<[u8; 32]> {
        let peer_pub = XPublicKey::from(peer_pk);
        let shared = self.x25519_sk.diffie_hellman(&peer_pub);
        Ok(shared.to_bytes())
    }
}

#[cfg(all(test, feature = "kyber", feature = "falcon"))]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_export_gating() {
        use crate::crypto::falcon::Falcon;
        use crate::crypto::kyber::Kyber;
        use crate::crypto::traits::{PqcKEM, PqcSignature};

        let kyber = Kyber::new();
        let (kyber_pk, kyber_sk) = kyber.generate_keypair().expect("kyber keygen");

        let falcon = Falcon::new();
        let (falcon_pk, falcon_sk) = falcon.generate_keypair().expect("falcon keygen");

        let provider = SoftwareSecurityProvider::new(
            kyber_sk.clone(),
            kyber_pk.clone(),
            falcon_sk.clone(),
            falcon_pk.clone(),
        );

        assert!(provider.export_secret_keys().is_none());

        let exportable =
            SoftwareSecurityProvider::new_exportable(kyber_sk, kyber_pk, falcon_sk, falcon_pk);
        assert!(exportable.export_secret_keys().is_some());

        let label = format!("seal_test_{}", rand::random::<u32>());
        let data = b"pqc-iiot-sealed-data";

        provider.seal_data(&label, data).expect("seal_data");
        let out = provider.unseal_data(&label).expect("unseal_data");
        assert_eq!(out, data);

        let path = format!("pqc_sealed_{}.bin", label);
        let blob = std::fs::read(&path).expect("read sealed blob");
        assert_eq!(blob.len(), 12 + data.len() + 16);
        std::fs::remove_file(&path).expect("cleanup");
    }
}
