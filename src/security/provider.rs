use crate::{Error, Result};
use pqcrypto_falcon::falcon1024::{detached_sign, SecretKey as FalconSecretKey};
use pqcrypto_falcon::falcon512::{
    detached_sign as detached_sign_512, SecretKey as FalconSecretKey512,
};
use pqcrypto_kyber::kyber1024::{
    ciphertext_bytes as kyber_ct_size, decapsulate, Ciphertext as KyberCiphertext,
    SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret};
use pqcrypto_traits::sign::{DetachedSignature, SecretKey as _};


/// Trait for abstracting cryptographic operations.
/// This allows integrating Hardware Security Modules (HSM), TPMs, or TEEs.
pub trait SecurityProvider: Send + Sync {
    /// Get the Kyber Public Key (KEM)
    fn kem_public_key(&self) -> &[u8];

    /// Get the Falcon Public Key (Signature)
    fn sig_public_key(&self) -> &[u8];

    /// Decrypt a ciphertext using the internal Kyber Secret Key.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Sign a message using the internal Falcon Secret Key.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Export secret keys (Kyber SK, Falcon SK) if allowed by the provider.
    /// Returns None for hardware providers (TPM/HSM).
    fn export_secret_keys(&self) -> Option<(Vec<u8>, Vec<u8>)>;
}

/// Default software-based security provider.
/// Holds keys in memory but uses `Zeroize` to wipe them on drop.
pub struct SoftwareSecurityProvider {
    kyber_sk: zeroize::Zeroizing<Vec<u8>>,
    kyber_pk: Vec<u8>,
    falcon_sk: zeroize::Zeroizing<Vec<u8>>,
    falcon_pk: Vec<u8>,
}

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
        Self {
            kyber_sk: zeroize::Zeroizing::new(kyber_sk),
            kyber_pk,
            falcon_sk: zeroize::Zeroizing::new(falcon_sk),
            falcon_pk,
        }
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
        if ciphertext.len() != kyber_ct_size() {
            return Err(Error::CryptoError(
                "Invalid Kyber ciphertext length".to_string(),
            ));
        }

        let sk = KyberSecretKey::from_bytes(&self.kyber_sk)
            .map_err(|e| Error::CryptoError(format!("Invalid Kyber SK: {}", e)))?;
        let ct = KyberCiphertext::from_bytes(ciphertext)
            .map_err(|e| Error::CryptoError(format!("Invalid Kyber CT: {}", e)))?;

        let shared_secret = decapsulate(&ct, &sk);
        Ok(shared_secret.as_bytes().to_vec())
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

    fn export_secret_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        Some(((*self.kyber_sk).clone(), (*self.falcon_sk).clone()))
    }
}
