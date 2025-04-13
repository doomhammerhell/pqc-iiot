use core::fmt;
use heapless::Vec;
use pqc_saber::{
    Saber as PqcSaber, SaberKeypair, SaberPublicKey, SaberSecretKey, SaberSharedSecret,
};
use zeroize::Zeroize;

use crate::error::CryptoError;

/// SABER security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaberSecurityLevel {
    /// LightSaber (lightest)
    LightSaber,
    /// Saber (recommended)
    Saber,
    /// FireSaber (highest security)
    FireSaber,
}

impl fmt::Display for SaberSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaberSecurityLevel::LightSaber => write!(f, "LightSaber"),
            SaberSecurityLevel::Saber => write!(f, "Saber"),
            SaberSecurityLevel::FireSaber => write!(f, "FireSaber"),
        }
    }
}

/// SABER key pair
#[derive(Clone)]
pub struct SaberKeyPair {
    public_key: SaberPublicKey,
    secret_key: SaberSecretKey,
}

impl SaberKeyPair {
    /// Create a new SABER key pair with the specified security level
    pub fn new(level: SaberSecurityLevel) -> Result<Self, CryptoError> {
        let keypair = match level {
            SaberSecurityLevel::LightSaber => PqcSaber::generate_keypair_lightsaber(),
            SaberSecurityLevel::Saber => PqcSaber::generate_keypair_saber(),
            SaberSecurityLevel::FireSaber => PqcSaber::generate_keypair_firesaber(),
        };

        Ok(Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &SaberPublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &SaberSecretKey {
        &self.secret_key
    }
}

impl Drop for SaberKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// SABER KEM implementation
pub struct Saber {
    level: SaberSecurityLevel,
}

impl Saber {
    /// Create a new SABER instance with the specified security level
    pub fn new(level: SaberSecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<SaberKeyPair, CryptoError> {
        SaberKeyPair::new(self.level)
    }

    /// Encapsulate a shared secret
    pub fn encapsulate(
        &self,
        public_key: &SaberPublicKey,
    ) -> Result<(Vec<u8, 992>, Vec<u8, 32>), CryptoError> {
        let (ciphertext, shared_secret) = match self.level {
            SaberSecurityLevel::LightSaber => PqcSaber::encapsulate_lightsaber(public_key),
            SaberSecurityLevel::Saber => PqcSaber::encapsulate_saber(public_key),
            SaberSecurityLevel::FireSaber => PqcSaber::encapsulate_firesaber(public_key),
        };

        Ok((
            Vec::from_slice(&ciphertext).map_err(|_| CryptoError::EncapsulationError)?,
            Vec::from_slice(&shared_secret).map_err(|_| CryptoError::EncapsulationError)?,
        ))
    }

    /// Decapsulate a shared secret
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &SaberSecretKey,
    ) -> Result<Vec<u8, 32>, CryptoError> {
        let shared_secret = match self.level {
            SaberSecurityLevel::LightSaber => PqcSaber::decapsulate_lightsaber(ciphertext, secret_key),
            SaberSecurityLevel::Saber => PqcSaber::decapsulate_saber(ciphertext, secret_key),
            SaberSecurityLevel::FireSaber => PqcSaber::decapsulate_firesaber(ciphertext, secret_key),
        };

        Ok(Vec::from_slice(&shared_secret).map_err(|_| CryptoError::DecapsulationError)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saber_keypair_generation() {
        let saber = Saber::new(SaberSecurityLevel::Saber);
        let keypair = saber.generate_keypair().unwrap();
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());
    }

    #[test]
    fn test_saber_encapsulation() {
        let saber = Saber::new(SaberSecurityLevel::Saber);
        let keypair = saber.generate_keypair().unwrap();
        
        let (ciphertext, shared_secret1) = saber.encapsulate(keypair.public_key()).unwrap();
        let shared_secret2 = saber.decapsulate(&ciphertext, keypair.secret_key()).unwrap();
        
        assert_eq!(shared_secret1, shared_secret2);
    }
} 