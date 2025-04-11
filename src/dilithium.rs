use core::fmt;
use heapless::Vec;
use pqc_dilithium::{
    Dilithium as PqcDilithium, DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey,
    DilithiumSignature,
};
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Dilithium security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DilithiumSecurityLevel {
    /// Level 2 (recommended)
    Level2,
    /// Level 3 (higher security)
    Level3,
    /// Level 5 (highest security)
    Level5,
}

impl fmt::Display for DilithiumSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DilithiumSecurityLevel::Level2 => write!(f, "Level 2"),
            DilithiumSecurityLevel::Level3 => write!(f, "Level 3"),
            DilithiumSecurityLevel::Level5 => write!(f, "Level 5"),
        }
    }
}

/// Dilithium key pair
#[derive(Clone)]
pub struct DilithiumKeyPair {
    public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,
}

impl DilithiumKeyPair {
    /// Create a new Dilithium key pair with the specified security level
    pub fn new(level: DilithiumSecurityLevel) -> Result<Self, CryptoError> {
        let keypair = match level {
            DilithiumSecurityLevel::Level2 => PqcDilithium::generate_keypair_level2(),
            DilithiumSecurityLevel::Level3 => PqcDilithium::generate_keypair_level3(),
            DilithiumSecurityLevel::Level5 => PqcDilithium::generate_keypair_level5(),
        };

        Ok(Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &DilithiumSecretKey {
        &self.secret_key
    }
}

impl Drop for DilithiumKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Dilithium signature implementation
pub struct Dilithium {
    level: DilithiumSecurityLevel,
}

impl Dilithium {
    /// Create a new Dilithium instance with the specified security level
    pub fn new(level: DilithiumSecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<DilithiumKeyPair, CryptoError> {
        DilithiumKeyPair::new(self.level)
    }

    /// Sign a message
    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &DilithiumSecretKey,
    ) -> Result<Vec<u8, 2420>, CryptoError> {
        let signature = match self.level {
            DilithiumSecurityLevel::Level2 => PqcDilithium::sign_level2(message, secret_key),
            DilithiumSecurityLevel::Level3 => PqcDilithium::sign_level3(message, secret_key),
            DilithiumSecurityLevel::Level5 => PqcDilithium::sign_level5(message, secret_key),
        };

        Ok(Vec::from_slice(&signature).map_err(|_| CryptoError::SignatureError)?)
    }

    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &DilithiumPublicKey,
    ) -> Result<bool, CryptoError> {
        let result = match self.level {
            DilithiumSecurityLevel::Level2 => {
                PqcDilithium::verify_level2(message, signature, public_key)
            }
            DilithiumSecurityLevel::Level3 => {
                PqcDilithium::verify_level3(message, signature, public_key)
            }
            DilithiumSecurityLevel::Level5 => {
                PqcDilithium::verify_level5(message, signature, public_key)
            }
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_keypair_generation() {
        let dilithium = Dilithium::new(DilithiumSecurityLevel::Level2);
        let keypair = dilithium.generate_keypair().unwrap();
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());
    }

    #[test]
    fn test_dilithium_sign_verify() {
        let dilithium = Dilithium::new(DilithiumSecurityLevel::Level2);
        let keypair = dilithium.generate_keypair().unwrap();
        let message = b"Test message";
        
        let signature = dilithium.sign(message, keypair.secret_key()).unwrap();
        let verified = dilithium.verify(message, &signature, keypair.public_key()).unwrap();
        
        assert!(verified);
    }
} 