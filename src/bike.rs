use core::fmt;
use heapless::Vec;
use pqc_bike::{
    Bike as PqcBike, BikeKeypair, BikePublicKey, BikeSecretKey, BikeSharedSecret,
};
use zeroize::Zeroize;

use crate::error::CryptoError;

/// BIKE security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BikeSecurityLevel {
    /// Level 1 (lightest)
    Level1,
    /// Level 3 (recommended)
    Level3,
    /// Level 5 (highest security)
    Level5,
}

impl fmt::Display for BikeSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BikeSecurityLevel::Level1 => write!(f, "Level 1"),
            BikeSecurityLevel::Level3 => write!(f, "Level 3"),
            BikeSecurityLevel::Level5 => write!(f, "Level 5"),
        }
    }
}

/// BIKE key pair
#[derive(Clone)]
pub struct BikeKeyPair {
    public_key: BikePublicKey,
    secret_key: BikeSecretKey,
}

impl BikeKeyPair {
    /// Create a new BIKE key pair with the specified security level
    pub fn new(level: BikeSecurityLevel) -> Result<Self, CryptoError> {
        let keypair = match level {
            BikeSecurityLevel::Level1 => PqcBike::generate_keypair_level1(),
            BikeSecurityLevel::Level3 => PqcBike::generate_keypair_level3(),
            BikeSecurityLevel::Level5 => PqcBike::generate_keypair_level5(),
        };

        Ok(Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &BikePublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &BikeSecretKey {
        &self.secret_key
    }
}

impl Drop for BikeKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// BIKE KEM implementation
pub struct Bike {
    level: BikeSecurityLevel,
}

impl Bike {
    /// Create a new BIKE instance with the specified security level
    pub fn new(level: BikeSecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<BikeKeyPair, CryptoError> {
        BikeKeyPair::new(self.level)
    }

    /// Encapsulate a shared secret
    pub fn encapsulate(
        &self,
        public_key: &BikePublicKey,
    ) -> Result<(Vec<u8, 1232>, Vec<u8, 32>), CryptoError> {
        let (ciphertext, shared_secret) = match self.level {
            BikeSecurityLevel::Level1 => PqcBike::encapsulate_level1(public_key),
            BikeSecurityLevel::Level3 => PqcBike::encapsulate_level3(public_key),
            BikeSecurityLevel::Level5 => PqcBike::encapsulate_level5(public_key),
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
        secret_key: &BikeSecretKey,
    ) -> Result<Vec<u8, 32>, CryptoError> {
        let shared_secret = match self.level {
            BikeSecurityLevel::Level1 => PqcBike::decapsulate_level1(ciphertext, secret_key),
            BikeSecurityLevel::Level3 => PqcBike::decapsulate_level3(ciphertext, secret_key),
            BikeSecurityLevel::Level5 => PqcBike::decapsulate_level5(ciphertext, secret_key),
        };

        Ok(Vec::from_slice(&shared_secret).map_err(|_| CryptoError::DecapsulationError)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bike_keypair_generation() {
        let bike = Bike::new(BikeSecurityLevel::Level3);
        let keypair = bike.generate_keypair().unwrap();
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());
    }

    #[test]
    fn test_bike_encapsulation() {
        let bike = Bike::new(BikeSecurityLevel::Level3);
        let keypair = bike.generate_keypair().unwrap();
        
        let (ciphertext, shared_secret1) = bike.encapsulate(keypair.public_key()).unwrap();
        let shared_secret2 = bike.decapsulate(&ciphertext, keypair.secret_key()).unwrap();
        
        assert_eq!(shared_secret1, shared_secret2);
    }
} 