//! Dilithium implementation for post-quantum digital signatures.
//!
//! This module provides an implementation of the Dilithium algorithm,
//! a lattice-based digital signature scheme that is resistant to
//! quantum computer attacks.

use crate::crypto::traits::{KeyRotation, Metrics, PqcSignature, SecurityLevel};
use crate::error::Error;
use core::fmt;
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// Security levels for Dilithium
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DilithiumSecurityLevel {
    /// Dilithium2 - NIST Level 2
    Level2,
    /// Dilithium3 - NIST Level 3
    Level3,
    /// Dilithium5 - NIST Level 5
    Level5,
}

impl fmt::Display for DilithiumSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DilithiumSecurityLevel::Level2 => write!(f, "Dilithium2"),
            DilithiumSecurityLevel::Level3 => write!(f, "Dilithium3"),
            DilithiumSecurityLevel::Level5 => write!(f, "Dilithium5"),
        }
    }
}

/// Dilithium implementation
pub struct Dilithium {
    security_level: DilithiumSecurityLevel,
    key_rotation_interval: core::time::Duration,
    last_key_generation: std::time::Instant,
    metrics: DilithiumMetrics,
}

/// Metrics for Dilithium operations
#[derive(Default)]
struct DilithiumMetrics {
    key_generation_time: core::time::Duration,
    signing_time: core::time::Duration,
    verification_time: core::time::Duration,
    operations_count: u64,
}

impl Dilithium {
    /// Create a new Dilithium instance with the default security level (Level3)
    pub fn new() -> Self {
        Self {
            security_level: DilithiumSecurityLevel::Level3,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: DilithiumMetrics::default(),
        }
    }

    /// Create a new Dilithium instance with a specified security level
    pub fn new_with_level(security_level: DilithiumSecurityLevel) -> Self {
        Self {
            security_level,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: DilithiumMetrics::default(),
        }
    }

    pub fn with_key_rotation_interval(mut self, interval: core::time::Duration) -> Self {
        self.key_rotation_interval = interval;
        self
    }
}

impl PqcSignature for Dilithium {
    type Error = Error;

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (pk, sk) = match self.security_level {
            DilithiumSecurityLevel::Level2 => {
                let (pk, sk) = dilithium2::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            DilithiumSecurityLevel::Level3 => {
                let (pk, sk) = dilithium3::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            DilithiumSecurityLevel::Level5 => {
                let (pk, sk) = dilithium5::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        // self.metrics.key_generation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((pk, sk))
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let start = std::time::Instant::now();
        // Need to construct SecretKey from bytes.
        // Assuming Keypair or SecretKey struct has from_bytes/from_slice.
        // pqc_dilithium likely uses `SecretKey::from_bytes`.
        // Also assuming `sign` method on SecretKey or detached_sign.

        let signature = match self.security_level {
            DilithiumSecurityLevel::Level2 => {
                let sk = dilithium2::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                dilithium2::detached_sign(msg, &sk).as_bytes().to_vec()
            }
            DilithiumSecurityLevel::Level3 => {
                let sk = dilithium3::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                dilithium3::detached_sign(msg, &sk).as_bytes().to_vec()
            }
            DilithiumSecurityLevel::Level5 => {
                let sk = dilithium5::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                dilithium5::detached_sign(msg, &sk).as_bytes().to_vec()
            }
        };
        // self.metrics.signing_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(signature)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error> {
        let start = std::time::Instant::now();
        let result = match self.security_level {
            DilithiumSecurityLevel::Level2 => {
                let pk = dilithium2::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let sig = dilithium2::DetachedSignature::from_bytes(sig)
                    .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
                dilithium2::verify_detached_signature(&sig, msg, &pk).is_ok()
            }
            DilithiumSecurityLevel::Level3 => {
                let pk = dilithium3::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let sig = dilithium3::DetachedSignature::from_bytes(sig)
                    .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
                dilithium3::verify_detached_signature(&sig, msg, &pk).is_ok()
            }
            DilithiumSecurityLevel::Level5 => {
                let pk = dilithium5::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let sig = dilithium5::DetachedSignature::from_bytes(sig)
                    .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
                dilithium5::verify_detached_signature(&sig, msg, &pk).is_ok()
            }
        };
        // self.metrics.verification_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(result)
    }
}

impl SecurityLevel for Dilithium {
    fn security_level(&self) -> u32 {
        match self.security_level {
            DilithiumSecurityLevel::Level2 => 2,
            DilithiumSecurityLevel::Level3 => 3,
            DilithiumSecurityLevel::Level5 => 5,
        }
    }

    fn set_security_level(&mut self, level: u32) -> Result<(), crate::crypto::traits::CryptoError> {
        self.security_level = match level {
            2 => DilithiumSecurityLevel::Level2,
            3 => DilithiumSecurityLevel::Level3,
            5 => DilithiumSecurityLevel::Level5,
            _ => return Err(crate::crypto::traits::CryptoError::InvalidParameters),
        };
        Ok(())
    }
}

impl KeyRotation for Dilithium {
    fn rotate_keys(&mut self) -> Result<(), crate::crypto::traits::CryptoError> {
        self.last_key_generation = std::time::Instant::now();
        Ok(())
    }

    fn time_until_rotation(&self) -> core::time::Duration {
        let elapsed = self.last_key_generation.elapsed();
        if elapsed >= self.key_rotation_interval {
            core::time::Duration::ZERO
        } else {
            self.key_rotation_interval - elapsed
        }
    }
}

impl Metrics for Dilithium {
    fn metrics(&self) -> &dyn core::any::Any {
        &self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = DilithiumMetrics::default();
    }
}
