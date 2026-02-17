//! Falcon implementation for post-quantum digital signatures.
//!
//! This module provides an implementation of the Falcon algorithm,
//! a lattice-based digital signature scheme that is resistant to
//! quantum computer attacks.

use crate::crypto::traits::{KeyRotation, Metrics, PqcSignature, SecurityLevel};
use crate::error::Error;
use core::fmt;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// Security levels for Falcon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconSecurityLevel {
    /// Falcon512 - NIST Level 1
    Falcon512,
    /// Falcon1024 - NIST Level 5
    Falcon1024,
}

impl fmt::Display for FalconSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalconSecurityLevel::Falcon512 => write!(f, "Falcon512"),
            FalconSecurityLevel::Falcon1024 => write!(f, "Falcon1024"),
        }
    }
}

/// Falcon implementation
pub struct Falcon {
    security_level: FalconSecurityLevel,
    key_rotation_interval: core::time::Duration,
    last_key_generation: std::time::Instant,
    metrics: FalconMetrics,
}

/// Metrics for Falcon operations
#[derive(Default)]
#[allow(dead_code)]
struct FalconMetrics {
    key_generation_time: core::time::Duration,
    signing_time: core::time::Duration,
    verification_time: core::time::Duration,
    operations_count: u64,
}

impl Default for Falcon {
    fn default() -> Self {
        Self::new()
    }
}

impl Falcon {
    /// Create a new Falcon instance with the default security level (Falcon512)
    pub fn new() -> Self {
        Self {
            security_level: FalconSecurityLevel::Falcon512,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: FalconMetrics::default(),
        }
    }

    /// Create a new Falcon instance with a specified security level
    pub fn new_with_level(security_level: FalconSecurityLevel) -> Self {
        Self {
            security_level,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: FalconMetrics::default(),
        }
    }
}

impl PqcSignature for Falcon {
    type Error = Error;

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (pk, sk) = match self.security_level {
            FalconSecurityLevel::Falcon512 => {
                let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            FalconSecurityLevel::Falcon1024 => {
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        // self.metrics.key_generation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((pk, sk))
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // let start = std::time::Instant::now();
        let signature = match self.security_level {
            FalconSecurityLevel::Falcon512 => {
                let sk = pqcrypto_falcon::falcon512::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                pqcrypto_falcon::falcon512::detached_sign(msg, &sk)
                    .as_bytes()
                    .to_vec()
            }
            FalconSecurityLevel::Falcon1024 => {
                let sk = pqcrypto_falcon::falcon1024::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                pqcrypto_falcon::falcon1024::detached_sign(msg, &sk)
                    .as_bytes()
                    .to_vec()
            }
        };
        // self.metrics.signing_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(signature)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error> {
        // let start = std::time::Instant::now();
        let result = match self.security_level {
            FalconSecurityLevel::Falcon512 => {
                let pk = pqcrypto_falcon::falcon512::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let sig = pqcrypto_falcon::falcon512::DetachedSignature::from_bytes(sig)
                    .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
                pqcrypto_falcon::falcon512::verify_detached_signature(&sig, msg, &pk).is_ok()
            }
            FalconSecurityLevel::Falcon1024 => {
                let pk = pqcrypto_falcon::falcon1024::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let sig = pqcrypto_falcon::falcon1024::DetachedSignature::from_bytes(sig)
                    .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
                pqcrypto_falcon::falcon1024::verify_detached_signature(&sig, msg, &pk).is_ok()
            }
        };
        // self.metrics.verification_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(result)
    }
}

impl SecurityLevel for Falcon {
    fn security_level(&self) -> u32 {
        match self.security_level {
            FalconSecurityLevel::Falcon512 => 1,
            FalconSecurityLevel::Falcon1024 => 5,
        }
    }

    fn set_security_level(&mut self, level: u32) -> Result<(), crate::crypto::traits::CryptoError> {
        self.security_level = match level {
            1 => FalconSecurityLevel::Falcon512,
            5 => FalconSecurityLevel::Falcon1024,
            _ => return Err(crate::crypto::traits::CryptoError::InvalidParameters),
        };
        Ok(())
    }
}

impl KeyRotation for Falcon {
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

impl Metrics for Falcon {
    fn metrics(&self) -> &dyn core::any::Any {
        &self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = FalconMetrics::default();
    }
}
