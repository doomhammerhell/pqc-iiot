//! CRYSTALS-Kyber implementation for post-quantum key encapsulation.
//!
//! This module provides an implementation of the CRYSTALS-Kyber algorithm,
//! a lattice-based key encapsulation mechanism (KEM) that is resistant to
//! quantum computer attacks.

use crate::crypto::traits::{KeyRotation, Metrics, PqcKEM, SecurityLevel};
use crate::error::Error;
use core::fmt;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Security levels for Kyber
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyberSecurityLevel {
    /// Kyber512 - NIST Level 1
    Kyber512,
    /// Kyber768 - NIST Level 3
    Kyber768,
    /// Kyber1024 - NIST Level 5
    Kyber1024,
}

impl fmt::Display for KyberSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KyberSecurityLevel::Kyber512 => write!(f, "Kyber512"),
            KyberSecurityLevel::Kyber768 => write!(f, "Kyber768"),
            KyberSecurityLevel::Kyber1024 => write!(f, "Kyber1024"),
        }
    }
}

/// CRYSTALS-Kyber implementation
pub struct Kyber {
    security_level: KyberSecurityLevel,
    key_rotation_interval: core::time::Duration,
    last_key_generation: std::time::Instant,
    metrics: KyberMetrics,
}

/// Metrics for Kyber operations
#[derive(Default)]
#[allow(dead_code)]
struct KyberMetrics {
    key_generation_time: core::time::Duration,
    encapsulation_time: core::time::Duration,
    decapsulation_time: core::time::Duration,
    operations_count: u64,
}

impl Default for Kyber {
    fn default() -> Self {
        Self::new()
    }
}

impl Kyber {
    /// Create a new Kyber instance with the default security level (Kyber768)
    pub fn new() -> Self {
        Self {
            security_level: KyberSecurityLevel::Kyber768,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: KyberMetrics::default(),
        }
    }

    /// Create a new Kyber instance with a specified security level
    pub fn new_with_level(security_level: KyberSecurityLevel) -> Self {
        Self {
            security_level,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: KyberMetrics::default(),
        }
    }

    /// Set the key rotation interval
    pub fn with_key_rotation_interval(mut self, interval: core::time::Duration) -> Self {
        self.key_rotation_interval = interval;
        self
    }
}

impl PqcKEM for Kyber {
    type Error = Error;

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (pk, sk) = match self.security_level {
            KyberSecurityLevel::Kyber512 => {
                let (pk, sk) = pqcrypto_kyber::kyber512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KyberSecurityLevel::Kyber768 => {
                let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KyberSecurityLevel::Kyber1024 => {
                let (pk, sk) = pqcrypto_kyber::kyber1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        // self.metrics.key_generation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (ss, ct) = match self.security_level {
            KyberSecurityLevel::Kyber512 => {
                let pk = pqcrypto_kyber::kyber512::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber512::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KyberSecurityLevel::Kyber768 => {
                let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber768::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KyberSecurityLevel::Kyber1024 => {
                let pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(pk)
                    .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
                let (ss, ct) = pqcrypto_kyber::kyber1024::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
        };
        // self.metrics.encapsulation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((ct, ss))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // let start = std::time::Instant::now();
        let ss = match self.security_level {
            KyberSecurityLevel::Kyber512 => {
                let sk = pqcrypto_kyber::kyber512::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                let ct = pqcrypto_kyber::kyber512::Ciphertext::from_bytes(ct)
                    .map_err(|e| Error::CryptoError(format!("Invalid ciphertext: {}", e)))?;
                pqcrypto_kyber::kyber512::decapsulate(&ct, &sk)
                    .as_bytes()
                    .to_vec()
            }
            KyberSecurityLevel::Kyber768 => {
                let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ct)
                    .map_err(|e| Error::CryptoError(format!("Invalid ciphertext: {}", e)))?;
                pqcrypto_kyber::kyber768::decapsulate(&ct, &sk)
                    .as_bytes()
                    .to_vec()
            }
            KyberSecurityLevel::Kyber1024 => {
                let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(sk)
                    .map_err(|e| Error::CryptoError(format!("Invalid secret key: {}", e)))?;
                let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ct)
                    .map_err(|e| Error::CryptoError(format!("Invalid ciphertext: {}", e)))?;
                pqcrypto_kyber::kyber1024::decapsulate(&ct, &sk)
                    .as_bytes()
                    .to_vec()
            }
        };
        // self.metrics.decapsulation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(ss)
    }
}

impl SecurityLevel for Kyber {
    fn security_level(&self) -> u32 {
        match self.security_level {
            KyberSecurityLevel::Kyber512 => 1,
            KyberSecurityLevel::Kyber768 => 3,
            KyberSecurityLevel::Kyber1024 => 5,
        }
    }

    fn set_security_level(&mut self, level: u32) -> Result<(), crate::crypto::traits::CryptoError> {
        self.security_level = match level {
            1 => KyberSecurityLevel::Kyber512,
            3 => KyberSecurityLevel::Kyber768,
            5 => KyberSecurityLevel::Kyber1024,
            _ => return Err(crate::crypto::traits::CryptoError::InvalidParameters),
        };
        Ok(())
    }
}

impl KeyRotation for Kyber {
    fn rotate_keys(&mut self) -> Result<(), crate::crypto::traits::CryptoError> {
        self.last_key_generation = std::time::Instant::now();
        Ok(())
    }

    fn time_until_rotation(&self) -> std::time::Duration {
        let elapsed = self.last_key_generation.elapsed();
        if elapsed >= self.key_rotation_interval {
            std::time::Duration::ZERO
        } else {
            self.key_rotation_interval - elapsed
        }
    }
}

impl Metrics for Kyber {
    fn metrics(&self) -> &dyn core::any::Any {
        &self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = KyberMetrics::default();
    }
}
