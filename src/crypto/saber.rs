//! SABER implementation for post-quantum key encapsulation.
//!
//! This module provides an implementation of the SABER algorithm,
//! a lattice-based key encapsulation mechanism (KEM) that is resistant to
//! quantum computer attacks.

use crate::crypto::traits::{KeyRotation, Metrics, PqcKEM, SecurityLevel};
use crate::error::Error;
use core::fmt;
use pqcrypto_saber::{firesaber, lightsaber, saber};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

/// Security levels for SABER
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaberSecurityLevel {
    /// LightSaber - NIST Level 1
    LightSaber,
    /// Saber - NIST Level 3
    Saber,
    /// FireSaber - NIST Level 5
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

/// SABER implementation
pub struct Saber {
    security_level: SaberSecurityLevel,
    key_rotation_interval: core::time::Duration,
    last_key_generation: std::time::Instant,
    metrics: SaberMetrics,
}

/// Metrics for SABER operations
#[derive(Default)]
struct SaberMetrics {
    key_generation_time: core::time::Duration,
    encapsulation_time: core::time::Duration,
    decapsulation_time: core::time::Duration,
    operations_count: u64,
}

impl Saber {
    /// Create a new SABER instance with the default security level (Saber)
    pub fn new() -> Self {
        Self {
            security_level: SaberSecurityLevel::Saber,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: SaberMetrics::default(),
        }
    }

    /// Create a new SABER instance with a specified security level
    pub fn new_with_level(security_level: SaberSecurityLevel) -> Self {
        Self {
            security_level,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: SaberMetrics::default(),
        }
    }

    /// Set the key rotation interval
    pub fn with_key_rotation_interval(mut self, interval: core::time::Duration) -> Self {
        self.key_rotation_interval = interval;
        self
    }
}

impl PqcKEM for Saber {
    type Error = Error;

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (pk, sk) = match self.security_level {
            SaberSecurityLevel::LightSaber => {
                let (pk, sk) = lightsaber::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SaberSecurityLevel::Saber => {
                let (pk, sk) = saber::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SaberSecurityLevel::FireSaber => {
                let (pk, sk) = firesaber::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        // self.metrics.key_generation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        // let start = std::time::Instant::now();
        let (ct, ss) = match self.security_level {
            SaberSecurityLevel::LightSaber => {
                let pk = lightsaber::PublicKey::from_bytes(pk)
                    .map_err(|_| Error::CryptoError("Invalid public key".to_string()))?;
                let (ct, ss) = lightsaber::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            SaberSecurityLevel::Saber => {
                let pk = saber::PublicKey::from_bytes(pk)
                    .map_err(|_| Error::CryptoError("Invalid public key".to_string()))?;
                let (ct, ss) = saber::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            SaberSecurityLevel::FireSaber => {
                let pk = firesaber::PublicKey::from_bytes(pk)
                    .map_err(|_| Error::CryptoError("Invalid public key".to_string()))?;
                let (ct, ss) = firesaber::encapsulate(&pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
        };
        // self.metrics.encapsulation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok((ct, ss))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // let start = std::time::Instant::now();
        let ss = match self.security_level {
            SaberSecurityLevel::LightSaber => {
                let sk = lightsaber::SecretKey::from_bytes(sk)
                    .map_err(|_| Error::CryptoError("Invalid secret key".to_string()))?;
                let ct = lightsaber::Ciphertext::from_bytes(ct)
                    .map_err(|_| Error::CryptoError("Invalid ciphertext".to_string()))?;
                let ss = lightsaber::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            SaberSecurityLevel::Saber => {
                let sk = saber::SecretKey::from_bytes(sk)
                    .map_err(|_| Error::CryptoError("Invalid secret key".to_string()))?;
                let ct = saber::Ciphertext::from_bytes(ct)
                    .map_err(|_| Error::CryptoError("Invalid ciphertext".to_string()))?;
                let ss = saber::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            SaberSecurityLevel::FireSaber => {
                let sk = firesaber::SecretKey::from_bytes(sk)
                    .map_err(|_| Error::CryptoError("Invalid secret key".to_string()))?;
                let ct = firesaber::Ciphertext::from_bytes(ct)
                    .map_err(|_| Error::CryptoError("Invalid ciphertext".to_string()))?;
                let ss = firesaber::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
        };
        // self.metrics.decapsulation_time = start.elapsed();
        // self.metrics.operations_count += 1;
        Ok(ss)
    }
}

impl SecurityLevel for Saber {
    fn security_level(&self) -> u32 {
        match self.security_level {
            SaberSecurityLevel::LightSaber => 1,
            SaberSecurityLevel::Saber => 3,
            SaberSecurityLevel::FireSaber => 5,
        }
    }

    fn set_security_level(&mut self, level: u32) -> Result<(), crate::crypto::traits::CryptoError> {
        self.security_level = match level {
            1 => SaberSecurityLevel::LightSaber,
            3 => SaberSecurityLevel::Saber,
            5 => SaberSecurityLevel::FireSaber,
            _ => return Err(crate::crypto::traits::CryptoError::InvalidParameters),
        };
        Ok(())
    }
}

impl KeyRotation for Saber {
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

impl Metrics for Saber {
    fn metrics(&self) -> &dyn core::any::Any {
        &self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = SaberMetrics::default();
    }
}
