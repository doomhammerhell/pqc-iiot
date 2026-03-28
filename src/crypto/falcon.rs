//! Falcon implementation for post-quantum digital signatures.
//!
//! This module provides an implementation of the Falcon algorithm,
//! a lattice-based digital signature scheme that is resistant to
//! quantum computer attacks.

#[cfg(feature = "std")]
use crate::crypto::traits::KeyRotation;
use crate::crypto::traits::{Metrics, PqcSignature, SecurityLevel};
use crate::error::Error;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "falcon-pqclean")]
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
    #[cfg(feature = "std")]
    rotation: KeyRotationState,
    metrics: FalconMetrics,
}

#[cfg(feature = "std")]
#[derive(Clone)]
struct KeyRotationState {
    key_rotation_interval: core::time::Duration,
    last_key_generation: std::time::Instant,
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
        Self::new_with_level(FalconSecurityLevel::Falcon512)
    }

    /// Create a new Falcon instance with a specified security level
    pub fn new_with_level(security_level: FalconSecurityLevel) -> Self {
        Self {
            security_level,
            #[cfg(feature = "std")]
            rotation: KeyRotationState {
                key_rotation_interval: core::time::Duration::from_secs(3600),
                last_key_generation: std::time::Instant::now(),
            },
            metrics: FalconMetrics::default(),
        }
    }
}

impl PqcSignature for Falcon {
    type Error = Error;

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        falcon_generate_keypair(self.security_level)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        falcon_sign(self.security_level, sk, msg)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error> {
        falcon_verify(self.security_level, pk, msg, sig)
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

#[cfg(feature = "std")]
impl KeyRotation for Falcon {
    fn rotate_keys(&mut self) -> Result<(), crate::crypto::traits::CryptoError> {
        self.rotation.last_key_generation = std::time::Instant::now();
        Ok(())
    }

    fn time_until_rotation(&self) -> core::time::Duration {
        let elapsed = self.rotation.last_key_generation.elapsed();
        if elapsed >= self.rotation.key_rotation_interval {
            core::time::Duration::ZERO
        } else {
            self.rotation.key_rotation_interval - elapsed
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

#[cfg(feature = "falcon-pqclean")]
fn falcon_generate_keypair(
    security_level: FalconSecurityLevel,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (pk, sk) = match security_level {
        FalconSecurityLevel::Falcon512 => {
            let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        FalconSecurityLevel::Falcon1024 => {
            let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
    };
    Ok((pk, sk))
}

#[cfg(not(feature = "falcon-pqclean"))]
fn falcon_generate_keypair(
    _security_level: FalconSecurityLevel,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    Err(Error::CryptoError(
        "Falcon backend unavailable: enable feature `falcon-pqclean`".into(),
    ))
}

#[cfg(feature = "falcon-pqclean")]
fn falcon_sign(
    security_level: FalconSecurityLevel,
    sk: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    let signature = match security_level {
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
    Ok(signature)
}

#[cfg(not(feature = "falcon-pqclean"))]
fn falcon_sign(
    _security_level: FalconSecurityLevel,
    _sk: &[u8],
    _msg: &[u8],
) -> Result<Vec<u8>, Error> {
    Err(Error::CryptoError(
        "Falcon backend unavailable: enable feature `falcon-pqclean`".into(),
    ))
}

#[cfg(feature = "falcon-pqclean")]
fn falcon_verify(
    security_level: FalconSecurityLevel,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let result = match security_level {
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
    Ok(result)
}

#[cfg(not(feature = "falcon-pqclean"))]
fn falcon_verify(
    _security_level: FalconSecurityLevel,
    _pk: &[u8],
    _msg: &[u8],
    _sig: &[u8],
) -> Result<bool, Error> {
    Err(Error::CryptoError(
        "Falcon backend unavailable: enable feature `falcon-pqclean`".into(),
    ))
}
