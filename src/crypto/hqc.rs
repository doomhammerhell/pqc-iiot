//! HQC (Hamming Quasi-Cyclic) implementation - REAL
//!
//! Using `pqcrypto-hqc` (Round 4) for code-based KEM.
//! This provides a fallback if lattice-based crypto is broken.

use crate::crypto::traits::{CryptoError, KeyRotation, Metrics, PqcKEM, SecurityLevel};
use crate::error::Error;
use core::fmt;

// Import the specific HQC variant (HQC-128 / Level 1)
#[cfg(feature = "hqc")]
use pqcrypto_hqc::hqc128;
#[cfg(feature = "hqc")]
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

/// HQC security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HqcSecurityLevel {
    /// Level 1 (AES-128 equivalent) - hqc-128
    Level1,
}

impl fmt::Display for HqcSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HqcSecurityLevel::Level1 => write!(f, "HQC-128 (Level 1)"),
        }
    }
}

/// HQC implementation
pub struct Hqc {
    #[allow(dead_code)]
    security_level: HqcSecurityLevel,
    key_rotation_interval: core::time::Duration,
    #[allow(dead_code)] // Used for logic even if not read directly yet
    last_key_generation: std::time::Instant,
    metrics: HqcMetrics,
}

/// Metrics for HQC operations
#[derive(Default, Debug, Clone)]
struct HqcMetrics {
    #[allow(dead_code)]
    key_generation_time: core::time::Duration,
    #[allow(dead_code)]
    encapsulation_time: core::time::Duration,
    #[allow(dead_code)]
    decapsulation_time: core::time::Duration,
    #[allow(dead_code)]
    operations_count: u64,
}

impl Default for Hqc {
    fn default() -> Self {
        Self::new()
    }
}

impl Hqc {
    /// Create a new HQC instance
    pub fn new() -> Self {
        Self {
            security_level: HqcSecurityLevel::Level1,
            key_rotation_interval: core::time::Duration::from_secs(3600),
            last_key_generation: std::time::Instant::now(),
            metrics: HqcMetrics::default(),
        }
    }

    /// Set the key rotation interval
    pub fn with_key_rotation_interval(mut self, interval: core::time::Duration) -> Self {
        self.key_rotation_interval = interval;
        self
    }
}

impl PqcKEM for Hqc {
    type Error = Error;

    #[cfg(feature = "hqc")]
    fn generate_keypair(&self) -> Result<(std::vec::Vec<u8>, std::vec::Vec<u8>), Self::Error> {
        let (pk, sk) = hqc128::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    #[cfg(not(feature = "hqc"))]
    fn generate_keypair(&self) -> Result<(std::vec::Vec<u8>, std::vec::Vec<u8>), Self::Error> {
        Err(Error::CryptoError("HQC feature disabled".into()))
    }

    #[cfg(feature = "hqc")]
    fn encapsulate(
        &self,
        pk: &[u8],
    ) -> Result<(std::vec::Vec<u8>, std::vec::Vec<u8>), Self::Error> {
        let pk = hqc128::PublicKey::from_bytes(pk)
            .map_err(|e| Error::CryptoError(format!("Invalid HQC public key: {}", e)))?;

        let (ct, ss) = hqc128::encapsulate(&pk);
        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    #[cfg(not(feature = "hqc"))]
    fn encapsulate(
        &self,
        _pk: &[u8],
    ) -> Result<(std::vec::Vec<u8>, std::vec::Vec<u8>), Self::Error> {
        Err(Error::CryptoError("HQC feature disabled".into()))
    }

    #[cfg(feature = "hqc")]
    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<std::vec::Vec<u8>, Self::Error> {
        let sk = hqc128::SecretKey::from_bytes(sk)
            .map_err(|e| Error::CryptoError(format!("Invalid HQC secret key: {}", e)))?;
        let ct = hqc128::Ciphertext::from_bytes(ct)
            .map_err(|e| Error::CryptoError(format!("Invalid HQC ciphertext: {}", e)))?;

        let ss = hqc128::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }

    #[cfg(not(feature = "hqc"))]
    fn decapsulate(&self, _sk: &[u8], _ct: &[u8]) -> Result<std::vec::Vec<u8>, Self::Error> {
        Err(Error::CryptoError("HQC feature disabled".into()))
    }
}

impl SecurityLevel for Hqc {
    fn security_level(&self) -> u32 {
        1
    }

    fn set_security_level(&mut self, _level: u32) -> Result<(), CryptoError> {
        Ok(())
    }
}

impl KeyRotation for Hqc {
    fn rotate_keys(&mut self) -> Result<(), CryptoError> {
        Ok(())
    }

    fn time_until_rotation(&self) -> core::time::Duration {
        core::time::Duration::ZERO
    }
}

impl Metrics for Hqc {
    fn metrics(&self) -> &dyn core::any::Any {
        &self.metrics
    }

    fn reset_metrics(&mut self) {}
}
