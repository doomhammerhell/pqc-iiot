//! Cryptographic profiles for post-quantum cryptography in IIoT systems.
//!
//! This module provides pre-defined combinations of key encapsulation mechanisms (KEM)
//! and digital signature algorithms, optimized for different IIoT use cases.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```rust
//! use pqc_iiot::crypto::profile::{CryptoProfile, ProfileKyberFalcon};
//!
//! // Create a profile instance
//! let profile = ProfileKyberFalcon::new();
//!
//! // Generate a secure session
//! let (pk, sk) = profile.generate_keypair().unwrap();
//! let (ct, ss) = profile.encapsulate(&pk).unwrap();
//!
//! // Sign and verify a payload
//! let msg = b"Hello, IIoT!";
//! let sig = profile.sign(&sk, msg).unwrap();
//! assert!(profile.verify(&pk, msg, &sig).unwrap());
//! ```

use core::fmt;
use crate::crypto::traits::{PqcKEM, PqcSignature, CryptoError};

/// Pre-defined cryptographic profiles for IIoT systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoProfile {
    /// Kyber (KEM) + Falcon (Signature)
    ProfileKyberFalcon,
    /// SABER (KEM) + Dilithium (Signature)
    ProfileSaberDilithium,
    /// Kyber (KEM) + Dilithium (Signature)
    ProfileKyberDilithium,
    /// Custom combination of KEM and signature algorithms
    Custom {
        /// The key encapsulation mechanism
        kem: KemType,
        /// The digital signature algorithm
        sign: SignType,
    },
}

/// Available key encapsulation mechanisms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemType {
    /// Kyber algorithm
    Kyber,
    /// SABER algorithm
    Saber,
}

/// Available digital signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignType {
    /// Falcon algorithm
    Falcon,
    /// Dilithium algorithm
    Dilithium,
}

/// Error type for cryptographic profile operations
#[derive(Debug)]
pub enum ProfileError {
    /// Error from the KEM algorithm
    KemError(CryptoError),
    /// Error from the signature algorithm
    SignError(CryptoError),
    /// Invalid profile configuration
    InvalidConfig,
    /// Operation not supported by this profile
    UnsupportedOperation,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::KemError(e) => write!(f, "KEM error: {}", e),
            ProfileError::SignError(e) => write!(f, "Signature error: {}", e),
            ProfileError::InvalidConfig => write!(f, "Invalid profile configuration"),
            ProfileError::UnsupportedOperation => write!(f, "Operation not supported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProfileError {}

/// Trait for cryptographic profiles
pub trait CryptoProfileTrait {
    /// Generate a key pair for both KEM and signature algorithms
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError>;

    /// Encapsulate a shared secret using the KEM algorithm
    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileError>;

    /// Decapsulate a shared secret using the KEM algorithm
    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, ProfileError>;

    /// Sign a message using the signature algorithm
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, ProfileError>;

    /// Verify a signature using the signature algorithm
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, ProfileError>;

    /// Get the security level of the profile
    fn security_level(&self) -> u32;

    /// Get the KEM type used in this profile
    fn kem_type(&self) -> KemType;

    /// Get the signature type used in this profile
    fn sign_type(&self) -> SignType;
}

/// Implementation of the Kyber + Falcon profile
pub struct ProfileKyberFalcon {
    kem: Kyber,
    sign: Falcon,
}

impl ProfileKyberFalcon {
    /// Create a new Kyber + Falcon profile
    pub fn new() -> Self {
        Self {
            kem: Kyber::new(KyberSecurityLevel::Kyber768),
            sign: Falcon::new(FalconSecurityLevel::Falcon512),
        }
    }
}

impl CryptoProfileTrait for ProfileKyberFalcon {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        let (kem_pk, kem_sk) = self.kem.generate_keypair()
            .map_err(ProfileError::KemError)?;
        let (sign_pk, sign_sk) = self.sign.generate_keypair()
            .map_err(ProfileError::SignError)?;
        
        // Combine the keys
        let mut pk = kem_pk;
        pk.extend_from_slice(&sign_pk);
        let mut sk = kem_sk;
        sk.extend_from_slice(&sign_sk);
        
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        self.kem.encapsulate(pk)
            .map_err(ProfileError::KemError)
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.kem.decapsulate(sk, ct)
            .map_err(ProfileError::KemError)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.sign.sign(sk, msg)
            .map_err(ProfileError::SignError)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, ProfileError> {
        self.sign.verify(pk, msg, sig)
            .map_err(ProfileError::SignError)
    }

    fn security_level(&self) -> u32 {
        self.kem.security_level()
    }

    fn kem_type(&self) -> KemType {
        KemType::Kyber
    }

    fn sign_type(&self) -> SignType {
        SignType::Falcon
    }
}

/// Implementation of the SABER + Dilithium profile
pub struct ProfileSaberDilithium {
    kem: Saber,
    sign: Dilithium,
}

impl ProfileSaberDilithium {
    /// Create a new SABER + Dilithium profile
    pub fn new() -> Self {
        Self {
            kem: Saber::new(SaberSecurityLevel::Saber),
            sign: Dilithium::new(DilithiumSecurityLevel::Level3),
        }
    }
}

impl CryptoProfileTrait for ProfileSaberDilithium {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        let (kem_pk, kem_sk) = self.kem.generate_keypair()
            .map_err(ProfileError::KemError)?;
        let (sign_pk, sign_sk) = self.sign.generate_keypair()
            .map_err(ProfileError::SignError)?;
        
        // Combine the keys
        let mut pk = kem_pk;
        pk.extend_from_slice(&sign_pk);
        let mut sk = kem_sk;
        sk.extend_from_slice(&sign_sk);
        
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        self.kem.encapsulate(pk)
            .map_err(ProfileError::KemError)
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.kem.decapsulate(sk, ct)
            .map_err(ProfileError::KemError)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.sign.sign(sk, msg)
            .map_err(ProfileError::SignError)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, ProfileError> {
        self.sign.verify(pk, msg, sig)
            .map_err(ProfileError::SignError)
    }

    fn security_level(&self) -> u32 {
        self.kem.security_level()
    }

    fn kem_type(&self) -> KemType {
        KemType::Saber
    }

    fn sign_type(&self) -> SignType {
        SignType::Dilithium
    }
}

/// Implementation of the Kyber + Dilithium profile
pub struct ProfileKyberDilithium {
    kem: Kyber,
    sign: Dilithium,
}

impl ProfileKyberDilithium {
    /// Create a new Kyber + Dilithium profile
    pub fn new() -> Self {
        Self {
            kem: Kyber::new(KyberSecurityLevel::Kyber768),
            sign: Dilithium::new(DilithiumSecurityLevel::Level3),
        }
    }
}

impl CryptoProfileTrait for ProfileKyberDilithium {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        let (kem_pk, kem_sk) = self.kem.generate_keypair()
            .map_err(ProfileError::KemError)?;
        let (sign_pk, sign_sk) = self.sign.generate_keypair()
            .map_err(ProfileError::SignError)?;
        
        // Combine the keys
        let mut pk = kem_pk;
        pk.extend_from_slice(&sign_pk);
        let mut sk = kem_sk;
        sk.extend_from_slice(&sign_sk);
        
        Ok((pk, sk))
    }

    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        self.kem.encapsulate(pk)
            .map_err(ProfileError::KemError)
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.kem.decapsulate(sk, ct)
            .map_err(ProfileError::KemError)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, ProfileError> {
        self.sign.sign(sk, msg)
            .map_err(ProfileError::SignError)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, ProfileError> {
        self.sign.verify(pk, msg, sig)
            .map_err(ProfileError::SignError)
    }

    fn security_level(&self) -> u32 {
        self.kem.security_level()
    }

    fn kem_type(&self) -> KemType {
        KemType::Kyber
    }

    fn sign_type(&self) -> SignType {
        SignType::Dilithium
    }
} 