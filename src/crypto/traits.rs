//! Traits for post-quantum cryptographic primitives.
//!
//! This module defines the core traits that all post-quantum cryptographic
//! implementations must adhere to, providing a consistent API across different
//! algorithms.
//!
//! # Examples
//!
//! Basic usage of the traits:
//!
//! ```rust
//! use pqc_iiot::crypto::traits::{PqcKEM, PqcSignature};
//! use pqc_iiot::{Kyber, Falcon};
//!
//! // Key Encapsulation
//! let kyber = Kyber::new(KyberSecurityLevel::Kyber768);
//! let (pk, sk) = kyber.generate_keypair().unwrap();
//! let (ct, ss1) = kyber.encapsulate(&pk).unwrap();
//! let ss2 = kyber.decapsulate(&sk, &ct).unwrap();
//! assert_eq!(ss1, ss2);
//!
//! // Digital Signatures
//! let falcon = Falcon::new(FalconSecurityLevel::Falcon512);
//! let (pk, sk) = falcon.generate_keypair().unwrap();
//! let msg = b"Hello, world!";
//! let sig = falcon.sign(&sk, msg).unwrap();
//! assert!(falcon.verify(&pk, msg, &sig).unwrap());
//! ```
//!
//! # Security Considerations
//!
//! When implementing these traits:
//!
//! 1. Use constant-time operations for all cryptographic computations
//! 2. Securely erase sensitive data from memory
//! 3. Validate all inputs before processing
//! 4. Use appropriate key sizes for the security level
//! 5. Implement proper error handling
//!
//! # Performance
//!
//! Implementations should:
//!
//! 1. Minimize memory allocations
//! 2. Use efficient algorithms
//! 3. Support hardware acceleration when available
//! 4. Provide performance metrics
//!
//! # Error Handling
//!
//! All operations should return appropriate error types and handle failures
//! gracefully. Common error cases include:
//!
//! - Invalid input parameters
//! - Memory allocation failures
//! - Cryptographic operation failures
//! - Security level mismatches

use core::fmt;

/// Error type for cryptographic operations
#[derive(Debug)]
pub enum CryptoError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid ciphertext size
    InvalidCiphertextSize,
    /// Invalid signature size
    InvalidSignatureSize,
    /// Operation failed
    OperationFailed,
    /// Memory allocation failed
    AllocationFailed,
    /// Invalid parameters
    InvalidParameters,
    /// Security level mismatch
    SecurityLevelMismatch,
    /// Key rotation failed
    KeyRotationFailed,
    /// Invalid security level
    InvalidSecurityLevel,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeySize => write!(f, "Invalid key size"),
            CryptoError::InvalidCiphertextSize => write!(f, "Invalid ciphertext size"),
            CryptoError::InvalidSignatureSize => write!(f, "Invalid signature size"),
            CryptoError::OperationFailed => write!(f, "Operation failed"),
            CryptoError::AllocationFailed => write!(f, "Memory allocation failed"),
            CryptoError::InvalidParameters => write!(f, "Invalid parameters"),
            CryptoError::SecurityLevelMismatch => write!(f, "Security level mismatch"),
            CryptoError::KeyRotationFailed => write!(f, "Key rotation failed"),
            CryptoError::InvalidSecurityLevel => write!(f, "Invalid security level"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Trait for post-quantum key encapsulation mechanisms
///
/// This trait defines the interface for key encapsulation mechanisms (KEMs)
/// that are resistant to quantum computer attacks.
///
/// # Examples
///
/// ```rust
/// use pqc_iiot::crypto::traits::PqcKEM;
/// use pqc_iiot::Kyber;
///
/// let kem = Kyber::new(KyberSecurityLevel::Kyber768);
/// let (pk, sk) = kem.generate_keypair().unwrap();
/// let (ct, ss1) = kem.encapsulate(&pk).unwrap();
/// let ss2 = kem.decapsulate(&sk, &ct).unwrap();
/// assert_eq!(ss1, ss2);
/// ```
pub trait PqcKEM {
    /// Error type for KEM operations
    type Error: fmt::Debug + fmt::Display;

    /// Generate a key pair
    ///
    /// Returns a tuple of (public_key, secret_key)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails
    /// - Key generation fails
    /// - Security level is invalid
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Encapsulate a shared secret
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate against
    ///
    /// Returns a tuple of (ciphertext, shared_secret)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Public key is invalid
    /// - Encapsulation fails
    /// - Memory allocation fails
    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Decapsulate a shared secret
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to use for decapsulation
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// Returns the shared secret
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Secret key is invalid
    /// - Ciphertext is invalid
    /// - Decapsulation fails
    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Trait for post-quantum digital signatures
///
/// This trait defines the interface for digital signature schemes
/// that are resistant to quantum computer attacks.
///
/// # Examples
///
/// ```rust
/// use pqc_iiot::crypto::traits::PqcSignature;
/// use pqc_iiot::Falcon;
///
/// let signer = Falcon::new(FalconSecurityLevel::Falcon512);
/// let (pk, sk) = signer.generate_keypair().unwrap();
/// let msg = b"Hello, world!";
/// let sig = signer.sign(&sk, msg).unwrap();
/// assert!(signer.verify(&pk, msg, &sig).unwrap());
/// ```
pub trait PqcSignature {
    /// Error type for signature operations
    type Error: fmt::Debug + fmt::Display;

    /// Generate a key pair
    ///
    /// Returns a tuple of (public_key, secret_key)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails
    /// - Key generation fails
    /// - Security level is invalid
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to use for signing
    /// * `msg` - The message to sign
    ///
    /// Returns the signature
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Secret key is invalid
    /// - Message is empty
    /// - Signing fails
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to use for verification
    /// * `msg` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// Returns true if the signature is valid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Public key is invalid
    /// - Signature is invalid
    /// - Verification fails
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error>;
}

/// Trait for cryptographic algorithms that support different security levels
///
/// This trait defines the interface for managing security levels in
/// cryptographic algorithms.
///
/// # Examples
///
/// ```rust
/// use pqc_iiot::crypto::traits::SecurityLevel;
/// use pqc_iiot::Kyber;
///
/// let mut kem = Kyber::new(KyberSecurityLevel::Kyber768);
/// println!("Current security level: {}", kem.security_level());
/// kem.set_security_level(1).unwrap(); // Change to Level 1
/// ```
pub trait SecurityLevel {
    /// Get the current security level
    ///
    /// Returns a numeric value representing the security level:
    /// - 1: NIST Level 1
    /// - 2: NIST Level 2
    /// - 3: NIST Level 3
    /// - 5: NIST Level 5
    fn security_level(&self) -> u32;

    /// Set the security level
    ///
    /// # Arguments
    ///
    /// * `level` - The new security level (1, 2, 3, or 5)
    ///
    /// # Errors
    ///
    /// Returns an error if the security level is invalid
    fn set_security_level(&mut self, level: u32) -> Result<(), CryptoError>;
}

/// Trait for cryptographic algorithms that support key rotation
///
/// This trait defines the interface for managing key rotation in
/// cryptographic algorithms.
///
/// # Examples
///
/// ```rust
/// use pqc_iiot::crypto::traits::KeyRotation;
/// use pqc_iiot::Kyber;
/// use std::time::Duration;
///
/// let mut kem = Kyber::new(KyberSecurityLevel::Kyber768)
///     .with_key_rotation_interval(Duration::from_secs(3600));
/// kem.rotate_keys().unwrap();
/// println!("Time until next rotation: {:?}", kem.time_until_rotation());
/// ```
pub trait KeyRotation {
    /// Rotate the current key pair
    ///
    /// # Errors
    ///
    /// Returns an error if key rotation fails
    fn rotate_keys(&mut self) -> Result<(), CryptoError>;

    /// Get the time until next key rotation
    ///
    /// Returns the duration until the next key rotation is required
    fn time_until_rotation(&self) -> core::time::Duration;
}

/// Trait for cryptographic algorithms that support performance metrics
///
/// This trait defines the interface for collecting and managing
/// performance metrics in cryptographic algorithms.
///
/// # Examples
///
/// ```rust
/// use pqc_iiot::crypto::traits::Metrics;
/// use pqc_iiot::Kyber;
///
/// let mut kem = Kyber::new(KyberSecurityLevel::Kyber768);
/// // Perform some operations
/// let metrics = kem.metrics();
/// println!("Metrics: {:?}", metrics);
/// kem.reset_metrics();
/// ```
pub trait Metrics {
    /// Get the current metrics
    ///
    /// Returns a reference to the metrics object
    fn metrics(&self) -> &dyn core::any::Any;

    /// Reset the metrics
    ///
    /// Resets all performance metrics to their initial values
    fn reset_metrics(&mut self);
} 