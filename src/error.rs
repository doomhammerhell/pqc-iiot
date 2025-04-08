//! Error types for the PQC-IIoT crate

/// Errors that can occur during cryptographic operations
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// Key generation failed
    KeyGeneration,
    /// Encapsulation failed
    Encapsulation,
    /// Decapsulation failed
    Decapsulation,
    /// Signature generation failed
    SignatureGeneration,
    /// Signature verification failed
    SignatureVerification,
    /// Invalid input parameters
    InvalidInput,
    /// Buffer too small
    BufferTooSmall,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::KeyGeneration => write!(f, "key generation failed"),
            Error::Encapsulation => write!(f, "encapsulation failed"),
            Error::Decapsulation => write!(f, "decapsulation failed"),
            Error::SignatureGeneration => write!(f, "signature generation failed"),
            Error::SignatureVerification => write!(f, "signature verification failed"),
            Error::InvalidInput => write!(f, "invalid input parameters"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
        }
    }
}
