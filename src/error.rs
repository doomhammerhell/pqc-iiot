//! Error types for the PQC-IIoT crate

/// Result type for PQC-IIoT operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations
#[derive(Debug)]
pub enum Error {
    /// Error during key generation
    KeyGenerationError(String),
    /// Cryptographic error
    CryptoError(String),
    /// Network error
    NetworkError(String),
    /// Error during encapsulation
    EncapsulationError(String),
    /// Error during decapsulation
    DecapsulationError(String),
    /// Error during signing
    SigningError(String),
    /// Error during verification
    VerificationError(String),
    /// Error during MQTT operations
    MqttError(String),
    /// Error during I/O operations
    IoError(std::io::Error),
    /// Error during CoAP operations
    CoapError(String),
    /// Error during client operations
    ClientError(String),
    /// Buffer too small for operation
    BufferTooSmall,
    /// Invalid input parameters
    InvalidInput(String),
    /// Signature verification failed
    SignatureVerification(String),
    /// Error during compliance check
    ComplianceError(String),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyGenerationError(e) => write!(f, "Key generation error: {}", e),
            Error::EncapsulationError(e) => write!(f, "Encapsulation error: {}", e),
            Error::DecapsulationError(e) => write!(f, "Decapsulation error: {}", e),
            Error::SigningError(e) => write!(f, "Signing error: {}", e),
            Error::VerificationError(e) => write!(f, "Verification error: {}", e),
            Error::MqttError(e) => write!(f, "MQTT error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::CoapError(e) => write!(f, "CoAP error: {}", e),
            Error::ClientError(e) => write!(f, "Client error: {}", e),
            Error::BufferTooSmall => write!(f, "Buffer too small for operation"),
            Error::InvalidInput(e) => write!(f, "Invalid input: {}", e),
            Error::SignatureVerification(e) => write!(f, "Signature verification failed: {}", e),
            Error::CryptoError(e) => write!(f, "Cryptographic error: {}", e),
            Error::NetworkError(e) => write!(f, "Network error: {}", e),
            Error::ComplianceError(e) => write!(f, "Compliance error: {}", e),
        }
    }
}
