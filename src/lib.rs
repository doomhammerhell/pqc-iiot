#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

//! A post-quantum cryptography crate designed for Industrial IoT (IIoT) applications.
//! Provides quantum-resistant cryptographic primitives with a focus on embedded systems
//! and resource-constrained devices.

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub mod utils;

/// Cryptographic primitives module
pub mod crypto {
    /// Traits for cryptographic primitives
    pub mod traits {
        /// Trait for post-quantum key encapsulation mechanisms
        pub trait PqcKEM {
            /// Error type for KEM operations
            type Error;

            /// Generate a key pair
            fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

            /// Encapsulate a shared secret
            fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

            /// Decapsulate a shared secret
            fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, Self::Error>;
        }

        /// Trait for post-quantum digital signatures
        pub trait PqcSignature {
            /// Error type for signature operations
            type Error;

            /// Generate a key pair
            fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

            /// Sign a message
            fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

            /// Verify a signature
            fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error>;
        }
    }

    /// Kyber implementation
    #[cfg(feature = "kyber")]
    pub mod kyber;

    /// Falcon implementation
    #[cfg(feature = "falcon")]
    pub mod falcon;

    /// Dilithium implementation
    #[cfg(feature = "dilithium")]
    pub mod dilithium;

    /// SABER implementation
    #[cfg(feature = "saber")]
    pub mod saber;

    /// BIKE implementation
    #[cfg(feature = "bike")]
    pub mod bike;
}

/// Secure MQTT client implementation
#[cfg(feature = "mqtt")]
pub mod mqtt_secure;

/// Secure CoAP client implementation
#[cfg(feature = "coap")]
pub mod coap_secure;

/// Re-export commonly used items
pub use error::Error;
pub use utils::{KeyStorage, Metrics, SecurityLevel};

#[cfg(feature = "kyber")]
pub use crypto::kyber::Kyber;

#[cfg(feature = "falcon")]
pub use crypto::falcon::Falcon;

#[cfg(feature = "dilithium")]
pub use crypto::dilithium::Dilithium;

#[cfg(feature = "saber")]
pub use crypto::saber::Saber;

#[cfg(feature = "bike")]
pub use crypto::bike::Bike;

#[cfg(feature = "mqtt")]
pub use mqtt_secure::SecureMqttClient;

#[cfg(feature = "coap")]
pub use coap_secure::SecureCoapClient;
