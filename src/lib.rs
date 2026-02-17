#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

//! A post-quantum cryptography crate designed for Industrial IoT (IIoT) applications.
//! Provides quantum-resistant cryptographic primitives with a focus on embedded systems
//! and resource-constrained devices.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Audit logging and event tracking
pub mod audit;
pub mod compliance;
pub mod error;
pub mod kem;
/// Security primitives and providers
pub mod security;
pub mod sign;
pub mod utils;

#[cfg(feature = "config")]
pub mod config;

/// Cryptographic primitives module
pub mod crypto {
    /// Traits for cryptographic primitives
    pub mod traits;

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

    /// Cryptographic profiles
    #[cfg(feature = "config")]
    pub mod profile;
}

/// Secure MQTT client implementation
#[cfg(feature = "mqtt")]
pub mod mqtt_secure;

/// Secure CoAP client implementation
#[cfg(feature = "coap")]
pub mod coap_secure;

pub use security::hybrid;
pub use security::keystore::KeyStore;

pub use crypto::traits::{Metrics, SecurityLevel};
/// Re-export commonly used items
pub use error::{Error, Result};

#[cfg(feature = "kyber")]
pub use crypto::kyber::{Kyber, KyberSecurityLevel};

#[cfg(feature = "falcon")]
pub use crypto::falcon::{Falcon, FalconSecurityLevel};

#[cfg(feature = "dilithium")]
pub use crypto::dilithium::{Dilithium, DilithiumSecurityLevel};

#[cfg(feature = "saber")]
pub use crypto::saber::{Saber, SaberSecurityLevel};

#[cfg(feature = "bike")]
pub use crypto::bike::{Bike, BikeSecurityLevel};

#[cfg(feature = "mqtt")]
pub use mqtt_secure::SecureMqttClient;

#[cfg(feature = "coap")]
pub use coap_secure::SecureCoapClient;
