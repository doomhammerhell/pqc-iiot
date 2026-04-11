#![cfg_attr(not(feature = "std"), no_std)]
// #![forbid(unsafe_code)] // Disabled for Compliance Memory Checks
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

//! A post-quantum cryptography crate designed for Industrial IoT (IIoT) applications.
//! Provides quantum-resistant cryptographic primitives with a focus on embedded systems
//! and resource-constrained devices.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Audit logging and event tracking
#[cfg(feature = "serde")]
pub mod audit;
/// Remote Attestation features for verifying firmware integrity.
pub mod attestation {
    /// Remote Attestation Quotes
    #[cfg(feature = "serde")]
    pub mod quote;
}
/// Typestate Client Machine for enforcing secure state transitions.
#[cfg(feature = "std")]
pub mod client_state;
pub mod compliance;
pub mod error;
/// Secure Firmware Over-The-Air (FOTA) updates.
#[cfg(feature = "std")]
pub mod fota;
#[cfg(feature = "kyber-pqclean")]
pub mod kem;
#[cfg(feature = "std")]
pub mod persistence;
/// Industrial Provisioning Protocol (Join/Enrollment).
#[cfg(feature = "std")]
pub mod provisioning;
/// Cryptographic Ratcheting (Double Ratchet) for Forward Secrecy.
#[cfg(feature = "std")]
pub mod ratchet;
/// Security primitives and providers
#[cfg(feature = "std")]
pub mod security;
#[cfg(feature = "falcon-pqclean")]
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

    /// HQC implementation
    #[cfg(feature = "hqc")]
    pub mod hqc;

    /// Cryptographic profiles
    #[cfg(feature = "config")]
    pub mod profile;
}

/// Secure MQTT client implementation
#[cfg(feature = "mqtt")]
pub mod mqtt_secure;

/// MQTT control-plane helpers (policy/revocation sync responder).
#[cfg(feature = "mqtt")]
pub mod mqtt_control_plane;

/// Secure CoAP client implementation
#[cfg(feature = "coap")]
pub mod coap_secure;

#[cfg(feature = "std")]
pub use security::hybrid;
#[cfg(feature = "std")]
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

#[cfg(feature = "hqc")]
pub use crypto::hqc::{Hqc, HqcSecurityLevel};

#[cfg(feature = "mqtt")]
pub use mqtt_secure::SecureMqttClient;

#[cfg(feature = "coap")]
pub use coap_secure::SecureCoapClient;
