#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

//! A post-quantum cryptography library for IIoT applications
//!
//! This crate provides post-quantum cryptographic primitives based on CRYSTALS-Kyber
//! for key encapsulation (KEM) and Falcon for digital signatures, specifically
//! designed for IIoT and embedded applications.

pub mod coap_secure;
pub mod error;
pub mod kem;
pub mod mqtt_secure;
pub mod sign;
pub mod utils;

// Re-exports for convenience
pub use coap_secure::SecureCoapClient;
pub use error::Error;
pub use kem::Kyber;
pub use mqtt_secure::SecureMqttClient;
pub use sign::Falcon;

/// Result type used throughout the crate
pub type Result<T> = core::result::Result<T, Error>;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(feature = "kyber")]
pub mod kyber;
#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "dilithium")]
pub mod dilithium;
#[cfg(feature = "saber")]
pub mod saber;
#[cfg(feature = "bike")]
pub mod bike;

/// Enum for selecting KEM algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// CRYSTALS-Kyber
    #[cfg(feature = "kyber")]
    Kyber,
    /// SABER
    #[cfg(feature = "saber")]
    Saber,
    /// BIKE (experimental)
    #[cfg(feature = "bike")]
    Bike,
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "kyber")]
            KemAlgorithm::Kyber => write!(f, "Kyber"),
            #[cfg(feature = "saber")]
            KemAlgorithm::Saber => write!(f, "SABER"),
            #[cfg(feature = "bike")]
            KemAlgorithm::Bike => write!(f, "BIKE"),
        }
    }
}

/// Enum for selecting signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    /// Falcon
    #[cfg(feature = "falcon")]
    Falcon,
    /// Dilithium
    #[cfg(feature = "dilithium")]
    Dilithium,
}

impl fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "falcon")]
            SignAlgorithm::Falcon => write!(f, "Falcon"),
            #[cfg(feature = "dilithium")]
            SignAlgorithm::Dilithium => write!(f, "Dilithium"),
        }
    }
}

#[cfg(feature = "kyber")]
pub use kyber::{Kyber, KyberSecurityLevel};
#[cfg(feature = "falcon")]
pub use falcon::{Falcon, FalconSecurityLevel};
#[cfg(feature = "dilithium")]
pub use dilithium::{Dilithium, DilithiumSecurityLevel};
#[cfg(feature = "saber")]
pub use saber::{Saber, SaberSecurityLevel};
#[cfg(feature = "bike")]
pub use bike::{Bike, BikeSecurityLevel};

#[cfg(feature = "mqtt")]
pub use mqtt_secure::SecureMqttClient;
#[cfg(feature = "coap")]
pub use coap_secure::SecureCoapClient;
