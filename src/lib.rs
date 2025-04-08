#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! A post-quantum cryptography library for IIoT applications
//!
//! This crate provides post-quantum cryptographic primitives based on CRYSTALS-Kyber
//! for key encapsulation (KEM) and Falcon for digital signatures, specifically
//! designed for IIoT and embedded applications.

pub mod error;
pub mod kem;
pub mod sign;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-exports for convenience
pub use error::Error;
pub use kem::Kyber;
pub use sign::Falcon;

/// Result type used throughout the crate
pub type Result<T> = core::result::Result<T, Error>;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
