//! Examples demonstrating the usage of post-quantum cryptographic primitives.
//!
//! This module provides examples for:
//! - Key Encapsulation (Kyber, SABER)
//! - Digital Signatures (Falcon, Dilithium)
//! - Security Level Management
//! - Key Rotation
//! - Performance Metrics

use pqc_iiot::{Falcon, FalconSecurityLevel, Kyber, KyberSecurityLevel};
#[cfg(feature = "dilithium")]
use pqc_iiot::{Dilithium, DilithiumSecurityLevel};
#[cfg(feature = "saber")]
use pqc_iiot::{Saber, SaberSecurityLevel};
// use pqc_iiot::crypto::traits::{KeyRotation, Metrics, PqcKEM, PqcSignature, SecurityLevel};
// use pqc_iiot::crypto::traits::*;
use pqc_iiot::crypto::traits::{KeyRotation, Metrics, PqcKEM, PqcSignature, SecurityLevel};
use std::time::Duration;

/// Example demonstrating Kyber key encapsulation
fn kyber_example() {
    println!("Kyber Example:");

    // Create a Kyber instance with NIST Level 3 security
    let kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber768)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Generate key pair
    let (pk, sk) = kyber.generate_keypair().unwrap();
    println!("Generated Kyber key pair");

    // Encapsulate a shared secret
    let (ct, ss1) = kyber.encapsulate(&pk).unwrap();
    println!("Encapsulated shared secret");

    // Decapsulate the shared secret
    let ss2 = kyber.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret");

    // Verify the shared secrets match
    assert_eq!(ss1, ss2);
    println!("Shared secrets match!");

    // Print metrics
    let metrics = kyber.metrics();
    println!("Metrics: {:?}", metrics);
}

/// Example demonstrating Falcon digital signatures
fn falcon_example() {
    println!("\nFalcon Example:");

    // Create a Falcon instance with NIST Level 5 security
    let falcon = Falcon::new_with_level(FalconSecurityLevel::Falcon512);

    // Generate key pair
    let (pk, sk) = falcon.generate_keypair().unwrap();
    println!("Generated Falcon key pair");

    // Sign a message
    let msg = b"Hello, Falcon!";
    let sig = falcon.sign(&sk, msg).unwrap();
    println!("Signed message");

    // Verify the signature
    let valid = falcon.verify(&pk, msg, &sig).unwrap();
    println!("Signature verification: {}", valid);

    // Print metrics
    let metrics = falcon.metrics();
    println!("Metrics: {:?}", metrics);
}

/// Example demonstrating Dilithium digital signatures
/// Example demonstrating Dilithium digital signatures
#[cfg(feature = "dilithium")]
fn dilithium_example() {
    println!("\nDilithium Example:");

    // Create a Dilithium instance with NIST Level 3 security
    let dilithium = Dilithium::new_with_level(DilithiumSecurityLevel::Level3)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Generate key pair
    let (pk, sk) = dilithium.generate_keypair().unwrap();
    println!("Generated Dilithium key pair");

    // Sign a message
    let msg = b"Hello, Dilithium!";
    let sig = dilithium.sign(&sk, msg).unwrap();
    println!("Signed message");

    // Verify the signature
    let valid = dilithium.verify(&pk, msg, &sig).unwrap();
    println!("Signature verification: {}", valid);

    // Print metrics
    let metrics = dilithium.metrics();
    println!("Metrics: {:?}", metrics);
}

/// Example demonstrating SABER key encapsulation
/// Example demonstrating SABER key encapsulation
#[cfg(feature = "saber")]
fn saber_example() {
    println!("\nSABER Example:");

    // Create a SABER instance with NIST Level 3 security
    let saber = Saber::new_with_level(SaberSecurityLevel::Saber)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Generate key pair
    let (pk, sk) = saber.generate_keypair().unwrap();
    println!("Generated SABER key pair");

    // Encapsulate a shared secret
    let (ct, ss1) = saber.encapsulate(&pk).unwrap();
    println!("Encapsulated shared secret");

    // Decapsulate the shared secret
    let ss2 = saber.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret");

    // Verify the shared secrets match
    assert_eq!(ss1, ss2);
    println!("Shared secrets match!");

    // Print metrics
    let metrics = saber.metrics();
    println!("Metrics: {:?}", metrics);
}

/// Example demonstrating security level management
fn security_level_example() {
    println!("\nSecurity Level Example:");

    // Create instances with different security levels
    let kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber768);
    let falcon = Falcon::new_with_level(FalconSecurityLevel::Falcon1024);
    #[cfg(feature = "dilithium")]
    let dilithium = Dilithium::new_with_level(DilithiumSecurityLevel::Level3);
    #[cfg(feature = "saber")]
    let saber = Saber::new_with_level(SaberSecurityLevel::Saber);

    // Print security levels
    println!("Kyber security level: {}", kyber.security_level());
    println!("Falcon security level: {}", falcon.security_level());
    #[cfg(feature = "dilithium")]
    println!("Dilithium security level: {}", dilithium.security_level());
    #[cfg(feature = "saber")]
    println!("SABER security level: {}", saber.security_level());

    // Change security levels
    let mut kyber = kyber;
    kyber.set_security_level(1).unwrap(); // Change to Level 1
    println!("Kyber new security level: {}", kyber.security_level());
}

/// Example demonstrating key rotation
fn key_rotation_example() {
    println!("\nKey Rotation Example:");

    // Create a Kyber instance with 1-hour rotation interval
    let mut kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber768)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Generate initial key pair
    let (pk1, sk1) = kyber.generate_keypair().unwrap();
    println!("Generated initial key pair");

    // Force key rotation
    kyber.rotate_keys().unwrap();
    println!("Rotated keys");

    // Generate new key pair
    let (pk2, sk2) = kyber.generate_keypair().unwrap();
    println!("Generated new key pair");

    // Verify keys are different
    assert_ne!(pk1, pk2);
    assert_ne!(sk1, sk2);
    println!("Key pairs are different");

    // Check time until next rotation
    let time_until = kyber.time_until_rotation();
    println!("Time until next rotation: {:?}", time_until);
}

fn main() {
    // Run all examples
    kyber_example();
    falcon_example();
    #[cfg(feature = "dilithium")]
    dilithium_example();
    #[cfg(feature = "saber")]
    saber_example();
    security_level_example();
    key_rotation_example();
}
