//! Example demonstrating the use of cryptographic profiles in IIoT systems.
//!
//! This example shows how to:
//! 1. Create and use different cryptographic profiles
//! 2. Generate key pairs
//! 3. Perform key encapsulation
//! 4. Sign and verify messages
//! 5. Handle errors

use pqc_iiot::crypto::profile::{CryptoProfileTrait, ProfileKyberFalcon};
#[cfg(feature = "dilithium")]
use pqc_iiot::crypto::profile::{ProfileKyberDilithium, ProfileSaberDilithium};

fn main() {
    // Example 1: Kyber + Falcon Profile
    println!("Example 1: Kyber + Falcon Profile");
    kyber_falcon_example();

    // Example 2: SABER + Dilithium Profile
    #[cfg(feature = "dilithium")]
    {
        println!("\nExample 2: SABER + Dilithium Profile");
        saber_dilithium_example();
    }

    // Example 3: Kyber + Dilithium Profile
    #[cfg(feature = "dilithium")]
    {
        println!("\nExample 3: Kyber + Dilithium Profile");
        kyber_dilithium_example();
    }
}

fn kyber_falcon_example() {
    // Create a Kyber + Falcon profile
    let profile = ProfileKyberFalcon::new();
    println!(
        "Created Kyber + Falcon profile with security level {}",
        profile.security_level()
    );

    // Generate key pair
    let (pk, sk) = profile.generate_keypair().unwrap();
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    // Encapsulate a shared secret
    let (ct, ss1) = profile.encapsulate(&pk).unwrap();
    println!(
        "Encapsulated shared secret (ciphertext: {} bytes, shared secret: {} bytes)",
        ct.len(),
        ss1.len()
    );

    // Decapsulate the shared secret
    let ss2 = profile.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret ({} bytes)", ss2.len());
    assert_eq!(ss1, ss2, "Shared secrets should match");

    // Sign a message
    let msg = b"Hello, IIoT!";
    let sig = profile.sign(&sk, msg).unwrap();
    println!("Signed message (signature: {} bytes)", sig.len());

    // Verify the signature
    let valid = profile.verify(&pk, msg, &sig).unwrap();
    println!("Signature verification: {}", valid);
    assert!(valid, "Signature should be valid");
}

#[cfg(feature = "dilithium")]
fn saber_dilithium_example() {
    // Create a SABER + Dilithium profile
    let profile = ProfileSaberDilithium::new();
    println!(
        "Created SABER + Dilithium profile with security level {}",
        profile.security_level()
    );

    // Generate key pair
    let (pk, sk) = profile.generate_keypair().unwrap();
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    // Encapsulate a shared secret
    let (ct, ss1) = profile.encapsulate(&pk).unwrap();
    println!(
        "Encapsulated shared secret (ciphertext: {} bytes, shared secret: {} bytes)",
        ct.len(),
        ss1.len()
    );

    // Decapsulate the shared secret
    let ss2 = profile.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret ({} bytes)", ss2.len());
    assert_eq!(ss1, ss2, "Shared secrets should match");

    // Sign a message
    let msg = b"Hello, IIoT!";
    let sig = profile.sign(&sk, msg).unwrap();
    println!("Signed message (signature: {} bytes)", sig.len());

    // Verify the signature
    let valid = profile.verify(&pk, msg, &sig).unwrap();
    println!("Signature verification: {}", valid);
    assert!(valid, "Signature should be valid");
}

#[cfg(feature = "dilithium")]
fn kyber_dilithium_example() {
    // Create a Kyber + Dilithium profile
    let profile = ProfileKyberDilithium::new();
    println!(
        "Created Kyber + Dilithium profile with security level {}",
        profile.security_level()
    );

    // Generate key pair
    let (pk, sk) = profile.generate_keypair().unwrap();
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    // Encapsulate a shared secret
    let (ct, ss1) = profile.encapsulate(&pk).unwrap();
    println!(
        "Encapsulated shared secret (ciphertext: {} bytes, shared secret: {} bytes)",
        ct.len(),
        ss1.len()
    );

    // Decapsulate the shared secret
    let ss2 = profile.decapsulate(&sk, &ct).unwrap();
    println!("Decapsulated shared secret ({} bytes)", ss2.len());
    assert_eq!(ss1, ss2, "Shared secrets should match");

    // Sign a message
    let msg = b"Hello, IIoT!";
    let sig = profile.sign(&sk, msg).unwrap();
    println!("Signed message (signature: {} bytes)", sig.len());

    // Verify the signature
    let valid = profile.verify(&pk, msg, &sig).unwrap();
    println!("Signature verification: {}", valid);
    assert!(valid, "Signature should be valid");
}
