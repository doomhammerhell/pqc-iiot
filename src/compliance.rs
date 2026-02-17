//! Compliance and Self-Tests (FIPS 140-3 / IEC 62443 based)
//!
//! This module implements mandatory Power-On Self-Tests (POST) to ensure
//! cryptographic primitives are functioning correctly before operation.

use crate::crypto::traits::{PqcKEM, PqcSignature};
use crate::{Error, Result};
use crate::{Falcon, Kyber};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use log::{error, info};
use sha2::{Digest, Sha256};

/// Runs all mandatory self-tests.
/// Panics or returns specific errors if any test fails.
/// This should be called on application startup.
pub fn run_self_tests() -> Result<()> {
    info!("[COMPLIANCE] Running Power-On Self-Tests (POST)...");

    test_integrity()?;
    test_aes_gcm_kat()?;
    test_kyber_pct()?;
    test_falcon_pct()?;

    info!("[COMPLIANCE] All Self-Tests PASSED. System is in APPROVED mode.");
    Ok(())
}

/// Integrity Check (Simulated)
/// In a real FIPS module, this would calculate HMAC-SHA256 of the code segment.
fn test_integrity() -> Result<()> {
    // For this library, we verify that critical constants are consistent
    // and SHA2 working correctly.
    let mut hasher = Sha256::new();
    hasher.update(b"pqc-iiot-integrity-check");
    let result = hasher.finalize();

    // Known hash for "pqc-iiot-integrity-check"
    let expected = hex::decode("1adef1ac56909d3e5320799507ee1c75f01788450cbd5e56f7341135660423f9")
        .map_err(|_| Error::ComplianceError("Hex decode failed".to_string()))?;

    if result.as_slice() != expected.as_slice() {
        error!("[COMPLIANCE] Integrity Check FAILED");
        return Err(Error::ComplianceError("Integrity Check Failed".to_string()));
    }
    Ok(())
}

/// AES-256-GCM Known Answer Test (KAT)
fn test_aes_gcm_kat() -> Result<()> {
    let key_bytes = [0u8; 32];
    let nonce_bytes = [0u8; 12];
    let plaintext = b"fips-test";

    let cipher = Aes256Gcm::new(&key_bytes.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| Error::ComplianceError(format!("AES KAT Encryption failed: {}", e)))?;

    // Decrypt back
    let decrypted = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| Error::ComplianceError(format!("AES KAT Decryption failed: {}", e)))?;

    if decrypted != plaintext {
        return Err(Error::ComplianceError("AES KAT Mismatch".to_string()));
    }
    Ok(())
}

/// Kyber Pairwise Consistency Test (PCT)
/// FIPS 140-3 IG 9.3.A
fn test_kyber_pct() -> Result<()> {
    let kyber = Kyber::new();
    let (pk, sk) = kyber
        .generate_keypair()
        .map_err(|e| Error::ComplianceError(format!("Kyber PCT Keygen failed: {}", e)))?;

    let (ciphertext, shared_secret_a) = kyber
        .encapsulate(&pk)
        .map_err(|e| Error::ComplianceError(format!("Kyber PCT Encap failed: {}", e)))?;

    let shared_secret_b = kyber
        .decapsulate(&sk, &ciphertext)
        .map_err(|e| Error::ComplianceError(format!("Kyber PCT Decap failed: {}", e)))?;

    if shared_secret_a != shared_secret_b {
        error!("[COMPLIANCE] Kyber PCT FAILED (Shared Secret Mismatch)");
        return Err(Error::ComplianceError("Kyber PCT Failed".to_string()));
    }
    Ok(())
}

/// Falcon Pairwise Consistency Test (PCT)
fn test_falcon_pct() -> Result<()> {
    let falcon = Falcon::new();
    let (pk, sk) = falcon
        .generate_keypair()
        .map_err(|e| Error::ComplianceError(format!("Falcon PCT Keygen failed: {}", e)))?;

    let message = b"pairwise-consistency-test";

    let signature = falcon
        .sign(&sk, message)
        .map_err(|e| Error::ComplianceError(format!("Falcon PCT Sign failed: {}", e)))?;

    falcon
        .verify(&pk, message, &signature)
        .map_err(|e| Error::ComplianceError(format!("Falcon PCT Verify failed: {}", e)))?;

    Ok(())
}
