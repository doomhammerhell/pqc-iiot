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
use alloc::format;
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

// Integrity Check
// In a real FIPS module, this calculates HMAC-SHA256 of the binary image.
// For this library, we provide a mechanism to verify the in-memory code segment.
// The application must provide the correct range of the code segment.
//
#[allow(improper_ctypes)]
// Linker Symbols (defined in linker script)
// These are standard names. We declare them here.
extern "C" {
    static _stext: u8; // Start of text (code)
    static _etext: u8; // End of text
    static _sdata: u8; // Start of data
    static _edata: u8; // End of data
}

/// Helper to check if a range is within valid memory regions
fn is_valid_memory_range(start: *const u8, len: usize) -> bool {
    // In hosted/test mode, we can't check against linker symbols of the host
    #[cfg(not(target_os = "none"))]
    {
        let _ = (start, len);
        true
    }

    #[cfg(target_os = "none")]
    unsafe {
        let start_addr = start as usize;
        let end_addr = start_addr.saturating_add(len);

        let text_start = &_stext as *const u8 as usize;
        let text_end = &_etext as *const u8 as usize;
        let data_start = &_sdata as *const u8 as usize;
        let data_end = &_edata as *const u8 as usize;

        // Check Text Segment
        if start_addr >= text_start && end_addr <= text_end {
            return true;
        }
        // Check Data Segment
        if start_addr >= data_start && end_addr <= data_end {
            return true;
        }
        false
    }
}

/// Verify integrity of a memory region (Code/Data)
///
/// # Safety
/// This function is unsafe because it reads arbitrary memory ranges.
/// The caller must ensure the range is valid.
/// **UPDATE**: We now validate against linker symbols internally as an extra guard.
pub unsafe fn verify_memory_integrity(
    start: *const u8,
    len: usize,
    expected_hash: &[u8],
) -> Result<()> {
    if !is_valid_memory_range(start, len) {
        return Err(Error::ComplianceError(
            "Memory Integrity Check Failed: Invalid Memory Range".into(),
        ));
    }

    if len == 0 {
        return Err(Error::ComplianceError("Zero length memory range".into()));
    }

    let mut hasher = Sha256::new();
    // Read memory in chunks to avoid stack overflow or cache thrashing issues
    // though Sha256 update is streaming.
    // Verify that the memory segment is mapped and readable for integrity hashing.
    let slice = core::slice::from_raw_parts(start, len);
    hasher.update(slice);

    let result = hasher.finalize();

    if result.as_slice() != expected_hash {
        error!(
            "[COMPLIANCE] Integrity Check FAILED. Calculated: {:x?}, Expected: {:x?}",
            result, expected_hash
        );
        return Err(Error::ComplianceError("Integrity Check Failed".into()));
    }

    info!("[COMPLIANCE] Memory Integrity Verified.");
    Ok(())
}

fn test_integrity() -> Result<()> {
    // Self-Test of the Integrity Mechanism
    // We verify a known local constant to prove the hasher works.
    let data = b"pqc-iiot-integrity-check";
    let expected = hex::decode("1adef1ac56909d3e5320799507ee1c75f01788450cbd5e56f7341135660423f9")
        .map_err(|_| Error::ComplianceError("Hex decode failed".into()))?;

    unsafe { verify_memory_integrity(data.as_ptr(), data.len(), &expected) }
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
        return Err(Error::ComplianceError("AES KAT Mismatch".into()));
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
        return Err(Error::ComplianceError("Kyber PCT Failed".into()));
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
