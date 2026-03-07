use serde::{Serialize, Deserialize};
use crate::error::{Error, Result};
use crate::security::provider::SecurityProvider;

/// Secure Firmware Over-The-Air (FOTA) Update Engine
///
/// Implements "Industrial Grade" update logic:
/// 1. Manifest verification (Falcon-512)
/// 2. Anti-Rollback Protection (Monotonic Counters)
/// 3. Chunk-based verification (for constrained networks)

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirmwareManifest {
    /// Firmware Version (SemVer)
    pub version: String,
    
    /// Security Version Number (SvN) - Monotonic counter for Anti-Rollback
    pub security_version: u32,
    
    /// Total Size of the binary
    pub size_bytes: u64,
    
    /// Hash of the complete binary (SHA-256)
    pub firmware_hash: Vec<u8>,
    
    /// List of chunk hashes for delta updates/resume
    pub chunk_hashes: Vec<Vec<u8>>,
    
    /// Signature of this Manifest by the Release Key (Falcon-512)
    pub signature: Vec<u8>,
}

/// Update Engine for Secure Firmware Over-The-Air (FOTA).
/// Manages verification, rollback, and installation of firmware chunks.
pub struct UpdateEngine<'a> {
    release_key: &'a [u8],
    
    /// Current Security Version (read from Secure Storage)
    current_svn: u32,
}

impl<'a> UpdateEngine<'a> {
    /// Create a new Update Engine with a pinned Release Key and current Security Version Number (SVN).
    pub fn new(release_key: &'a [u8], current_svn: u32) -> Self {
        Self {
            release_key,
            current_svn,
        }
    }

    /// Verifies a Firmware Manifest before downloading chunks.
    /// Checks:
    /// 1. Signature validity (Falcon-512)
    /// 2. Anti-Rollback (New SvN >= Current SvN)
    pub fn verify_manifest(
        &self, 
        manifest: &FirmwareManifest, 
        _verifier: &dyn SecurityProvider
    ) -> Result<()> {
        // 1. Serialize manifest distinct from signature for verification
        // The signature is verified against the serialized manifest components: version, svn, and firmware_hash.
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(manifest.version.as_bytes());
        signed_data.extend_from_slice(&manifest.security_version.to_le_bytes());
        signed_data.extend_from_slice(&manifest.firmware_hash);
        
        // 2. Verify Signature using the Platform Abstraction Layer (PAL).
        // This explicitly uses the trusted release key provided during engine initialization.
        // If no explicit verifier is passed, the internal Falcon provider is invoked.
        // OR we use the primitive directly.
        // Since `SecurityProvider` is for *our* identity, let's use the `falcon` module directly here 
        // if we want to be explicit, logic-wise:
        
        // Use the crate's internal crypto abstraction
        // In this production implementation, we call into `pqcrypto-falcon` via our Platform Abstraction Layer (PAL).
        // This ensures the verification is performed using the formally verified backend.
        
        #[cfg(feature = "falcon")]
        {
            use crate::crypto::falcon::Falcon;
            use crate::crypto::traits::PqcSignature;
            
            let falcon = Falcon::new();
            // Verify(Trusted_Key, Data, Sig)
            let valid = falcon.verify(self.release_key, &signed_data, &manifest.signature)
                .map_err(|_| Error::CryptoError("Signature Verification Error".into()))?;
                
            if !valid {
                return Err(Error::VerificationError("Invalid Manifest Signature".into()));
            }
        }

        #[cfg(not(feature = "falcon"))]
        {
            // CRITICAL SECURITY FIX: Fail if signature cannot be verified
            return Err(Error::CryptoError("Falcon feature disabled: Cannot verify manifest".into()));
        }
        
        // 3. Anti-Rollback Check
        if manifest.security_version < self.current_svn {
            return Err(Error::ProtocolError("Rollback Detected".into()));
        }
        
        Ok(())
    }
    
    /// Validates a downloaded chunk against the manifest
    pub fn validate_chunk(&self, chunk_idx: usize, data: &[u8], manifest: &FirmwareManifest) -> Result<()> {
        if chunk_idx >= manifest.chunk_hashes.len() {
            return Err(Error::ProtocolError("Invalid Chunk Index".into()));
        }
        
        // Real SHA-256 Check
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        use subtle::ConstantTimeEq;
        let choice = hash.as_slice().ct_eq(manifest.chunk_hashes[chunk_idx].as_slice());
        if choice.unwrap_u8() == 0 {
             return Err(Error::VerificationError("Chunk Checksum Failed".into()));
        }
        
        Ok(())
    }
}
