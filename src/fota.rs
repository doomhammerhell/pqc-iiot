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

/// Deterministic serialization of the manifest fields that must be authenticated.
fn manifest_sign_payload(manifest: &FirmwareManifest) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(manifest.version.as_bytes());
    data.extend_from_slice(&manifest.security_version.to_le_bytes());
    data.extend_from_slice(&manifest.size_bytes.to_le_bytes());
    data.extend_from_slice(&manifest.firmware_hash);
    data.extend_from_slice(&(manifest.chunk_hashes.len() as u32).to_le_bytes());
    for chunk in &manifest.chunk_hashes {
        data.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        data.extend_from_slice(chunk);
    }
    data
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
        // 1. Canonical payload for signature: includes version, SVN, size and every chunk hash.
        let signed_data = manifest_sign_payload(manifest);
        
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

#[cfg(all(test, feature = "falcon"))]
mod tests {
    use super::*;

    struct NoopProvider;

    impl crate::security::provider::SecurityProvider for NoopProvider {
        fn kem_public_key(&self) -> &[u8] {
            &[]
        }

        fn sig_public_key(&self) -> &[u8] {
            &[]
        }

        fn decrypt(&self, _ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
            unreachable!("not used by this test")
        }

        fn sign(&self, _message: &[u8]) -> crate::Result<Vec<u8>> {
            unreachable!("not used by this test")
        }

        fn export_secret_keys(&self) -> Option<crate::security::provider::ExportedIdentitySecrets> {
            None
        }

        fn seal_data(&self, _label: &str, _data: &[u8]) -> crate::Result<()> {
            unreachable!("not used by this test")
        }

        fn unseal_data(&self, _label: &str) -> crate::Result<Vec<u8>> {
            unreachable!("not used by this test")
        }

        fn generate_quote(
            &self,
            _pcr_indices: &[u32],
            _nonce: &[u8],
        ) -> crate::Result<crate::attestation::quote::AttestationQuote> {
            unreachable!("not used by this test")
        }

        fn x25519_public_key(&self) -> [u8; 32] {
            [0u8; 32]
        }

        fn x25519_exchange(&self, _peer_pk: [u8; 32]) -> crate::Result<[u8; 32]> {
            unreachable!("not used by this test")
        }
    }

    #[test]
    fn manifest_signature_binds_size_and_chunk_hashes() {
        use crate::crypto::falcon::Falcon;
        use crate::crypto::traits::PqcSignature;

        let falcon = Falcon::new();
        let (release_pk, release_sk) = falcon.generate_keypair().expect("keygen");

        let mut manifest = FirmwareManifest {
            version: "1.0.0".to_string(),
            security_version: 10,
            size_bytes: 1234,
            firmware_hash: vec![0xAA; 32],
            chunk_hashes: vec![vec![0x01; 32], vec![0x02; 32]],
            signature: Vec::new(),
        };

        let payload = manifest_sign_payload(&manifest);
        manifest.signature = falcon.sign(&release_sk, &payload).expect("sign");

        let engine = UpdateEngine::new(&release_pk, 0);
        engine
            .verify_manifest(&manifest, &NoopProvider)
            .expect("manifest should verify");

        let mut tampered_chunks = manifest.clone();
        tampered_chunks.chunk_hashes[0][0] ^= 0x01;
        assert!(engine.verify_manifest(&tampered_chunks, &NoopProvider).is_err());

        let mut tampered_size = manifest.clone();
        tampered_size.size_bytes += 1;
        assert!(engine.verify_manifest(&tampered_size, &NoopProvider).is_err());
    }
}
