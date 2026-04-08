use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::traits::PqcSignature;
use crate::{Error, Falcon, FalconSecurityLevel, Result};

/// A single revocation entry targeting a specific certified `key_id` for a device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Device identifier (must match the OperationalCertificate `device_id` / MQTT peer_id).
    pub device_id: String,
    /// Revoked key identifier (OperationalCertificate `key_id`, 16 bytes).
    #[serde(with = "crate::security::keystore::base64_serde")]
    pub key_id: Vec<u8>,
}

/// A CA-signed revocation update message (CRL-like).
///
/// Security model:
/// - The update is authenticated by a detached Falcon signature from the mesh CA.
/// - Consumers must enforce `seq` monotonicity to prevent rollback/replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationUpdate {
    /// Schema version for forward compatibility.
    pub version: u8,
    /// Monotonic sequence number for anti-rollback and replay protection.
    pub seq: u64,
    /// Issuance timestamp (unix seconds). Informational unless the verifier has a trusted time source.
    pub issued_at: u64,
    /// Revocation entries.
    pub entries: Vec<RevocationEntry>,
    /// Detached Falcon signature by the CA over `payload_v1`.
    #[serde(with = "crate::security::keystore::base64_serde")]
    pub signature: Vec<u8>,
}

impl RevocationUpdate {
    /// Current revocation update schema version.
    pub const VERSION_V1: u8 = 1;

    fn payload_v1(&self, topic: &str) -> Result<Vec<u8>> {
        if self.version != Self::VERSION_V1 {
            return Err(Error::ProtocolError(format!(
                "Unsupported revocation version: {}",
                self.version
            )));
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(b"pqc-iiot:revocation:v1");
        buf.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        buf.extend_from_slice(topic.as_bytes());
        buf.push(self.version);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            if entry.key_id.len() != 16 {
                return Err(Error::InvalidInput(format!(
                    "Invalid revocation key_id length: {}",
                    entry.key_id.len()
                )));
            }
            buf.extend_from_slice(&(entry.device_id.len() as u16).to_be_bytes());
            buf.extend_from_slice(entry.device_id.as_bytes());
            buf.extend_from_slice(&(entry.key_id.len() as u16).to_be_bytes());
            buf.extend_from_slice(&entry.key_id);
        }
        Ok(buf)
    }

    /// Sign this update with the CA secret key for a specific MQTT topic scope.
    pub fn sign(&mut self, ca_sig_sk: &[u8], topic: &str) -> Result<()> {
        let payload = self.payload_v1(topic)?;
        let signature = falcon_sign_auto(ca_sig_sk, &payload)?;
        self.signature = signature;
        Ok(())
    }

    /// Verify this update against the pinned CA public key and topic scope.
    pub fn verify(&self, ca_sig_pk: &[u8], topic: &str) -> Result<()> {
        let payload = self.payload_v1(topic)?;
        let ok = falcon_verify_auto(ca_sig_pk, &payload, &self.signature)?;
        if !ok {
            return Err(Error::SignatureVerification(
                "RevocationUpdate signature invalid".into(),
            ));
        }
        Ok(())
    }

    /// A stable 128-bit identifier for observability/deduplication.
    pub fn stable_id(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"pqc-iiot:revocation-id:v1");
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.seq.to_be_bytes());
        hasher.update(self.issued_at.to_be_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }
}

fn falcon_verify_auto(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
    let level = match pk.len() {
        897 => FalconSecurityLevel::Falcon512,
        1793 => FalconSecurityLevel::Falcon1024,
        _ => {
            return Err(Error::InvalidInput(format!(
                "Invalid Falcon public key length: {}",
                pk.len()
            )))
        }
    };
    let falcon = Falcon::new_with_level(level);
    falcon.verify(pk, msg, sig)
}

fn falcon_sign_auto(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let level = match sk.len() {
        1281 => FalconSecurityLevel::Falcon512,
        2305 => FalconSecurityLevel::Falcon1024,
        _ => {
            return Err(Error::InvalidInput(format!(
                "Invalid Falcon secret key length: {}",
                sk.len()
            )))
        }
    };
    let falcon = Falcon::new_with_level(level);
    falcon.sign(sk, msg)
}
