use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::traits::PqcSignature;
use crate::{Error, Falcon, FalconSecurityLevel, Result};

/// Per-peer crypto budget parameters (token bucket).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetParams {
    /// Per-peer token bucket capacity.
    pub per_peer_capacity: u32,
    /// Per-peer token bucket refill rate (tokens per second).
    pub per_peer_refill_per_sec: u32,
    /// Global token bucket capacity (shared across all peers).
    pub global_capacity: u32,
    /// Global token bucket refill rate (tokens per second).
    pub global_refill_per_sec: u32,
}

/// Fleet-wide security policy update, signed by the mesh CA.
///
/// Threat model:
/// - Delivered over an attacker-controlled broker/network; must be verified before applying.
/// - Consumers must enforce `seq` monotonicity to prevent rollback/replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FleetPolicyUpdate {
    /// Schema version for forward compatibility.
    pub version: u8,
    /// Monotonic sequence number for anti-rollback and replay protection.
    pub seq: u64,
    /// Issuance timestamp (unix seconds). Informational unless the verifier has a trusted time source.
    pub issued_at: u64,
    /// If true, require that the `SecurityProvider` backend is rollback-resistant.
    ///
    /// This is a hard safety gate for critical fleets: without rollback-resistant sealing (TPM NV,
    /// HSM, TEE monotonic storage, or a remote append-only service), time windows and replay-state
    /// persistence can be rolled back under filesystem compromise.
    #[serde(default)]
    pub require_rollback_resistant_storage: bool,
    /// If true, reject key announcements without an OperationalCertificate (no TOFU).
    pub strict_mode: bool,
    /// If true, peers are marked trusted only after a verifier-driven attestation roundtrip.
    pub attestation_required: bool,
    /// If true, disallow v1 per-message KEM/signature encryption and require session/ratchet (v2) before sending.
    pub require_sessions: bool,
    /// Optional minimum revocation sequence that must be applied before accepting trust transitions.
    ///
    /// If set, clients should fail closed until they have processed revocation updates up to this `seq`.
    /// This is a partition-resilience mechanism: it prevents accepting fresh identities while missing
    /// emergency revocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_revocation_seq: Option<u64>,
    /// Optional crypto DoS budget overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_verify_budget: Option<BudgetParams>,
    /// Optional decryption/KEM DoS budget overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypt_budget: Option<BudgetParams>,
    /// Optional policy TTL in seconds. If set and secure time is available, new handshakes should fail closed when stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Optional session rekey threshold (messages sent) to enforce periodic re-handshake.
    ///
    /// This is not a DH ratchet, but it is a practical PCS building block for fleets that can
    /// tolerate handshake churn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_rekey_after_msgs: Option<u32>,
    /// Optional session rekey threshold (seconds since session establishment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_rekey_after_secs: Option<u64>,
    /// Detached Falcon signature by the CA over `payload_v1`.
    #[serde(with = "crate::security::keystore::base64_serde")]
    pub signature: Vec<u8>,
}

impl FleetPolicyUpdate {
    /// Current fleet policy schema version.
    pub const VERSION_V1: u8 = 1;
    /// Extended fleet policy schema version (adds storage/time/PCS gates).
    pub const VERSION_V2: u8 = 2;

    fn payload(&self, topic: &str) -> Result<Vec<u8>> {
        match self.version {
            Self::VERSION_V1 => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"pqc-iiot:fleet-policy:v1");
                buf.extend_from_slice(&(topic.len() as u16).to_be_bytes());
                buf.extend_from_slice(topic.as_bytes());
                buf.push(self.version);
                buf.extend_from_slice(&self.seq.to_be_bytes());
                buf.extend_from_slice(&self.issued_at.to_be_bytes());
                buf.push(self.strict_mode as u8);
                buf.push(self.attestation_required as u8);
                buf.push(self.require_sessions as u8);

                match &self.sig_verify_budget {
                    Some(b) => {
                        buf.push(1);
                        buf.extend_from_slice(&b.per_peer_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.per_peer_refill_per_sec.to_be_bytes());
                        buf.extend_from_slice(&b.global_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.global_refill_per_sec.to_be_bytes());
                    }
                    None => buf.push(0),
                }
                match &self.decrypt_budget {
                    Some(b) => {
                        buf.push(1);
                        buf.extend_from_slice(&b.per_peer_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.per_peer_refill_per_sec.to_be_bytes());
                        buf.extend_from_slice(&b.global_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.global_refill_per_sec.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                match self.ttl_secs {
                    Some(ttl) => {
                        buf.push(1);
                        buf.extend_from_slice(&ttl.to_be_bytes());
                    }
                    None => buf.push(0),
                }
                Ok(buf)
            }
            Self::VERSION_V2 => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"pqc-iiot:fleet-policy:v2");
                buf.extend_from_slice(&(topic.len() as u16).to_be_bytes());
                buf.extend_from_slice(topic.as_bytes());
                buf.push(self.version);
                buf.extend_from_slice(&self.seq.to_be_bytes());
                buf.extend_from_slice(&self.issued_at.to_be_bytes());
                buf.push(self.require_rollback_resistant_storage as u8);
                buf.push(self.strict_mode as u8);
                buf.push(self.attestation_required as u8);
                buf.push(self.require_sessions as u8);

                match self.min_revocation_seq {
                    Some(seq) => {
                        buf.push(1);
                        buf.extend_from_slice(&seq.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                match &self.sig_verify_budget {
                    Some(b) => {
                        buf.push(1);
                        buf.extend_from_slice(&b.per_peer_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.per_peer_refill_per_sec.to_be_bytes());
                        buf.extend_from_slice(&b.global_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.global_refill_per_sec.to_be_bytes());
                    }
                    None => buf.push(0),
                }
                match &self.decrypt_budget {
                    Some(b) => {
                        buf.push(1);
                        buf.extend_from_slice(&b.per_peer_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.per_peer_refill_per_sec.to_be_bytes());
                        buf.extend_from_slice(&b.global_capacity.to_be_bytes());
                        buf.extend_from_slice(&b.global_refill_per_sec.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                match self.ttl_secs {
                    Some(ttl) => {
                        buf.push(1);
                        buf.extend_from_slice(&ttl.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                match self.session_rekey_after_msgs {
                    Some(n) => {
                        buf.push(1);
                        buf.extend_from_slice(&n.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                match self.session_rekey_after_secs {
                    Some(n) => {
                        buf.push(1);
                        buf.extend_from_slice(&n.to_be_bytes());
                    }
                    None => buf.push(0),
                }

                Ok(buf)
            }
            v => Err(Error::ProtocolError(format!(
                "Unsupported fleet policy version: {}",
                v
            ))),
        }
    }

    /// Sign this update with the CA secret key for a specific topic scope.
    pub fn sign(&mut self, ca_sig_sk: &[u8], topic: &str) -> Result<()> {
        if self.version == Self::VERSION_V1
            && (self.require_rollback_resistant_storage
                || self.min_revocation_seq.is_some()
                || self.session_rekey_after_msgs.is_some()
                || self.session_rekey_after_secs.is_some())
        {
            return Err(Error::ProtocolError(
                "FleetPolicyUpdate v1 must not set v2-only fields".into(),
            ));
        }
        let payload = self.payload(topic)?;
        let signature = falcon_sign_auto(ca_sig_sk, &payload)?;
        self.signature = signature;
        Ok(())
    }

    /// Verify this update against the pinned CA public key and topic scope.
    pub fn verify(&self, ca_sig_pk: &[u8], topic: &str) -> Result<()> {
        let payload = self.payload(topic)?;
        let ok = falcon_verify_auto(ca_sig_pk, &payload, &self.signature)?;
        if !ok {
            return Err(Error::SignatureVerification(
                "FleetPolicyUpdate signature invalid".into(),
            ));
        }
        if self.version == Self::VERSION_V1
            && (self.require_rollback_resistant_storage
                || self.min_revocation_seq.is_some()
                || self.session_rekey_after_msgs.is_some()
                || self.session_rekey_after_secs.is_some())
        {
            return Err(Error::ProtocolError(
                "FleetPolicyUpdate v1 must not set v2-only fields".into(),
            ));
        }
        Ok(())
    }

    /// Stable 128-bit identifier for observability/deduplication.
    pub fn stable_id(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"pqc-iiot:fleet-policy-id:v1");
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
