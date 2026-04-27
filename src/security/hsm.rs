use crate::security::provider::SecurityProvider;
use crate::security::root_of_trust::RootOfTrust;
use crate::{Error, Result};
use rand_core::OsRng;
use rand_core::RngCore;
use sha2::Digest;
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// PQC-capable HSM backend boundary.
///
/// This models the subset we need for gateway-grade deployments:
/// - non-exportable long-term signature key (`sign`)
/// - non-exportable long-term KEM secret key (`kem_decapsulate`)
/// - stable export of public keys (for certificates + announcements)
///
/// Notes:
/// - KEM encapsulation does not require the HSM (recipient public key is public); we only require
///   decapsulation to keep the KEM secret key non-exportable.
/// - Many real HSMs expose PQC via PKCS#11 vendor-defined mechanisms. The `hsm_pkcs11` module
///   implements a concrete backend when enabled.
pub trait PqcHsmBackend: Send + Sync {
    /// Human-readable backend kind string for observability.
    fn hsm_kind(&self) -> &'static str;

    /// Return the PQC KEM public key bytes.
    fn kem_public_key(&self) -> Result<Vec<u8>>;

    /// Return the PQC signature public key bytes.
    fn sig_public_key(&self) -> Result<Vec<u8>>;

    /// Optional token-resident X25519 identity public key (32 bytes).
    ///
    /// When present, the gateway provider treats X25519 as a non-exportable HSM identity key.
    /// That implies:
    /// - the provider will not store an X25519 static secret in host memory, and
    /// - decrypt must use `decrypt_hybrid_v1_full_in_token` for v1 packets (no exported `x25519_ss`).
    fn x25519_public_key(&self) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    /// Sign a message using the HSM-resident signature secret key.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Decapsulate a KEM capsule and return the 32-byte shared secret.
    fn kem_decapsulate(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]>;

    /// Return `true` if this backend can decrypt hybrid v1 packets fully inside the token
    /// (i.e., without exporting the KEM shared secret to host memory).
    ///
    /// This requires **more** than decapsulation:
    /// - KEM decapsulation producing a non-extractable secret key object (`C_DeriveKey`-style),
    /// - key derivation capabilities (concat + HKDF),
    /// - AES-256-GCM decrypt on a non-extractable key.
    ///
    /// If `false`, callers must assume that KEM shared secrets will be materialized in-process.
    fn supports_hybrid_v1_in_token_decrypt(&self) -> bool {
        false
    }

    /// Decrypt a hybrid v1 packet fully inside the token (no exported KEM shared secret).
    ///
    /// Callers must provide the X25519 shared secret bytes (derived from the peer ephemeral pubkey
    /// in the packet and the local X25519 static secret).
    ///
    /// Backends that do not support this must leave the default implementation in place.
    fn decrypt_hybrid_v1_in_token(&self, _packet: &[u8], _x25519_ss: [u8; 32]) -> Result<Vec<u8>> {
        Err(Error::ClientError(
            "HSM backend does not support in-token hybrid v1 decrypt".into(),
        ))
    }

    /// Return `true` if this backend can decrypt hybrid v1 packets fully inside the token
    /// **including** X25519 ECDH derivation.
    ///
    /// This is the strictest mode:
    /// - no KEM shared secret is exported to host memory
    /// - no X25519 shared secret is exported to host memory
    ///
    /// Backends implementing this are expected to hold an X25519 (EC Montgomery) private key
    /// inside the token and derive a non-extractable secret key via `C_DeriveKey` using ECDH.
    fn supports_hybrid_v1_full_in_token_decrypt(&self) -> bool {
        false
    }

    /// Decrypt a hybrid v1 packet fully inside the token, including X25519 ECDH.
    fn decrypt_hybrid_v1_full_in_token(&self, _packet: &[u8]) -> Result<Vec<u8>> {
        Err(Error::ClientError(
            "HSM backend does not support full in-token hybrid v1 decrypt".into(),
        ))
    }
}

fn is_filesystem_safe_id(id: &str) -> bool {
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn storage_id_for(client_id: &str) -> String {
    let is_safe = is_filesystem_safe_id(client_id);
    if is_safe && client_id.len() <= 128 {
        client_id.to_string()
    } else {
        let digest = sha2::Sha256::digest(client_id.as_bytes());
        format!("id_{}", hex::encode(digest))
    }
}

fn x25519_secret_label(storage_id: &str) -> String {
    format!("pqc-iiot:x25519-sk:v1:{}", storage_id)
}

/// Gateway-grade provider combining:
/// - PQC operations inside an HSM (`PqcHsmBackend`)
/// - rollback-resistant persistence via a Root-of-Trust (`RootOfTrust`)
/// - a classical X25519 static secret for the hybrid scheme (sealed via the RoT)
///
/// This is the practical “market path” for Linux gateways:
/// - TPM2 provides anti-rollback counters/sealing for floors + replay-state.
/// - PKCS#11 HSM provides non-exportable PQC identity operations.
pub struct GatewayHsmSecurityProvider {
    hsm: Arc<dyn PqcHsmBackend>,
    rot: Arc<dyn RootOfTrust>,
    kem_pk: Vec<u8>,
    sig_pk: Vec<u8>,
    x25519_sk: Option<X25519StaticSecret>,
    x25519_pk: [u8; 32],
    storage_id: String,
}

impl GatewayHsmSecurityProvider {
    /// Create a gateway provider bound to `client_id`.
    ///
    /// The `client_id` is normalized into a stable `storage_id` to derive sealed labels. This must
    /// match the `SecureMqttClient` storage identity derivation for operational cert binding.
    pub fn new(
        client_id: &str,
        hsm: Arc<dyn PqcHsmBackend>,
        rot: Arc<dyn RootOfTrust>,
    ) -> Result<Self> {
        let storage_id = storage_id_for(client_id);
        let kem_pk = hsm.kem_public_key()?;
        let sig_pk = hsm.sig_public_key()?;

        // X25519 identity key source:
        // - if the HSM backend provides a token-resident X25519 public key, we treat X25519 as
        //   non-exportable and rely on `decrypt_hybrid_v1_full_in_token` for v1 packets.
        // - otherwise, we keep a software X25519 static secret sealed by the RoT (legacy gateway
        //   mode; not "zero secrets in host").
        let (x25519_sk, x25519_pk) = match hsm.x25519_public_key()? {
            Some(pk) => {
                if !hsm.supports_hybrid_v1_full_in_token_decrypt() {
                    return Err(Error::ClientError(
                        "HSM provides X25519 identity but does not support full in-token decrypt"
                            .into(),
                    ));
                }
                (None, pk)
            }
            None => {
                // Load or generate the X25519 static secret sealed by the RoT.
                let label = x25519_secret_label(&storage_id);
                let sk_bytes = match rot.unseal_data(&label) {
                    Ok(blob) => {
                        if blob.len() != 32 {
                            return Err(Error::CryptoError(format!(
                                "Invalid sealed x25519 secret length: {}",
                                blob.len()
                            )));
                        }
                        let mut b = [0u8; 32];
                        b.copy_from_slice(&blob);
                        b
                    }
                    Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        let mut b = [0u8; 32];
                        OsRng.fill_bytes(&mut b);
                        rot.seal_data(&label, &b)?;
                        b
                    }
                    Err(e) => return Err(e),
                };
                let sk = X25519StaticSecret::from(sk_bytes);
                let pk = X25519PublicKey::from(&sk).to_bytes();
                (Some(sk), pk)
            }
        };

        Ok(Self {
            hsm,
            rot,
            kem_pk,
            sig_pk,
            x25519_sk,
            x25519_pk,
            storage_id,
        })
    }

    /// Observability: HSM kind string.
    pub fn hsm_kind(&self) -> &'static str {
        self.hsm.hsm_kind()
    }

    /// Observability: RoT kind string.
    pub fn rot_kind(&self) -> &'static str {
        self.rot.rot_kind()
    }

    /// Stable storage identifier derived from `client_id`.
    pub fn storage_id(&self) -> &str {
        &self.storage_id
    }
}

impl SecurityProvider for GatewayHsmSecurityProvider {
    fn kem_public_key(&self) -> &[u8] {
        &self.kem_pk
    }

    fn sig_public_key(&self) -> &[u8] {
        &self.sig_pk
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Prefer strict full in-token decrypt when available:
        // - Kyber shared secret is never exported
        // - X25519 shared secret is never exported
        if self.hsm.supports_hybrid_v1_full_in_token_decrypt()
            && ciphertext.first().copied() == Some(1)
        {
            return self.hsm.decrypt_hybrid_v1_full_in_token(ciphertext);
        }

        // Prefer an in-token decrypt path when the backend guarantees that the KEM shared secret
        // is never exported to host memory.
        if self.hsm.supports_hybrid_v1_in_token_decrypt()
            && ciphertext.first().copied() == Some(1)
            && ciphertext.len() >= 4 + 32
        {
            let capsule_len = u16::from_be_bytes([ciphertext[2], ciphertext[3]]) as usize;
            let eph_pk_start = 4usize
                .checked_add(capsule_len)
                .ok_or_else(|| Error::CryptoError("Packet too short".into()))?;
            let eph_pk_end = eph_pk_start
                .checked_add(32)
                .ok_or_else(|| Error::CryptoError("Packet too short".into()))?;
            if ciphertext.len() < eph_pk_end {
                return Err(Error::CryptoError("Packet too short for capsule".into()));
            }
            let mut peer_pk = [0u8; 32];
            peer_pk.copy_from_slice(&ciphertext[eph_pk_start..eph_pk_end]);
            let x_ss = self.x25519_exchange(peer_pk)?;
            return self.hsm.decrypt_hybrid_v1_in_token(ciphertext, x_ss);
        }

        // Fallback: decrypt using the HSM KEM decapsulation (shared secret exported) + local X25519 exchange.
        crate::security::hybrid::decrypt_with_kem_and_exchange(
            ciphertext,
            |ct| self.hsm.kem_decapsulate(ct),
            |peer_pk| self.x25519_exchange(peer_pk),
        )
    }

    fn kem_decapsulate(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.hsm.kem_decapsulate(kem_ciphertext)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.hsm.sign(message)
    }

    fn export_secret_keys(&self) -> Option<crate::security::provider::ExportedIdentitySecrets> {
        None
    }

    fn provider_kind(&self) -> &'static str {
        "gateway-hsm"
    }

    fn is_rollback_resistant_storage(&self) -> bool {
        self.rot.is_rollback_resistant_storage()
    }

    fn seal_data(&self, label: &str, data: &[u8]) -> Result<()> {
        self.rot.seal_data(label, data)
    }

    fn unseal_data(&self, label: &str) -> Result<Vec<u8>> {
        self.rot.unseal_data(label)
    }

    fn sealed_monotonic_u64_get(&self, label: &str) -> Result<Option<u64>> {
        self.rot.sealed_monotonic_u64_get(label)
    }

    fn sealed_monotonic_u64_advance_to(&self, label: &str, candidate: u64) -> Result<bool> {
        self.rot.sealed_monotonic_u64_advance_to(label, candidate)
    }

    fn sealed_monotonic_u64_increment(&self, label: &str) -> Result<u64> {
        self.rot.sealed_monotonic_u64_increment(label)
    }

    fn generate_quote(
        &self,
        _pcr_indices: &[u32],
        _nonce: &[u8],
    ) -> Result<crate::attestation::quote::AttestationQuote> {
        Err(Error::ClientError(
            "Attestation quotes are not supported by GatewayHsmSecurityProvider".into(),
        ))
    }

    fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_pk
    }

    fn x25519_exchange(&self, peer_pk: [u8; 32]) -> Result<[u8; 32]> {
        let sk = self.x25519_sk.as_ref().ok_or_else(|| {
            Error::ClientError(
                "X25519 exchange is not available (identity key is token-resident)".into(),
            )
        })?;
        let pk = X25519PublicKey::from(peer_pk);
        Ok(sk.diffie_hellman(&pk).to_bytes())
    }
}

impl Drop for GatewayHsmSecurityProvider {
    fn drop(&mut self) {
        // Best-effort memory scrubbing of cached public keys. HSM keys remain non-exportable.
        self.kem_pk.zeroize();
        self.sig_pk.zeroize();
        self.storage_id.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::falcon::Falcon;
    use crate::crypto::kyber::Kyber;
    use crate::crypto::traits::{PqcKEM, PqcSignature};
    use crate::security::root_of_trust::SoftwareRootOfTrust;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;

    struct MockHsm {
        kem_pk: Vec<u8>,
        kem_sk: Vec<u8>,
        sig_pk: Vec<u8>,
        sig_sk: Vec<u8>,
    }

    impl MockHsm {
        fn new() -> Self {
            let kyber = Kyber::new();
            let falcon = Falcon::new();
            let (kem_pk, kem_sk) = kyber.generate_keypair().unwrap();
            let (sig_pk, sig_sk) = falcon.generate_keypair().unwrap();
            Self {
                kem_pk,
                kem_sk,
                sig_pk,
                sig_sk,
            }
        }
    }

    impl PqcHsmBackend for MockHsm {
        fn hsm_kind(&self) -> &'static str {
            "mock-hsm"
        }

        fn kem_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.kem_pk.clone())
        }

        fn sig_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.sig_pk.clone())
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let falcon = Falcon::new();
            falcon
                .sign(&self.sig_sk, message)
                .map_err(|e| Error::CryptoError(format!("MockHsm falcon sign failed: {:?}", e)))
        }

        fn kem_decapsulate(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
            let kyber = Kyber::new();
            let mut ss = kyber
                .decapsulate(&self.kem_sk, kem_ciphertext)
                .map_err(|e| Error::CryptoError(format!("MockHsm kyber decap failed: {:?}", e)))?;
            if ss.len() != 32 {
                ss.zeroize();
                return Err(Error::CryptoError(format!(
                    "Unexpected shared secret length: {}",
                    ss.len()
                )));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&ss);
            ss.zeroize();
            Ok(out)
        }
    }

    struct MockInTokenHsm {
        kem_pk: Vec<u8>,
        kem_sk: Vec<u8>,
        sig_pk: Vec<u8>,
        sig_sk: Vec<u8>,
    }

    impl MockInTokenHsm {
        fn new() -> Self {
            let kyber = Kyber::new();
            let falcon = Falcon::new();
            let (kem_pk, kem_sk) = kyber.generate_keypair().unwrap();
            let (sig_pk, sig_sk) = falcon.generate_keypair().unwrap();
            Self {
                kem_pk,
                kem_sk,
                sig_pk,
                sig_sk,
            }
        }
    }

    impl PqcHsmBackend for MockInTokenHsm {
        fn hsm_kind(&self) -> &'static str {
            "mock-in-token"
        }

        fn kem_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.kem_pk.clone())
        }

        fn sig_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.sig_pk.clone())
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let falcon = Falcon::new();
            falcon.sign(&self.sig_sk, message)
        }

        fn kem_decapsulate(&self, _kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
            panic!("kem_decapsulate must not be called when in-token decrypt is supported");
        }

        fn supports_hybrid_v1_in_token_decrypt(&self) -> bool {
            true
        }

        fn decrypt_hybrid_v1_in_token(
            &self,
            packet: &[u8],
            mut x25519_ss: [u8; 32],
        ) -> Result<Vec<u8>> {
            // Mirror `hybrid::decrypt_v1_with_kem` but take x25519_ss as input.
            if packet.len() < 1 + 1 + 2 + 32 + 12 {
                return Err(Error::CryptoError("Packet too short".into()));
            }
            let capsule_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            let header_len = 1 + 1 + 2 + capsule_len + 32;
            if packet.len() < header_len + 12 + 16 {
                return Err(Error::CryptoError("Packet too short for capsule".into()));
            }

            let capsule_start = 4;
            let capsule_end = capsule_start + capsule_len;
            let nonce_start = header_len;
            let nonce_end = nonce_start + 12;

            let capsule = &packet[capsule_start..capsule_end];
            let nonce_bytes = &packet[nonce_start..nonce_end];
            let ciphertext = &packet[nonce_end..];
            let aad = &packet[..header_len];

            let kyber = match self.kem_sk.len() {
                1632 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber512),
                2400 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber768),
                3168 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber1024),
                len => {
                    return Err(Error::CryptoError(alloc::format!(
                        "Invalid Kyber SK length: {}",
                        len
                    )))
                }
            };
            let mut kyber_ss = kyber.decapsulate(&self.kem_sk, capsule)?;
            if kyber_ss.len() != 32 {
                kyber_ss.zeroize();
                return Err(Error::CryptoError(format!(
                    "Unexpected Kyber shared secret length: {}",
                    kyber_ss.len()
                )));
            }

            let mut ikm = [0u8; 64];
            ikm[..32].copy_from_slice(&kyber_ss);
            ikm[32..].copy_from_slice(&x25519_ss);
            kyber_ss.zeroize();
            x25519_ss.zeroize();

            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut key_bytes = [0u8; 32];
            hk.expand(b"pqc-iiot:hybrid:v1:aes-gcm-key", &mut key_bytes)
                .map_err(|_| Error::CryptoError("HKDF expand failed".into()))?;

            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes));
            let out = cipher
                .decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))?;

            key_bytes.zeroize();
            ikm.zeroize();
            Ok(out)
        }
    }

    struct MockFullInTokenHsm {
        kem_pk: Vec<u8>,
        kem_sk: Vec<u8>,
        sig_pk: Vec<u8>,
        sig_sk: Vec<u8>,
        x25519_sk: X25519StaticSecret,
        x25519_pk: [u8; 32],
    }

    impl MockFullInTokenHsm {
        fn new() -> Self {
            let kyber = Kyber::new();
            let falcon = Falcon::new();
            let (kem_pk, kem_sk) = kyber.generate_keypair().unwrap();
            let (sig_pk, sig_sk) = falcon.generate_keypair().unwrap();
            let x25519_sk = X25519StaticSecret::random_from_rng(OsRng);
            let x25519_pk = X25519PublicKey::from(&x25519_sk).to_bytes();
            Self {
                kem_pk,
                kem_sk,
                sig_pk,
                sig_sk,
                x25519_sk,
                x25519_pk,
            }
        }
    }

    impl PqcHsmBackend for MockFullInTokenHsm {
        fn hsm_kind(&self) -> &'static str {
            "mock-full-in-token"
        }

        fn kem_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.kem_pk.clone())
        }

        fn sig_public_key(&self) -> Result<Vec<u8>> {
            Ok(self.sig_pk.clone())
        }

        fn x25519_public_key(&self) -> Result<Option<[u8; 32]>> {
            Ok(Some(self.x25519_pk))
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let falcon = Falcon::new();
            falcon.sign(&self.sig_sk, message)
        }

        fn kem_decapsulate(&self, _kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
            panic!("kem_decapsulate must not be called when full in-token decrypt is supported");
        }

        fn supports_hybrid_v1_full_in_token_decrypt(&self) -> bool {
            true
        }

        fn decrypt_hybrid_v1_full_in_token(&self, packet: &[u8]) -> Result<Vec<u8>> {
            if packet.len() < 1 + 1 + 2 + 32 + 12 {
                return Err(Error::CryptoError("Packet too short".into()));
            }
            let capsule_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            let header_len = 1 + 1 + 2 + capsule_len + 32;
            if packet.len() < header_len + 12 + 16 {
                return Err(Error::CryptoError("Packet too short for capsule".into()));
            }

            let capsule_start = 4;
            let capsule_end = capsule_start + capsule_len;
            let eph_pk_start = capsule_end;
            let eph_pk_end = eph_pk_start + 32;
            let nonce_start = eph_pk_end;
            let nonce_end = nonce_start + 12;

            let capsule = &packet[capsule_start..capsule_end];
            let eph_pk_bytes = &packet[eph_pk_start..eph_pk_end];
            let nonce_bytes = &packet[nonce_start..nonce_end];
            let ciphertext = &packet[nonce_end..];
            let aad = &packet[..header_len];

            let kyber = match self.kem_sk.len() {
                1632 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber512),
                2400 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber768),
                3168 => Kyber::new_with_level(crate::KyberSecurityLevel::Kyber1024),
                len => {
                    return Err(Error::CryptoError(alloc::format!(
                        "Invalid Kyber SK length: {}",
                        len
                    )))
                }
            };
            let mut kyber_ss = kyber.decapsulate(&self.kem_sk, capsule)?;
            if kyber_ss.len() != 32 {
                kyber_ss.zeroize();
                return Err(Error::CryptoError(format!(
                    "Unexpected Kyber shared secret length: {}",
                    kyber_ss.len()
                )));
            }

            let mut eph_pk = [0u8; 32];
            eph_pk.copy_from_slice(eph_pk_bytes);
            let peer_pk = X25519PublicKey::from(eph_pk);
            let mut x_ss = self.x25519_sk.diffie_hellman(&peer_pk).to_bytes();

            let mut ikm = [0u8; 64];
            ikm[..32].copy_from_slice(&kyber_ss);
            ikm[32..].copy_from_slice(&x_ss);
            kyber_ss.zeroize();
            x_ss.zeroize();

            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut key_bytes = [0u8; 32];
            hk.expand(b"pqc-iiot:hybrid:v1:aes-gcm-key", &mut key_bytes)
                .map_err(|_| Error::CryptoError("HKDF expand failed".into()))?;

            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes));
            let out = cipher
                .decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))?;

            key_bytes.zeroize();
            ikm.zeroize();
            Ok(out)
        }
    }

    #[test]
    fn gateway_hsm_provider_roundtrips_hybrid_packets_and_signatures() {
        let hsm = Arc::new(MockHsm::new());
        let rot = Arc::new(SoftwareRootOfTrust::new([0x55u8; 32]));
        let provider = GatewayHsmSecurityProvider::new("gw-1", hsm, rot).unwrap();

        // Hybrid encrypt to the provider's identity.
        let pt = b"hello";
        let blob = crate::security::hybrid::encrypt(
            provider.kem_public_key(),
            &provider.x25519_public_key(),
            pt,
        )
        .unwrap();
        let out = provider.decrypt(&blob).unwrap();
        assert_eq!(out, pt);

        // Sign/verify (public key is exported; SK is non-exportable in the backend model).
        let msg = b"pqc-iiot:test";
        let sig = provider.sign(msg).unwrap();
        let falcon = Falcon::new();
        let ok = falcon.verify(provider.sig_public_key(), msg, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn gateway_hsm_provider_uses_in_token_decrypt_when_supported() {
        let hsm = Arc::new(MockInTokenHsm::new());
        let rot = Arc::new(SoftwareRootOfTrust::new([0x55u8; 32]));
        let provider = GatewayHsmSecurityProvider::new("gw_hsm_in_token", hsm, rot).unwrap();

        let msg = b"hello";
        let blob = crate::security::hybrid::encrypt(
            provider.kem_public_key(),
            &provider.x25519_public_key(),
            msg,
        )
        .unwrap();

        let out = provider.decrypt(&blob).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn gateway_hsm_provider_uses_full_in_token_decrypt_when_x25519_is_token_resident() {
        let hsm = Arc::new(MockFullInTokenHsm::new());
        let rot = Arc::new(SoftwareRootOfTrust::new([0x55u8; 32]));
        let provider =
            GatewayHsmSecurityProvider::new("gw_hsm_full_in_token", hsm.clone(), rot).unwrap();

        assert_eq!(provider.x25519_public_key(), hsm.x25519_pk);
        assert!(provider.x25519_exchange([0u8; 32]).is_err());

        let msg = b"hello";
        let blob = crate::security::hybrid::encrypt(
            provider.kem_public_key(),
            &provider.x25519_public_key(),
            msg,
        )
        .unwrap();

        let out = provider.decrypt(&blob).unwrap();
        assert_eq!(out, msg);
    }
}
