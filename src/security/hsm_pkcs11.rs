//! PKCS#11-backed HSM integration (gateway).
//!
//! This module is intentionally conservative:
//! - it treats PQC mechanisms as vendor-defined (`u64` mechanism IDs),
//! - it requires key objects to already exist on the token (generated inside the HSM),
//! - it never exports private keys.
//!
//! The runtime contract is minimal:
//! - `sign(message)` delegates to `C_Sign` with a configured mechanism and key handle.
//! - `kem_decapsulate(capsule)` delegates to `C_Decrypt` with a configured mechanism and key handle,
//!   returning the 32-byte shared secret.
//! - optionally, `decrypt_hybrid_v1_in_token` can decrypt hybrid v1 packets fully inside the token
//!   (no exported KEM shared secret) using a `C_DeriveKey`-style KEM mechanism + concat + HKDF
//!   + AES-256-GCM.
//! - optionally, `decrypt_hybrid_v1_full_in_token` can decrypt hybrid v1 packets fully inside the
//!   token **including** X25519 ECDH derivation (no `x25519_ss` materialized in host RAM). This
//!   requires a token-resident EC Montgomery (X25519) private key with `CKA_DERIVE=true`.
//!
//! If your vendor exposes KEM decapsulation via `C_DeriveKey` (returning a non-extractable secret
//! key object) and then expects `C_Decrypt` with that derived key, you must implement a custom
//! backend adapter on top of `cryptoki`.

use crate::security::hsm::PqcHsmBackend;
use crate::{Error, Result};
use alloc::vec::Vec;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::hkdf::{HkdfParams, HkdfSalt};
use cryptoki::mechanism::misc::KeyDerivationStringData;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki::types::Ulong;
use std::sync::Mutex;
use zeroize::Zeroize;

fn der_octet_string(inner: &[u8]) -> Vec<u8> {
    // DER: OCTET STRING (0x04) + len + bytes
    // X25519 public keys are 32 bytes, so short-form length is sufficient.
    let mut out = Vec::with_capacity(2 + inner.len());
    out.push(0x04);
    out.push(inner.len() as u8);
    out.extend_from_slice(inner);
    out
}

/// PKCS#11 PQC mechanism identifiers.
///
/// These are often vendor-defined today; treat them as configuration, not constants.
#[derive(Clone, Copy, Debug)]
pub struct Pkcs11PqcMechanisms {
    /// Signature mechanism (used with `C_Sign*`).
    pub sig_mechanism: u64,
    /// KEM decapsulation mechanism (used with `C_Decrypt*`).
    pub kem_decapsulate_mechanism: u64,
    /// Optional KEM decapsulation mechanism for `C_DeriveKey` (no shared-secret export).
    ///
    /// Vendor contract:
    /// - base key: `kem_key_label` private key object
    /// - params: `CK_KEY_DERIVATION_STRING_DATA` pointing at the capsule bytes
    /// - output: non-extractable 32-byte `CKK_GENERIC_SECRET` secret key object
    pub kem_derive_mechanism: Option<u64>,
}

/// Token + key selector.
#[derive(Clone, Debug)]
pub struct Pkcs11KeySelector {
    /// Token label (preferred for stable deployments). If set, slot discovery searches for this label.
    pub token_label: Option<String>,
    /// Explicit slot number. If set, takes precedence over `token_label`.
    pub slot: Option<u64>,
    /// Key object label for the signature key pair.
    pub sig_key_label: String,
    /// Key object label for the KEM secret key.
    pub kem_key_label: String,
    /// Optional key object label for the X25519 (EC Montgomery) private key.
    ///
    /// When set, the backend can provide a token-resident X25519 identity and support full
    /// in-token hybrid decryption (no exported `x25519_ss`).
    pub x25519_key_label: Option<String>,
}

/// PKCS#11-backed PQC HSM configuration.
#[derive(Clone, Debug)]
pub struct Pkcs11PqcConfig {
    /// Path to the vendor PKCS#11 shared library (`.so`/`.dylib`/`.dll`).
    pub library_path: String,
    /// User PIN for token login (CKU_USER).
    pub user_pin: String,
    /// Mechanism identifiers for PQC operations.
    pub mechanisms: Pkcs11PqcMechanisms,
    /// Token + key selection parameters.
    pub keys: Pkcs11KeySelector,
    /// Public KEM key bytes (exported at provisioning time).
    pub kem_public_key: Vec<u8>,
    /// Public signature key bytes (exported at provisioning time).
    pub sig_public_key: Vec<u8>,
    /// Optional public X25519 (EC Montgomery) key bytes (32 bytes).
    ///
    /// If `keys.x25519_key_label` is set, this must also be set and have length 32.
    pub x25519_public_key: Option<Vec<u8>>,
}

/// PKCS#11-backed PQC HSM backend.
///
/// Threading model:
/// - a single session is held behind a mutex (serialize crypto ops on one token).
/// - if your HSM supports parallel sessions, wrap this in a session pool.
pub struct Pkcs11PqcBackend {
    pkcs11: Option<Pkcs11>,
    slot: Slot,
    session: Mutex<Option<Session>>,
    sig_key: ObjectHandle,
    kem_key: ObjectHandle,
    x25519_key: Option<ObjectHandle>,
    kem_pk: Vec<u8>,
    sig_pk: Vec<u8>,
    x25519_pk: Option<[u8; 32]>,
    mechanisms: Pkcs11PqcMechanisms,
}

impl Pkcs11PqcBackend {
    /// Connect to a PKCS#11 token, login, and locate key objects.
    pub fn new(cfg: Pkcs11PqcConfig) -> Result<Self> {
        let pkcs11 = Pkcs11::new(&cfg.library_path)
            .map_err(|e| Error::ClientError(format!("PKCS#11 library load failed: {}", e)))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Error::ClientError(format!("PKCS#11 initialize failed: {}", e)))?;

        let slot = match cfg.keys.slot {
            Some(n) => Slot::try_from(n)
                .map_err(|e| Error::ClientError(format!("Invalid PKCS#11 slot {}: {}", n, e)))?,
            None => {
                let want_label = cfg.keys.token_label.clone().ok_or_else(|| {
                    Error::InvalidInput("Pkcs11PqcConfig requires slot or token_label".into())
                })?;
                find_slot_by_token_label(&pkcs11, &want_label)?
            }
        };

        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::ClientError(format!("PKCS#11 open session failed: {}", e)))?;

        // Login as user.
        let user_pin = AuthPin::new(cfg.user_pin.into_boxed_str());
        session
            .login(UserType::User, Some(&user_pin))
            .map_err(|e| Error::ClientError(format!("PKCS#11 login failed: {}", e)))?;

        let sig_key = find_key_by_label(&session, &cfg.keys.sig_key_label)?;
        let kem_key = find_key_by_label(&session, &cfg.keys.kem_key_label)?;

        let (x25519_key, x25519_pk) = match cfg.keys.x25519_key_label.as_deref() {
            Some(label) => {
                let pk = cfg.x25519_public_key.ok_or_else(|| {
                    Error::InvalidInput(
                        "Pkcs11PqcConfig.x25519_public_key is required when x25519_key_label is set"
                            .into(),
                    )
                })?;
                if pk.len() != 32 {
                    return Err(Error::InvalidInput(format!(
                        "Invalid X25519 public key length: {}",
                        pk.len()
                    )));
                }
                let mut xpk = [0u8; 32];
                xpk.copy_from_slice(&pk);
                let key = find_private_key_by_label(&session, label, KeyType::EC_MONTGOMERY)?;
                (Some(key), Some(xpk))
            }
            None => (None, None),
        };

        Ok(Self {
            slot,
            pkcs11: Some(pkcs11),
            session: Mutex::new(Some(session)),
            sig_key,
            kem_key,
            x25519_key,
            kem_pk: cfg.kem_public_key,
            sig_pk: cfg.sig_public_key,
            x25519_pk,
            mechanisms: cfg.mechanisms,
        })
    }

    /// PKCS#11 slot backing this backend instance.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    fn with_session<T>(&self, f: impl FnOnce(&Session) -> Result<T>) -> Result<T> {
        let guard = self
            .session
            .lock()
            .map_err(|_| Error::ClientError("PKCS#11 session mutex poisoned".into()))?;
        let session = guard
            .as_ref()
            .ok_or_else(|| Error::ClientError("PKCS#11 session is closed".into()))?;
        f(session)
    }

    fn vendor_mechanism(&self, mechanism_id: u64) -> Result<Mechanism<'static>> {
        let mech_type = MechanismType::new_vendor_defined(mechanism_id).map_err(|_| {
            Error::InvalidInput(format!(
                "Invalid vendor-defined PKCS#11 mechanism: {}",
                mechanism_id
            ))
        })?;
        Ok(Mechanism::VendorDefined(VendorDefinedMechanism::new(
            mech_type,
            None::<&()>,
        )))
    }

    fn sign_inner(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mech = self.vendor_mechanism(self.mechanisms.sig_mechanism)?;
        self.with_session(|sess| {
            sess.sign(&mech, self.sig_key, msg)
                .map_err(|e| Error::CryptoError(format!("PKCS#11 sign failed: {}", e)))
        })
    }

    fn kem_decapsulate_inner(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
        let mech = self.vendor_mechanism(self.mechanisms.kem_decapsulate_mechanism)?;
        let mut out = self.with_session(|sess| {
            sess.decrypt(&mech, self.kem_key, kem_ciphertext)
                .map_err(|e| Error::CryptoError(format!("PKCS#11 decrypt failed: {}", e)))
        })?;
        if out.len() != 32 {
            out.zeroize();
            return Err(Error::CryptoError(format!(
                "Unexpected KEM shared secret length from HSM: {}",
                out.len()
            )));
        }
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&out);
        out.zeroize();
        Ok(ss)
    }

    fn decrypt_hybrid_v1_in_token_inner(
        &self,
        packet: &[u8],
        mut x25519_ss: [u8; 32],
    ) -> Result<Vec<u8>> {
        let derive_mech_id = self.mechanisms.kem_derive_mechanism.ok_or_else(|| {
            Error::ClientError("PKCS#11 KEM derive-key mechanism is not configured".into())
        })?;

        if packet.len() < 1 + 1 + 2 + 32 + 12 {
            return Err(Error::CryptoError("Packet too short".into()));
        }
        if packet[0] != 1 {
            return Err(Error::CryptoError(format!(
                "Unsupported packet version: {}",
                packet[0]
            )));
        }
        if packet[1] != 1 {
            return Err(Error::CryptoError(format!(
                "Unsupported hybrid suite: {}",
                packet[1]
            )));
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

        // All derived keys are session objects (CKA_TOKEN=false) and best-effort destroyed
        // immediately after use.
        let out = self.with_session(|sess| {
            let mut derived: Vec<ObjectHandle> = Vec::new();

            let res = (|| -> Result<Vec<u8>> {
                // 1) Derive a non-extractable secret key for Kyber shared-secret via vendor KEM derive.
                let mech_type =
                    MechanismType::new_vendor_defined(derive_mech_id).map_err(|_| {
                        Error::InvalidInput(format!(
                            "Invalid vendor-defined PKCS#11 mechanism: {}",
                            derive_mech_id
                        ))
                    })?;
                let kem_params = KeyDerivationStringData::new(capsule);
                let kem_mech = Mechanism::VendorDefined(VendorDefinedMechanism::new(
                    mech_type,
                    Some(&kem_params),
                ));

                let ss_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::ValueLen(Ulong::new(32)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                ];
                let ss_key = sess
                    .derive_key(&kem_mech, self.kem_key, &ss_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (KEM) failed: {}", e))
                    })?;
                derived.push(ss_key);

                // 2) Derive IKM key = kyber_ss || x25519_ss via standard concatenation KDF.
                let concat_params = KeyDerivationStringData::new(&x25519_ss);
                let concat_mech = Mechanism::ConcatenateBaseAndData(concat_params);
                let ikm_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::ValueLen(Ulong::new(64)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                ];
                let ikm_key = sess
                    .derive_key(&concat_mech, ss_key, &ikm_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (concat) failed: {}", e))
                    })?;
                derived.push(ikm_key);

                // 3) Derive AES-256 key via HKDF-SHA256(ikm_key, salt=NULL, info=...).
                let hkdf_params = HkdfParams::new(
                    MechanismType::SHA256_HMAC,
                    Some(HkdfSalt::Null),
                    Some(b"pqc-iiot:hybrid:v1:aes-gcm-key"),
                );
                let hkdf_mech = Mechanism::HkdfDerive(hkdf_params);
                let aes_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::ValueLen(Ulong::new(32)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                ];
                let aes_key = sess
                    .derive_key(&hkdf_mech, ikm_key, &aes_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (HKDF) failed: {}", e))
                    })?;
                derived.push(aes_key);

                // 4) AES-256-GCM decrypt with AAD bound to the packet header.
                let mut iv = [0u8; 12];
                iv.copy_from_slice(nonce_bytes);
                let gcm_params = GcmParams::new(&mut iv, aad, Ulong::new(128))
                    .map_err(|e| Error::CryptoError(format!("PKCS#11 GCM params failed: {}", e)))?;
                let aead_mech = Mechanism::AesGcm(gcm_params);
                let plaintext = sess.decrypt(&aead_mech, aes_key, ciphertext).map_err(|e| {
                    Error::CryptoError(format!("PKCS#11 AES-GCM decrypt failed: {}", e))
                })?;

                Ok(plaintext)
            })();

            // Best-effort cleanup.
            for h in derived.into_iter().rev() {
                let _ = sess.destroy_object(h);
            }
            x25519_ss.zeroize();
            res
        })?;
        Ok(out)
    }

    fn decrypt_hybrid_v1_full_in_token_inner(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let derive_mech_id = self.mechanisms.kem_derive_mechanism.ok_or_else(|| {
            Error::ClientError("PKCS#11 KEM derive-key mechanism is not configured".into())
        })?;
        let x25519_key = self.x25519_key.ok_or_else(|| {
            Error::ClientError("PKCS#11 X25519 private key is not configured".into())
        })?;

        if packet.len() < 1 + 1 + 2 + 32 + 12 {
            return Err(Error::CryptoError("Packet too short".into()));
        }
        if packet[0] != 1 {
            return Err(Error::CryptoError(format!(
                "Unsupported packet version: {}",
                packet[0]
            )));
        }
        if packet[1] != 1 {
            return Err(Error::CryptoError(format!(
                "Unsupported hybrid suite: {}",
                packet[1]
            )));
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

        let out = self.with_session(|sess| {
            let mut derived: Vec<ObjectHandle> = Vec::new();

            let res = (|| -> Result<Vec<u8>> {
                // 1) Derive Kyber shared-secret key (non-extractable) via vendor KEM derive.
                let mech_type =
                    MechanismType::new_vendor_defined(derive_mech_id).map_err(|_| {
                        Error::InvalidInput(format!(
                            "Invalid vendor-defined PKCS#11 mechanism: {}",
                            derive_mech_id
                        ))
                    })?;
                let kem_params = KeyDerivationStringData::new(capsule);
                let kem_mech = Mechanism::VendorDefined(VendorDefinedMechanism::new(
                    mech_type,
                    Some(&kem_params),
                ));

                let ss_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::ValueLen(Ulong::new(32)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                ];
                let kyber_ss_key = sess
                    .derive_key(&kem_mech, self.kem_key, &ss_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (KEM) failed: {}", e))
                    })?;
                derived.push(kyber_ss_key);

                // 2) Derive X25519 shared-secret key (non-extractable) via ECDH1 derive.
                let x_ss_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::ValueLen(Ulong::new(32)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                ];
                // Tokens vary on how they expect an X25519 public key to be encoded in
                // `CK_ECDH1_DERIVE_PARAMS.public_data`:
                // - raw 32 bytes (RFC 7748)
                // - DER-encoded OCTET STRING wrapping the 32 bytes (CKA_EC_POINT-like)
                //
                // Try raw first, then fall back to DER OCTET STRING.
                let mut x_ss_key: Option<ObjectHandle> = None;
                let mut last_err: Option<cryptoki::error::Error> = None;
                for cand in [eph_pk_bytes.to_vec(), der_octet_string(eph_pk_bytes)].iter() {
                    let ecdh_params = Ecdh1DeriveParams::new(EcKdf::null(), cand);
                    let ecdh_mech = Mechanism::Ecdh1Derive(ecdh_params);
                    match sess.derive_key(&ecdh_mech, x25519_key, &x_ss_template) {
                        Ok(h) => {
                            x_ss_key = Some(h);
                            break;
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                let x_ss_key = match x_ss_key {
                    Some(h) => h,
                    None => {
                        let e = last_err.unwrap_or(cryptoki::error::Error::InvalidValue);
                        return Err(Error::CryptoError(format!(
                            "PKCS#11 derive_key (ECDH) failed: {}",
                            e
                        )));
                    }
                };
                derived.push(x_ss_key);

                // 3) Derive IKM key = kyber_ss || x25519_ss via standard concatenation KDF (base+key).
                let concat_mech = Mechanism::ConcatenateBaseAndKey(x_ss_key);
                let ikm_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::ValueLen(Ulong::new(64)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                ];
                let ikm_key = sess
                    .derive_key(&concat_mech, kyber_ss_key, &ikm_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (concat) failed: {}", e))
                    })?;
                derived.push(ikm_key);

                // 4) Derive AES-256 key via HKDF-SHA256(ikm_key, salt=NULL, info=...).
                let hkdf_params = HkdfParams::new(
                    MechanismType::SHA256_HMAC,
                    Some(HkdfSalt::Null),
                    Some(b"pqc-iiot:hybrid:v1:aes-gcm-key"),
                );
                let hkdf_mech = Mechanism::HkdfDerive(hkdf_params);
                let aes_template = [
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::ValueLen(Ulong::new(32)),
                    Attribute::Token(false),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                ];
                let aes_key = sess
                    .derive_key(&hkdf_mech, ikm_key, &aes_template)
                    .map_err(|e| {
                        Error::CryptoError(format!("PKCS#11 derive_key (HKDF) failed: {}", e))
                    })?;
                derived.push(aes_key);

                // 5) AES-256-GCM decrypt with AAD bound to the packet header.
                let mut iv = [0u8; 12];
                iv.copy_from_slice(nonce_bytes);
                let gcm_params = GcmParams::new(&mut iv, aad, Ulong::new(128))
                    .map_err(|e| Error::CryptoError(format!("PKCS#11 GCM params failed: {}", e)))?;
                let aead_mech = Mechanism::AesGcm(gcm_params);
                let plaintext = sess.decrypt(&aead_mech, aes_key, ciphertext).map_err(|e| {
                    Error::CryptoError(format!("PKCS#11 AES-GCM decrypt failed: {}", e))
                })?;
                Ok(plaintext)
            })();

            for h in derived.into_iter().rev() {
                let _ = sess.destroy_object(h);
            }
            res
        })?;
        Ok(out)
    }
}

impl Drop for Pkcs11PqcBackend {
    fn drop(&mut self) {
        // Best-effort logout + close session + finalize. Errors are ignored on drop.
        if let Ok(mut guard) = self.session.lock() {
            if let Some(sess) = guard.take() {
                let _ = sess.logout();
                let _ = sess.close();
            }
        }
        if let Some(pkcs11) = self.pkcs11.take() {
            let _ = pkcs11.finalize();
        }
    }
}

impl PqcHsmBackend for Pkcs11PqcBackend {
    fn hsm_kind(&self) -> &'static str {
        "pkcs11"
    }

    fn kem_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.kem_pk.clone())
    }

    fn sig_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.sig_pk.clone())
    }

    fn x25519_public_key(&self) -> Result<Option<[u8; 32]>> {
        Ok(self.x25519_pk)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_inner(message)
    }

    fn kem_decapsulate(&self, kem_ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.kem_decapsulate_inner(kem_ciphertext)
    }

    fn supports_hybrid_v1_in_token_decrypt(&self) -> bool {
        self.mechanisms.kem_derive_mechanism.is_some()
    }

    fn decrypt_hybrid_v1_in_token(&self, packet: &[u8], x25519_ss: [u8; 32]) -> Result<Vec<u8>> {
        self.decrypt_hybrid_v1_in_token_inner(packet, x25519_ss)
    }

    fn supports_hybrid_v1_full_in_token_decrypt(&self) -> bool {
        self.mechanisms.kem_derive_mechanism.is_some() && self.x25519_key.is_some()
    }

    fn decrypt_hybrid_v1_full_in_token(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_hybrid_v1_full_in_token_inner(packet)
    }
}

fn find_slot_by_token_label(pkcs11: &Pkcs11, want_label: &str) -> Result<Slot> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| Error::ClientError(format!("PKCS#11 get_slots_with_token failed: {}", e)))?;
    for slot in slots {
        let info = pkcs11
            .get_token_info(slot)
            .map_err(|e| Error::ClientError(format!("PKCS#11 token_info failed: {}", e)))?;
        let label = info.label().trim();
        if label == want_label.trim() {
            return Ok(slot);
        }
    }
    Err(Error::ClientError(format!(
        "PKCS#11 token not found (label={})",
        want_label
    )))
}

fn find_key_by_label(session: &Session, label: &str) -> Result<ObjectHandle> {
    let template = [Attribute::Label(label.as_bytes().to_vec())];
    let objects = session
        .find_objects(&template)
        .map_err(|e| Error::ClientError(format!("PKCS#11 find_objects failed: {}", e)))?;

    match objects.as_slice() {
        [] => Err(Error::ClientError(format!(
            "PKCS#11 key object not found (label={})",
            label
        ))),
        [one] => Ok(*one),
        _ => Err(Error::ClientError(format!(
            "PKCS#11 key label is not unique (label={}, matches={})",
            label,
            objects.len()
        ))),
    }
}

fn find_private_key_by_label(
    session: &Session,
    label: &str,
    key_type: KeyType,
) -> Result<ObjectHandle> {
    let template = [
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(key_type),
    ];
    let objects = session
        .find_objects(&template)
        .map_err(|e| Error::ClientError(format!("PKCS#11 find_objects failed: {}", e)))?;

    match objects.as_slice() {
        [] => Err(Error::ClientError(format!(
            "PKCS#11 private key object not found (label={})",
            label
        ))),
        [one] => Ok(*one),
        _ => Err(Error::ClientError(format!(
            "PKCS#11 private key label is not unique (label={}, matches={})",
            label,
            objects.len()
        ))),
    }
}
