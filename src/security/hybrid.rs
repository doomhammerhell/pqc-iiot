use crate::crypto::traits::PqcKEM;
use crate::{Error, Kyber, KyberSecurityLevel, Result}; // Use root exports
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
    Nonce, // AES-256-GCM
};
use alloc::vec::Vec;
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Constants
const NONCE_SIZE: usize = 12;
const X25519_PK_SIZE: usize = 32;

/// Hybrid encryption packet structure (v1):
/// `[version=1][suite=1][capsule_len:u16][capsule][x25519_eph_pk:32][nonce:12][ciphertext+tag]`
///
/// Key derivation:
/// `k = HKDF-SHA256(kyber_ss || x25519_ss, info="pqc-iiot:hybrid:v1:aes-gcm-key")`
pub fn encrypt(target_kem_pk: &[u8], target_x25519_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_v1(target_kem_pk, target_x25519_pk, plaintext, &mut OsRng)
}

/// Encrypt a payload using hybrid KEM v1 (Kyber + X25519 + AES-256-GCM).
///
/// Security properties and invariants:
/// - Confidentiality and integrity are provided by AES-256-GCM.
/// - The AEAD key is derived from *both* the Kyber shared secret and the X25519 DH shared secret.
/// - The packet header is authenticated as AAD to prevent substitution of KEM capsules / eph keys.
///
/// Operational constraints:
/// - `target_x25519_pk` must be exactly 32 bytes.
/// - `target_kem_pk` length determines Kyber parameter set (512/768/1024).
pub fn encrypt_v1<R: RngCore + CryptoRng>(
    target_kem_pk: &[u8],
    target_x25519_pk: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if target_x25519_pk.len() != X25519_PK_SIZE {
        return Err(Error::InvalidInput(format!(
            "Invalid X25519 PK length: {}",
            target_x25519_pk.len()
        )));
    }

    // 1. Determine Kyber level from Key Length
    let kyber = match target_kem_pk.len() {
        800 => Kyber::new_with_level(KyberSecurityLevel::Kyber512),
        1184 => Kyber::new_with_level(KyberSecurityLevel::Kyber768),
        1568 => Kyber::new_with_level(KyberSecurityLevel::Kyber1024),
        len => {
            return Err(Error::CryptoError(alloc::format!(
                "Invalid Kyber PK length: {}",
                len
            )))
        }
    };

    // 2. Encapsulate -> (Capsule, Kyber Shared Secret)
    // Note: encapsulate returns (ciphertext, shared_secret).
    let (capsule, kyber_ss) = kyber.encapsulate(target_kem_pk)?;

    // 3. X25519 ephemeral-static DH
    // `random_from_rng` takes the RNG by value; reborrow to avoid moving our &mut R.
    let eph_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pk = X25519PublicKey::from(&eph_sk).to_bytes();
    let mut peer_x_pk = [0u8; 32];
    peer_x_pk.copy_from_slice(target_x25519_pk);
    let peer_pub = X25519PublicKey::from(peer_x_pk);
    let x_ss = eph_sk.diffie_hellman(&peer_pub).to_bytes();

    // 4. Derive AEAD key via HKDF(kyber_ss || x25519_ss)
    if kyber_ss.len() != 32 {
        return Err(Error::CryptoError(format!(
            "Unexpected Kyber shared secret length: {}",
            kyber_ss.len()
        )));
    }
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&kyber_ss);
    ikm[32..].copy_from_slice(&x_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key_bytes = [0u8; 32];
    hk.expand(b"pqc-iiot:hybrid:v1:aes-gcm-key", &mut key_bytes)
        .map_err(|_| Error::CryptoError("HKDF expand failed".into()))?;

    // 5. Setup AES-GCM
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 6. Generate Nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 7. Serialize header and encrypt (header is AAD)
    // Header: [v][suite][capsule_len][capsule][eph_pk]
    let capsule_len = capsule.len() as u16;
    let mut packet = Vec::with_capacity(
        1 + 1 + 2 + capsule.len() + X25519_PK_SIZE + NONCE_SIZE + plaintext.len() + 16,
    );
    packet.push(1); // version
    packet.push(1); // suite: Kyber + X25519 -> AES-256-GCM
    packet.extend_from_slice(&capsule_len.to_be_bytes());
    packet.extend_from_slice(&capsule);
    packet.extend_from_slice(&eph_pk);

    let aad = packet.as_slice();
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))?;

    // 8. Append nonce + ciphertext
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);

    Ok(packet)
}
/// Decrypt a hybrid packet.
///
/// Expectations:
/// - My Kyber Secret Key (`my_sk`) matches the public key used for encryption.
///   v1: `[1][suite][capsule_len:u16][capsule][x25519_eph_pk:32][nonce:12][ciphertext+tag]`
///   legacy: `[capsule_len:u16][capsule][nonce:12][ciphertext+tag]` (Kyber-only key)
pub fn decrypt_with_exchange<F>(
    my_kem_sk: &[u8],
    packet: &[u8],
    x25519_exchange: F,
) -> Result<Vec<u8>>
where
    F: FnOnce([u8; 32]) -> Result<[u8; 32]>,
{
    if packet.is_empty() {
        return Err(Error::CryptoError("Packet too short".into()));
    }

    if packet[0] == 1 {
        decrypt_v1(my_kem_sk, packet, x25519_exchange)
    } else {
        decrypt_legacy(my_kem_sk, packet)
    }
}

fn decrypt_v1<F>(my_kem_sk: &[u8], packet: &[u8], x25519_exchange: F) -> Result<Vec<u8>>
where
    F: FnOnce([u8; 32]) -> Result<[u8; 32]>,
{
    if packet.len() < 1 + 1 + 2 + X25519_PK_SIZE + NONCE_SIZE {
        return Err(Error::CryptoError("Packet too short".into()));
    }

    let version = packet[0];
    let suite = packet[1];
    if version != 1 {
        return Err(Error::CryptoError(format!(
            "Unsupported packet version: {}",
            version
        )));
    }
    if suite != 1 {
        return Err(Error::CryptoError(format!(
            "Unsupported hybrid suite: {}",
            suite
        )));
    }

    let capsule_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let header_len = 1 + 1 + 2 + capsule_len + X25519_PK_SIZE;
    if packet.len() < header_len + NONCE_SIZE + 16 {
        return Err(Error::CryptoError("Packet too short for capsule".into()));
    }

    let capsule_start = 4;
    let capsule_end = capsule_start + capsule_len;
    let eph_pk_start = capsule_end;
    let eph_pk_end = eph_pk_start + X25519_PK_SIZE;
    let nonce_start = eph_pk_end;
    let nonce_end = nonce_start + NONCE_SIZE;

    let capsule = &packet[capsule_start..capsule_end];
    let eph_pk_bytes = &packet[eph_pk_start..eph_pk_end];
    let nonce_bytes = &packet[nonce_start..nonce_end];
    let ciphertext = &packet[nonce_end..];

    // Determine Kyber level from Secret Key Length.
    let kyber = match my_kem_sk.len() {
        1632 => Kyber::new_with_level(KyberSecurityLevel::Kyber512),
        2400 => Kyber::new_with_level(KyberSecurityLevel::Kyber768),
        3168 => Kyber::new_with_level(KyberSecurityLevel::Kyber1024),
        len => {
            return Err(Error::CryptoError(alloc::format!(
                "Invalid Kyber SK length: {}",
                len
            )))
        }
    };

    let kyber_ss = kyber.decapsulate(my_kem_sk, capsule)?;
    if kyber_ss.len() != 32 {
        return Err(Error::CryptoError(format!(
            "Unexpected Kyber shared secret length: {}",
            kyber_ss.len()
        )));
    }

    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(eph_pk_bytes);
    let x_ss = x25519_exchange(eph_pk)?;

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&kyber_ss);
    ikm[32..].copy_from_slice(&x_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key_bytes = [0u8; 32];
    hk.expand(b"pqc-iiot:hybrid:v1:aes-gcm-key", &mut key_bytes)
        .map_err(|_| Error::CryptoError("HKDF expand failed".into()))?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let aad = &packet[..header_len];
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
}

fn decrypt_legacy(my_kem_sk: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    // Legacy format: [Length(2)] [Capsule] [Nonce(12)] [Ciphertext]
    if packet.len() < 2 {
        return Err(Error::CryptoError("Packet too short".into()));
    }
    let (len_bytes, rest) = packet.split_at(2);
    let capsule_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

    if rest.len() < capsule_len + NONCE_SIZE {
        return Err(Error::CryptoError("Packet too short for capsule".into()));
    }
    let (capsule, rest) = rest.split_at(capsule_len);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_SIZE);

    let kyber = match my_kem_sk.len() {
        1632 => Kyber::new_with_level(KyberSecurityLevel::Kyber512),
        2400 => Kyber::new_with_level(KyberSecurityLevel::Kyber768),
        3168 => Kyber::new_with_level(KyberSecurityLevel::Kyber1024),
        len => {
            return Err(Error::CryptoError(alloc::format!(
                "Invalid Kyber SK length: {}",
                len
            )))
        }
    };

    let shared_secret = kyber.decapsulate(my_kem_sk, capsule)?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
}
