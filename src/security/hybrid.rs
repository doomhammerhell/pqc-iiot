use crate::crypto::traits::PqcKEM;
use crate::{Error, Kyber, KyberSecurityLevel, Result}; // Use root exports
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce, // AES-256-GCM
};
use alloc::vec::Vec;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Constants
const NONCE_SIZE: usize = 12;

/// Hybrid encryption packet structure:
/// [ Capsule Length (2 bytes BE) ] [ Capsule ] [ Nonce (12 bytes) ] [ Ciphertext (includes Tag) ]
pub fn encrypt(target_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // 1. Determine Kyber level from Key Length
    let kyber = match target_pk.len() {
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

    // 2. Encapsulate -> (Capsule, Shared Secret)
    // Note: encapsulate returns (ciphertext, shared_secret) based on our analysis of kyber.rs
    let (capsule, shared_secret) = kyber.encapsulate(target_pk)?;

    // 3. Setup AES-GCM
    // Shared Secret is 32 bytes (for all Kyber levels), fitting AES-256
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
    let cipher = Aes256Gcm::new(key);

    // 4. Generate Nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    // Use OsRng or StdRng? We added rand dependency with std_rng.
    // If no-std, we might need a different source, but we enabled std in Cargo.toml deps for now.
    // We'll use rand::thread_rng() if available via std features
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 5. Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))?;

    // 6. Serialize
    let capsule_len = capsule.len() as u16;
    let mut packet = Vec::with_capacity(2 + capsule.len() + NONCE_SIZE + ciphertext.len());
    packet.extend_from_slice(&capsule_len.to_be_bytes());
    packet.extend_from_slice(&capsule);
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);

    Ok(packet)
}
/// Decrypt a hybrid packet.
///
/// Expectations:
/// - My Kyber Secret Key (`my_sk`) matches the public key used for encryption.
///   Packet format: `[ Length(2) ] [ Capsule ] [ Nonce(12) ] [ Ciphertext ]`
pub fn decrypt(my_sk: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    // 1. Parse header
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

    // 2. Determine Kyber level from Secret Key Length
    let kyber = match my_sk.len() {
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

    // 3. Decapsulate -> Shared Secret
    let shared_secret = kyber.decapsulate(my_sk, capsule)?;

    // 4. Decrypt AES-GCM
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))?;

    Ok(plaintext)
}
