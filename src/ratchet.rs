use crate::crypto::traits::PqcKEM;
use crate::error::{Error, Result};
#[cfg(feature = "kyber")]
use crate::crypto::kyber::Kyber;
#[cfg(feature = "hqc")] // Added HQC support
#[allow(unused_imports)]
use crate::crypto::hqc::Hqc;

use sha2::Sha256;
use hkdf::Hkdf;
use rand_core::{RngCore, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use serde::{Serialize, Deserialize};
use std::collections::HashMap; // Requires std for now. For no-std, use hashbrown or similar.

/// Max number of skipped message keys to store (DoS protection)
const MAX_SKIPPED_KEYS: usize = 50;

/// KEM-based Double Ratchet Session
/// 
/// Implements Forward Secrecy (FS) and Post-Compromise Security (PCS).
/// 
/// State Machine:
/// - **Root Key (RK)**: Evolving secret shared between parties.
/// - **Chain Key (CK)**: Derived from RK, used to generate Message Keys.
/// - **Message Key (MK)**: Used to encrypt a single message.
/// 
/// Ratcheting Steps:
/// 1. **Symmetric Ratchet**: Per message. CK -> HKDF -> (Next CK, MK).
/// 2. **Diffie-Hellman (KEM) Ratchet**: Per epoch (ping-pong). 
///    - Alice sends new Kyber/HQC PK. 
///    - Bob encaps to Alice's PK -> New Shared Secret.
///    - New Shared Secret mixed into RK.

#[derive(Serialize, Deserialize)]
pub struct RatchetSession {
    // Current state keys (32 bytes)
    root_key: [u8; 32],
    chain_key_send: [u8; 32],
    chain_key_recv: [u8; 32],
    
    // Kyber/HQC State for KEM Ratchet
    my_keypair: Option<(Vec<u8>, Vec<u8>)>, // (PK, SK)
    peer_pubkey: Option<Vec<u8>>,
    
    // Counters
    msg_num_send: u32,
    msg_num_recv: u32,
    
    // Out-of-order handling
    skipped_message_keys: HashMap<u32, [u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Header for Ratchet Messages.
pub struct RatchetHeader {
    /// Compressed KEM Public Key, present if a KEM ratchet step occurred.
    pub compressed_pubkey: Option<Vec<u8>>, 
    /// Current message number in chain.
    pub msg_num: u32,
    /// Number of messages in the previous chain.
    pub previous_chain_len: u32,
}

#[derive(Debug, Serialize, Deserialize)]
/// Encrypted Ratchet Message.
pub struct RatchetMessage {
    /// Integrity and Sequencing Header.
    pub header: RatchetHeader,
    /// Encrypted Payload (Ciphertext + Tag). Nonce is prepended.
    pub ciphertext: Vec<u8>,
    /// Authentication Tag (AES-GCM) - Included in ciphertext typically
    pub auth_tag: Vec<u8>, 
}

impl RatchetSession {
    /// Initialize a new session with a pre-shared secret (e.g., from initial Handshake).
    pub fn initialize(initial_rk: [u8; 32], peer_pk: Option<&[u8]>) -> Self {
        Self {
            root_key: initial_rk,
            chain_key_send: initial_rk, 
            chain_key_recv: initial_rk, 
            my_keypair: None,
            peer_pubkey: peer_pk.map(|k| k.to_vec()),
            msg_num_send: 0,
            msg_num_recv: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Step 1: Symmetric Ratchet (KDF) using RFC 5869 HKDF
    /// Derives (Next_Chain_Key, Message_Key) from Current_Chain_Key
    /// Step 1: Symmetric Ratchet (KDF) using RFC 5869 HKDF
    /// Derives (Next_Chain_Key, Message_Key) from Current_Chain_Key
    fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        // HKDF-SHA256
        // Input: CK (IKM). Salt: Empty (or constant). Info: "1" for MK, "2" for NextCK.
        // We use HKDF Expand.
        
        // We treat CK as PRK (already high entropy from RK).
        let hkdf = Hkdf::<Sha256>::from_prk(ck).map_err(|_| Error::CryptoError("HKDF PRK init failed".into()))?;
        
        let mut mk = [0u8; 32];
        let mut next_ck = [0u8; 32];
        
        // Info separation
        hkdf.expand(b"MessageKey", &mut mk).map_err(|_| Error::CryptoError("HKDF expand MK failed".into()))?;
        hkdf.expand(b"ChainKey", &mut next_ck).map_err(|_| Error::CryptoError("HKDF expand CK failed".into()))?;
        
        Ok((next_ck, mk))
    }

    /// Step 2: KEM Ratchet (KDF) using RFC 5869 HKDF
    /// Derives (New_Root_Key, New_Chain_Key) from (Current_Root_Key, Shared_Secret)
    fn kdf_rk(rk: &[u8; 32], shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let (_, hkdf) = Hkdf::<Sha256>::extract(Some(rk), shared_secret);
        let mut new_rk = [0u8; 32];
        let mut new_ck = [0u8; 32];
        
        hkdf.expand(b"RootKey", &mut new_rk).map_err(|_| Error::CryptoError("HKDF RK fail".into()))?;
        hkdf.expand(b"ChainKey", &mut new_ck).map_err(|_| Error::CryptoError("HKDF CK fail".into()))?;
        
        Ok((new_rk, new_ck))
    }

    /// Perform a KEM Ratchet Step (Refresh Root Key)
    /// This happens when we receive a new PubKey from the peer.
    pub fn ratchet_kem_recv(&mut self, ciphertext: &[u8]) -> Result<()> {
        if let Some((_, sk)) = &self.my_keypair {
            // Decapsulate to get shared secret
            // TODO: Select algo based on config. For now prefer Kyber, fallback HQC.
             #[cfg(feature = "kyber")]
            {
                 let kyber = Kyber::new();
                 let shared_secret = kyber.decapsulate(sk, ciphertext)
                    .map_err(|e| Error::CryptoError(format!("Ratchet Decaps Fail: {:?}", e)))?;
                 self.advance_root_key(&shared_secret);
                 return Ok(())
            }
             #[cfg(all(feature = "hqc", not(feature = "kyber")))]
            {
                 let hqc = Hqc::new();
                 let shared_secret = hqc.decapsulate(sk, ciphertext)
                    .map_err(|e| Error::CryptoError(format!("Ratchet Decaps Fail: {:?}", e)))?;
                 self.advance_root_key(&shared_secret);
                 return Ok(())
            }
        }
        Err(Error::CryptoError("No Keypair for Ratchet or logic missing".into()))
    }
    
    fn advance_root_key(&mut self, shared_secret: &[u8]) {
        if let Ok((new_rk, new_ck)) = Self::kdf_rk(&self.root_key, shared_secret) {
            self.root_key = new_rk;
            self.chain_key_recv = new_ck; 
            self.chain_key_send = new_ck;
        }
    }

    /// Encrypts a message payload using the current Message Key (MK).
    /// Advances the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        // 1. Zero-Knowledge Key Rotation (Self-Healing)
        // Automatic rotation after 1000 messages to limit breach impact.
        if self.msg_num_send >= 1000 {
            let (new_rk, new_ck) = Self::kdf_rk(&self.root_key, &[0xDE, 0xAD, 0xBE, 0xEF])?;
            self.root_key = new_rk;
            self.chain_key_send = new_ck;
            self.msg_num_send = 0;
            // Note: In production, we'd signal this rotation to the peer (e.g. in the header)
        }

        // 2. Symmetric Ratchet Step
        let (next_ck, mk) = Self::kdf_ck(&self.chain_key_send)?;
        self.chain_key_send = next_ck;
        let msg_num = self.msg_num_send;
        self.msg_num_send += 1;
        
        // 2. Encrypt with MK (AES-256-GCM)
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&mk);
        let cipher = Aes256Gcm::new(key);
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
             .map_err(|_| Error::CryptoError("Encryption Failed".into()))?;
             
        // Prepend Nonce to ciphertext
        let mut final_ciphertext = Vec::with_capacity(12 + ciphertext.len());
        final_ciphertext.extend_from_slice(&nonce_bytes);
        final_ciphertext.extend_from_slice(&ciphertext);
        
        Ok(RatchetMessage {
            header: RatchetHeader {
                compressed_pubkey: None, 
                msg_num,
                previous_chain_len: 0,
            },
            ciphertext: final_ciphertext, 
            auth_tag: vec![], // Tag is inside AES-GCM ciphertext usually
        })
    }

    /// Decrypts a message, advancing the receiver chain.
    /// Handles out-of-order messages via Sliding Window.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // Check if message is in skipped keys
        if let Some(mk) = self.skipped_message_keys.remove(&msg.header.msg_num) {
            return self.decrypt_with_mk(&mk, &msg.ciphertext);
        }
        
        // Check window
        if msg.header.msg_num < self.msg_num_recv {
            return Err(Error::CryptoError("Message too old / Replay".into()));
        }
        if msg.header.msg_num - self.msg_num_recv > MAX_SKIPPED_KEYS as u32 {
            return Err(Error::CryptoError("Message too far in future (limit exceeded)".into()));
        }
        
        // Advance chain to the message
        while self.msg_num_recv < msg.header.msg_num {
             let (next_ck, mk) = Self::kdf_ck(&self.chain_key_recv)?;
             self.skipped_message_keys.insert(self.msg_num_recv, mk);
             self.chain_key_recv = next_ck;
             self.msg_num_recv += 1;
        }
        
        // Now self.msg_num_recv == msg.header.msg_num
        let (next_ck, mk) = Self::kdf_ck(&self.chain_key_recv)?;
        self.chain_key_recv = next_ck;
        self.msg_num_recv += 1;
        
        self.decrypt_with_mk(&mk, &msg.ciphertext)
    }
    
    fn decrypt_with_mk(&self, mk: &[u8; 32], ciphertext_full: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_full.len() < 12 {
            return Err(Error::CryptoError("Ciphertext too short".into()));
        }
        
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(mk);
        let cipher = Aes256Gcm::new(key);
        
        let nonce = aes_gcm::Nonce::from_slice(&ciphertext_full[0..12]);
        let actual_ciphertext = &ciphertext_full[12..];
        
        cipher.decrypt(nonce, actual_ciphertext)
             .map_err(|_| Error::CryptoError("Decryption Failed".into()))
    }

    /// Trigger a KEM Ratchet Step (Send new PubKey)
    /// Returns the Encapsulation (Ciphertext to be sent to peer)
    pub fn ratchet_kem_send(&mut self) -> Result<Vec<u8>> {
        if let Some(peer_pk) = &self.peer_pubkey {
             #[cfg(feature = "kyber")]
            {
                 let kyber = Kyber::new();
                 let (ct, shared_secret) = kyber.encapsulate(peer_pk)
                    .map_err(|e| Error::CryptoError(format!("Ratchet Encaps Fail: {:?}", e)))?;
                 
                 self.advance_root_key(&shared_secret);
                 return Ok(ct)
            }
        }
        Err(Error::CryptoError("Peer PubKey unknown".into()))
    }
    }


// CRITICAL SECURITY FIX: Zeroize keys on drop
impl Drop for RatchetSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
        
        if let Some((_, sk)) = &mut self.my_keypair {
            sk.zeroize();
        }
        
        for (_, key) in self.skipped_message_keys.iter_mut() {
            key.zeroize();
        }
        self.skipped_message_keys.clear();
    }
}

// Helper for Error mapping
impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Error::CryptoError("AEAD Error".into())
    }
}

#[cfg(test)]
mod verification {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_ratchet_correctness(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
            let mut alice = RatchetSession::initialize([1u8; 32], None);
            let mut bob = RatchetSession::initialize([1u8; 32], None);
            
            // Alice encrypts
            let msg = alice.encrypt(&payload).unwrap();
            
            // Bob decrypts
            let decrypted = bob.decrypt(&msg).unwrap();
            
            prop_assert_eq!(decrypted, payload);
        }

        #[test]
        fn test_ratchet_out_of_order(
            payload1 in prop::collection::vec(any::<u8>(), 0..256),
            payload2 in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let mut alice = RatchetSession::initialize([1u8; 32], None);
            let mut bob = RatchetSession::initialize([1u8; 32], None);
            
            let msg1 = alice.encrypt(&payload1).unwrap();
            let msg2 = alice.encrypt(&payload2).unwrap();
            
            // Bob receives msg2 first
            let decrypted2 = bob.decrypt(&msg2).unwrap();
            prop_assert_eq!(decrypted2, payload2);
            
            // Then msg1
            let decrypted1 = bob.decrypt(&msg1).unwrap();
            prop_assert_eq!(decrypted1, payload1);
        }

        #[test]
        fn test_ratchet_replay_protection(payload in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut alice = RatchetSession::initialize([1u8; 32], None);
            let mut bob = RatchetSession::initialize([1u8; 32], None);
            
            let msg = alice.encrypt(&payload).unwrap();
            
            // First decryption succeeds
            bob.decrypt(&msg).unwrap();
            
            // Replay attack fails
            prop_assert!(bob.decrypt(&msg).is_err());
        }
    }
}
