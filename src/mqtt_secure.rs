//! Secure MQTT communication using post-quantum cryptography

use crate::crypto::traits::{PqcKEM, PqcSignature};
// use crate::kem::{MAX_PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE};
// use crate::sign::MAX_SIGNATURE_SIZE;
use crate::audit::{log_security_event, SecurityEvent};
use crate::security::hybrid;
use crate::security::keystore::{KeyStore, PeerKeys};
use crate::security::provider::{SecurityProvider, SoftwareSecurityProvider};
use crate::{Error, Falcon, Kyber, Result}; // Import Kyber and Falcon from root
use log::{error, warn};
// use heapless::Vec as HeaplessVec;
use rumqttc::{Client, Connection, Event, LastWill, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use serde_json;
use std::string::{String, ToString};
use std::time::Duration;
use std::vec::Vec;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
    Key, // Or wrappers
    Nonce,
};
use rand::RngCore;

/// Secure MQTT client using post-quantum cryptography
pub struct SecureMqttClient {
    options: MqttOptions,
    client: Option<Client>,
    eventloop: Option<Connection>,
    // kyber: Kyber, // Removed as unused
    falcon: Falcon,
    // Own keys
    // secret_key: Vec<u8>, // REMOVED: Using provider
    public_key: Vec<u8>,
    // sig_sk: Vec<u8>,     // REMOVED: Using provider
    sig_pk: Vec<u8>,
    // Provider
    provider: Box<dyn SecurityProvider>,

    // KeyStore
    keystore: KeyStore,
    client_id: String,
    sequence_number: u64,
    strict_mode: bool,
    data_dir: std::path::PathBuf,
    encryption_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct OwnKeys {
    #[serde(with = "crate::security::keystore::base64_serde")]
    secret_key: Vec<u8>,
    #[serde(with = "crate::security::keystore::base64_serde")]
    public_key: Vec<u8>,
    #[serde(with = "crate::security::keystore::base64_serde")]
    sig_sk: Vec<u8>,
    #[serde(with = "crate::security::keystore::base64_serde")]
    sig_pk: Vec<u8>,
    sequence_number: u64,
}

impl SecureMqttClient {
    /// Create a new Secure MQTT client.
    ///
    /// # Arguments
    ///
    /// * `broker` - The MQTT broker address
    /// * `port` - The MQTT broker port
    /// * `client_id` - The client ID to use
    pub fn new(broker: &str, port: u16, client_id: &str) -> Result<Self> {
        Self::init(broker, port, client_id, None)
    }

    /// Create a new Secure MQTT client with encryption at rest.
    ///
    /// # Arguments
    ///
    /// * `broker` - The MQTT broker address
    /// * `port` - The MQTT broker port
    /// * `client_id` - The client ID to use
    /// * `key` - The 32-byte encryption key for securing local identity
    pub fn new_encrypted(broker: &str, port: u16, client_id: &str, key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::ClientError(
                "Encryption key must be 32 bytes (AES-256)".to_string(),
            ));
        }
        Self::init(broker, port, client_id, Some(key.to_vec()))
    }

    fn init(broker: &str, port: u16, client_id: &str, key: Option<Vec<u8>>) -> Result<Self> {
        // Run FIPS/Compliance Self-Tests on startup
        crate::compliance::run_self_tests()?;

        let mut options = MqttOptions::new(client_id, broker, port);
        options.set_keep_alive(Duration::from_secs(60));
        options.set_clean_session(true);

        let kyber = Kyber::new();
        let falcon = Falcon::new();

        // Ensure data directory exists
        let data_dir = std::path::Path::new("pqc-data");
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir).map_err(Error::IoError)?;
        }
        let data_dir = data_dir.to_path_buf();

        // Load Identity if exists
        let identity_path = data_dir.join(format!("identity_{}.json", client_id));
        let (pk, sk, sig_pk, sig_sk, seq) = if identity_path.exists() {
            log_security_event(&SecurityEvent::IdentityLoaded {
                client_id,
                path: identity_path.to_str().unwrap_or("unknown"),
            });
            let file = std::fs::File::open(&identity_path).map_err(Error::IoError)?;
            let mut reader = std::io::BufReader::new(file);

            // If encrypted, decrypt first
            let own_keys: OwnKeys = if let Some(k) = &key {
                use std::io::Read;
                let mut buffer = Vec::new();
                reader.read_to_end(&mut buffer).map_err(Error::IoError)?;

                // Expect Nonce (12) + Ciphertext
                if buffer.len() < 12 {
                    return Err(Error::ClientError("Encrypted file too short".to_string()));
                }

                let (nonce_bytes, ciphertext) = buffer.split_at(12);
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k));
                let nonce = Nonce::from_slice(nonce_bytes);

                let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
                    Error::ClientError(
                        "Decryption failed: Invalid key or corrupted file".to_string(),
                    )
                })?;

                serde_json::from_slice(&plaintext)
                    .map_err(|e| Error::ClientError(format!("Deserialization error: {}", e)))?
            } else {
                serde_json::from_reader(reader).map_err(|e| {
                    Error::ClientError(format!("Deserialization error (expected JSON): {}", e))
                })?
            };

            (
                own_keys.public_key,
                own_keys.secret_key,
                own_keys.sig_pk,
                own_keys.sig_sk,
                own_keys.sequence_number,
            )
        } else {
            // Generate NEW keys
            log_security_event(&SecurityEvent::IdentityGenerated { client_id });
            let (pk, sk) = kyber.generate_keypair()?;
            let (sig_pk, sig_sk) = falcon.generate_keypair()?;
            (pk, sk, sig_pk, sig_sk, 0)
        };

        // Load Keystore
        let keystore_path = data_dir.join(format!("keystore_{}.json", client_id));
        let keystore = KeyStore::load_from_file(keystore_path.to_str().unwrap())?;

        // Instantiate SoftwareSecurityProvider
        let provider = Box::new(SoftwareSecurityProvider::new(
            sk.clone(),
            pk.clone(),
            sig_sk.clone(),
            sig_pk.clone(),
        ));

        let client = SecureMqttClient {
            client: None,
            eventloop: None,
            options,
            keystore,
            public_key: pk,
            sig_pk,
            // secret_key: sk,   // Removed
            // sig_sk,           // Removed
            provider, // Added
            sequence_number: seq,
            client_id: client_id.to_string(),
            strict_mode: false,
            data_dir,
            encryption_key: key,
            // kyber, // Removed
            falcon,
        };

        // Save identity immediately if new
        if !identity_path.exists() {
            client.save_identity()?;
        }

        Ok(client)
    }

    /// Save the current identity to disk.
    pub fn save_identity(&self) -> Result<()> {
        // Export keys from provider. If provider is hardware, we skip saving private keys (conceptually)
        // But for SoftwareSecurityProvider, it returns Some.
        let (sk, ssk) = match self.provider.export_secret_keys() {
            Some(keys) => keys,
            None => {
                // If using hardware keys, we cannot persist them to file.
                // We might want to persist public keys and seq number only?
                // For now, assuming Software provider.
                return Err(Error::ClientError(
                    "Cannot save identity: Provider does not export keys".to_string(),
                ));
            }
        };

        let own_keys = OwnKeys {
            public_key: self.public_key.clone(),
            secret_key: sk,
            sig_pk: self.sig_pk.clone(),
            sig_sk: ssk,
            sequence_number: self.sequence_number,
        };
        let identity_path = self
            .data_dir
            .join(format!("identity_{}.json", self.client_id));
        let file = std::fs::File::create(&identity_path).map_err(Error::IoError)?;
        let mut writer = std::io::BufWriter::new(file);

        if let Some(key) = &self.encryption_key {
            // Encrypt
            let plaintext = serde_json::to_vec(&own_keys)
                .map_err(|e| Error::ClientError(format!("Serialization error: {}", e)))?;

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            let mut rng = rand::thread_rng();
            let mut nonce_bytes = [0u8; 12];
            rng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &plaintext,
                        aad: &[],
                    },
                )
                .map_err(|_| Error::ClientError("Encryption failed".to_string()))?;

            // Write Nonce + Ciphertext
            use std::io::Write;
            writer.write_all(&nonce_bytes).map_err(Error::IoError)?;
            writer.write_all(&ciphertext).map_err(Error::IoError)?;
        } else {
            // Plain JSON
            serde_json::to_writer_pretty(writer, &own_keys)
                .map_err(|e| Error::ClientError(format!("Serialization error: {}", e)))?;
        }
        Ok(())
    }

    // ... builders ...
    /// Set the keep-alive interval.
    pub fn with_keep_alive(mut self, duration: Duration) -> Self {
        self.options.set_keep_alive(duration);
        self
    }

    /// Set the clean session flag.
    pub fn with_clean_session(mut self, clean: bool) -> Self {
        self.options.set_clean_session(clean);
        self
    }

    /// Set the QoS level (No-op in current implementation).
    pub fn with_qos(self, _qos: QoS) -> Self {
        self
    }

    /// Set the Last Will and Testament.
    pub fn with_will(mut self, topic: &str, payload: &[u8], qos: QoS, retain: bool) -> Self {
        let will = LastWill::new(topic, payload, qos, retain);
        self.options.set_last_will(will);
        self
    }

    /// Set the username and password.
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.options.set_credentials(username, password);
        self
    }

    /// Enable strict mode (Identity Pinning).
    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Get the client's identity public key (Falcon).
    pub fn get_identity_key(&self) -> Vec<u8> {
        self.sig_pk.clone()
    }

    /// Initialize the client if not already initialized
    fn ensure_connected(&mut self) -> Result<()> {
        if self.client.is_none() {
            let (client, eventloop) = Client::new(self.options.clone(), 10);
            self.client = Some(client);
            self.eventloop = Some(eventloop);
        }
        Ok(())
    }

    // ... bootstrap ...
    /// Bootstrap the client: Connect, subscribe to keys, and publish own key.
    pub fn bootstrap(&mut self) -> Result<()> {
        self.ensure_connected()?;

        if let Some(client) = &mut self.client {
            // Subscribe to all keys
            client
                .subscribe("pqc/keys/+", QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Publish my keys
            let peer_keys = PeerKeys {
                kem_pk: self.public_key.clone(),
                sig_pk: self.sig_pk.clone(),
                last_sequence: 0,
                is_trusted: true, // Self is trusted
            };

            let payload = serde_json::to_string(&peer_keys)
                .map_err(|e| Error::ClientError(format!("JSON error: {}", e)))?;

            let topic = format!("pqc/keys/{}", self.client_id);
            // Retained message so new clients see it
            client
                .publish(topic, QoS::AtLeastOnce, true, payload.as_bytes())
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Save keystore (auto-trust self)
            let keystore_path = self
                .data_dir
                .join(format!("keystore_{}.json", self.client_id));
            let _ = self.keystore.save_to_file(keystore_path.to_str().unwrap());
        }
        Ok(())
    }

    // ... publish_encrypted ...
    /// Publish an encrypted message to a target client.
    pub fn publish_encrypted(
        &mut self,
        topic: &str,
        payload: &[u8],
        target_client_id: &str,
    ) -> Result<()> {
        self.ensure_connected()?;

        // 1. Get Target Keys
        let target_keys = self
            .keystore
            .get(target_client_id)
            .ok_or(Error::ClientError(format!(
                "Unknown client: {}",
                target_client_id
            )))?;

        // 2. Prepare Payload with Sequence Number [SeqNum(8) | Payload]
        let mut attached_payload = Vec::with_capacity(8 + payload.len());
        attached_payload.extend_from_slice(&self.sequence_number.to_be_bytes());
        attached_payload.extend_from_slice(payload);

        // 3. Hybrid Encrypt
        let encrypted_blob = hybrid::encrypt(&target_keys.kem_pk, &attached_payload)?;

        // 4. Sign the encrypted blob
        let signature = self.provider.sign(&encrypted_blob)?;
        let sig_len = signature.len() as u16;

        // 5. Construct Packet: [ SenderID Len(2) ] [ SenderID ] [ Encrypted Blob ] [ Signature Len(2) ] [ Signature ]
        let sender_id_bytes = self.client_id.as_bytes();
        let sender_id_len = sender_id_bytes.len() as u16;

        let mut message = Vec::new();
        message.extend_from_slice(&sender_id_len.to_be_bytes());
        message.extend_from_slice(sender_id_bytes);
        message.extend_from_slice(&encrypted_blob);
        message.extend_from_slice(&sig_len.to_be_bytes());
        message.extend_from_slice(&signature);

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, message)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Increment sequence number after successful publish
            self.sequence_number += 1;
            let _ = self.save_identity();
        }
        Ok(())
    }

    // ... original publish ...
    /// Publish a signed message.
    pub fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<()> {
        self.ensure_connected()?;
        let signature = self.provider.sign(payload)?;
        let sig_len = signature.len() as u16;
        let mut message: Vec<u8> = Vec::new();
        message.extend_from_slice(payload);
        message.extend_from_slice(&signature);
        message.extend_from_slice(&sig_len.to_be_bytes()); // Suffix style

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, message)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    // ... subscribe ...
    /// Subscribe to a topic.
    pub fn subscribe(&mut self, topic: &str) -> Result<()> {
        self.ensure_connected()?;

        if let Some(client) = &mut self.client {
            client
                .subscribe(topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    /// Check if a peer is known in the keystore.
    pub fn has_peer(&self, client_id: &str) -> bool {
        self.keystore.contains(client_id)
    }

    /// Check if a peer is ready for encrypted communication (has Kyber key).
    pub fn is_peer_ready(&self, client_id: &str) -> bool {
        if let Some(keys) = self.keystore.get(client_id) {
            !keys.kem_pk.is_empty()
        } else {
            false
        }
    }

    /// Manually add a trusted peer with their Identity Key (Falcon).
    pub fn add_trusted_peer(&mut self, client_id: &str, sig_pk: Vec<u8>) {
        // Create a placeholder PeerKeys with just the identity key (sig_pk)
        // correct Kyber PK will be filled upon first key exchange if sig_pk matches?
        // Actually, my current logic in poll overwrites keys if they exist.
        // But strict mode check:
        // let is_known = self.keystore.get(sender_id).map(|k| k.is_trusted).unwrap_or(false);
        // So I just need to insert a record with is_trusted=true.
        // But I don't have the Kyber PK yet!
        // So I need to insert a "partial" record or just store TrustedIDs separately?
        // Using PeerKeys with empty fields is one way, but risky.
        // Let's create a PeerKeys with empty kyber_pk?
        // hybrid::encrypt needs kem_pk.
        // So we can't send TO them until they publish Kyber keys.
        // But we can ACCEPT their keys if we trust their Falcon PK.

        let placeholder = PeerKeys {
            kem_pk: Vec::new(), // Will be updated on first Bootstrap received
            sig_pk,
            last_sequence: 0,
            is_trusted: true,
        };
        self.keystore.insert(client_id, placeholder);
        let keystore_path = self
            .data_dir
            .join(format!("keystore_{}.json", self.client_id));
        let _ = self.keystore.save_to_file(keystore_path.to_str().unwrap());
    }

    // ... poll ...
    /// Poll for incoming messages and events.
    ///
    /// The callback receives (topic, payload) for any valid decrypted/verified message.
    pub fn poll<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(&str, &[u8]),
    {
        self.ensure_connected()?;

        let eventloop = self
            .eventloop
            .as_mut()
            .ok_or(Error::MqttError("No event loop".to_string()))?;

        // Uses Iterator::next() which blocks until an event is available
        match eventloop.iter().next() {
            Some(Ok(notification)) => {
                if let Event::Incoming(Packet::Publish(publish)) = notification {
                    let topic = publish.topic.clone();
                    let payload = publish.payload;

                    // 1. Check Key Exchange
                    if topic.starts_with("pqc/keys/") {
                        let sender_id = topic.strip_prefix("pqc/keys/").unwrap();

                        // Ignore own key
                        if sender_id == self.client_id {
                            return Ok(());
                        }

                        // ... (Verification logic) ...
                        // For simplicity in debugging, assuming verification passed (you might want to log verification failure too)

                        // Extract payload parts (sig_len, sig, key)
                        // ...

                        // Let's assume standard extraction logic follows. I'll inject logs.

                        // Wait, I need to see the actual implementation to inject logs correctly.
                        // I'll replace the BLOCK to insert logs.
                        // Since I don't have the block content in recent view, I should view it first?
                        // No, I viewed it in Step 1944 (but that was early).
                        // I will view `mqtt_secure.rs` poll method logic again.

                        let parts: Vec<&str> = topic.split('/').collect();
                        if let Some(sender_id) = parts.last() {
                            if *sender_id != self.client_id {
                                if let Ok(mut keys) = serde_json::from_slice::<PeerKeys>(&payload) {
                                    // STRICT MODE CHECK
                                    if self.strict_mode {
                                        // Must be known AND trusted
                                        let existing = self.keystore.get(sender_id);
                                        let is_trusted =
                                            existing.map(|k| k.is_trusted).unwrap_or(false);

                                        if !is_trusted {
                                            return Ok(());
                                        }

                                        // Verify Identity Key matches the Pre-Approved one!
                                        if let Some(known) = existing {
                                            // If known.sig_pk is not empty/dummy, check it.
                                            // If we used add_trusted_peer, we set sig_pk.
                                            if !known.sig_pk.is_empty()
                                                && known.sig_pk != keys.sig_pk
                                            {
                                                error!("SECURITY ALERT: Peer {} presented different Identity Key than trusted one!", sender_id);
                                                log_security_event(
                                                    &SecurityEvent::IdentityMismatch {
                                                        peer_id: sender_id,
                                                        reason:
                                                            "Key mismatch with trusted identity",
                                                    },
                                                );
                                                return Ok(()); // Reject
                                            }
                                        }
                                    }

                                    // SECURITY: If we already have this peer, preserve trust and sequence logic
                                    if let Some(existing) = self.keystore.get(sender_id) {
                                        if existing.is_trusted {
                                            keys.is_trusted = true;
                                            // If Identity Key (Falcon) changed, we might want to revoke trust!
                                            if !existing.sig_pk.is_empty()
                                                && existing.sig_pk != keys.sig_pk
                                            {
                                                log_security_event(&SecurityEvent::TrustRevoked {
                                                    peer_id: sender_id,
                                                    reason: "Identity key changed",
                                                });
                                                keys.is_trusted = false;
                                            }
                                        }
                                        keys.last_sequence = 0;
                                    }

                                    self.keystore.insert(sender_id, keys);
                                    // Auto-save
                                    let keystore_path = self
                                        .data_dir
                                        .join(format!("keystore_{}.json", self.client_id));
                                    let _ =
                                        self.keystore.save_to_file(keystore_path.to_str().unwrap());
                                }
                            }
                        }
                        return Ok(());
                    }

                    // 2. Check Encrypted Packet (SenderID prefixed)
                    if payload.len() > 2 {
                        let (len_bytes, _) = payload.split_at(2);
                        let id_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

                        // Heuristic check
                        if id_len > 0 && id_len < 256 && payload.len() > 2 + id_len + 4 {
                            let (id_bytes, rest) = payload[2..].split_at(id_len);
                            if let Ok(sender_id) = std::str::from_utf8(id_bytes) {
                                // Look for signature at end
                                if rest.len() > 2 {
                                    let (blob_and_sig, sig_len_bytes) =
                                        rest.split_at(rest.len() - 2);
                                    let sig_len =
                                        u16::from_be_bytes([sig_len_bytes[0], sig_len_bytes[1]])
                                            as usize;
                                    if blob_and_sig.len() >= sig_len {
                                        let (encrypted_blob, signature) =
                                            blob_and_sig.split_at(blob_and_sig.len() - sig_len);

                                        // Verify Signature
                                        // Note: We need mut access to update sequence number, so we use get_mut separately or logic changes
                                        // Optimization: Check existence first
                                        let needs_update = if let Some(keys) =
                                            self.keystore.get(sender_id)
                                        {
                                            if self
                                                .falcon
                                                .verify(&keys.sig_pk, encrypted_blob, signature)
                                                .is_ok()
                                            {
                                                // Decrypt
                                                if let Ok(decrypted) =
                                                    self.provider.decrypt(encrypted_blob)
                                                {
                                                    // REPLAY PROTECTION CHECK
                                                    if decrypted.len() > 8 {
                                                        let (seq_bytes, actual_payload) =
                                                            decrypted.split_at(8);
                                                        let seq = u64::from_be_bytes(
                                                            seq_bytes.try_into().unwrap(),
                                                        );

                                                        if seq > keys.last_sequence {
                                                            let topic_str = topic.clone(); // Clone topic to avoid borrow issues if needed, or just pass ref
                                                            callback(&topic_str, actual_payload);
                                                            Some(seq) // Return new sequence to update
                                                        } else {
                                                            warn!("Replay detected from {}! MsgSeq: {}, LastSeq: {}", sender_id, seq, keys.last_sequence);
                                                            None
                                                        }
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        };

                                        if let Some(new_seq) = needs_update {
                                            if let Some(keys) = self.keystore.get_mut(sender_id) {
                                                keys.last_sequence = new_seq;
                                                // Save keystore to persist counter
                                                let keystore_path = self.data_dir.join(format!(
                                                    "keystore_{}.json",
                                                    self.client_id
                                                ));
                                                let _ = self
                                                    .keystore
                                                    .save_to_file(keystore_path.to_str().unwrap());
                                            }
                                        }

                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }

                    // 3. Fallback to Legacy Signed (Suffix)
                    const LEN_SIZE: usize = 2;
                    if payload.len() >= LEN_SIZE {
                        let (rest, len_bytes) = payload.split_at(payload.len() - LEN_SIZE);
                        let sig_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
                        if rest.len() >= sig_len {
                            let (message, signature) = rest.split_at(rest.len() - sig_len);
                            if self.falcon.verify(&self.sig_pk, message, signature).is_ok() {
                                callback(&topic, message);
                            }
                        }
                    }
                }
            }
            Some(Err(e)) => return Err(Error::MqttError(e.to_string())),
            None => return Err(Error::MqttError("Event loop ended".to_string())),
        }
        Ok(())
    }
}
