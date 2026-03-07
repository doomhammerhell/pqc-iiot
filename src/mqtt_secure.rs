use crate::crypto::traits::{PqcKEM, PqcSignature};
// use crate::kem::{MAX_PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE};
// use crate::sign::MAX_SIGNATURE_SIZE;
use crate::security::hybrid;
use crate::security::keystore::{KeyStore, PeerKeys};
use crate::security::provider::{SecurityProvider, SoftwareSecurityProvider};
use crate::security::audit::{AuditLogger, ChainedAuditLogger, SecurityEvent, Severity, AuditLog};
use crate::security::metrics::SecurityMetrics;
use std::sync::Arc;
use crate::{Error, Falcon, Kyber, Result}; // Import Kyber and Falcon from root
use log::{error, warn};
// use heapless::Vec as HeaplessVec;
use rumqttc::{Client, Event, LastWill, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use serde_json;
use std::string::{String, ToString};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread;

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
    // eventloop moved to thread
    // kyber: Kyber, // Removed as unused
    falcon: Falcon,
    // Own keys
    // secret_key: Vec<u8>, // REMOVED: Using provider
    public_key: Vec<u8>,
    // sig_sk: Vec<u8>,     // REMOVED: Using provider
    sig_pk: Vec<u8>,
    // Provider
    provider: Arc<dyn SecurityProvider>,

    // KeyStore
    keystore: KeyStore,
    client_id: String,
    sequence_number: u64,
    strict_mode: bool,
    data_dir: std::path::PathBuf,
    encryption_key: Option<Vec<u8>>,
    
    // Observability
    audit_logger: Box<dyn AuditLogger>,
    metrics: Arc<SecurityMetrics>,
    
    // Reliability
    persist_manager: crate::persistence::LazyPersistManager,
    
    // Threading & Watchdog
    network_recv: Option<Receiver<std::result::Result<Event, rumqttc::ConnectionError>>>, // Receive events from thread
    heartbeat: Arc<AtomicU64>,
    key_prefix: String,
}

use crate::persistence::AtomicFileStore;

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

/// Canonical payload used for signing/verifying key announcements.
/// Excludes the detached signature field to avoid recursion.
fn key_announcement_payload(keys: &PeerKeys) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&keys.kem_pk);
    buf.extend_from_slice(&keys.sig_pk);
    buf.extend_from_slice(&keys.last_sequence.to_be_bytes());
    buf.push(keys.is_trusted as u8);

    if let Some(quote) = &keys.quote {
        buf.extend_from_slice(&quote.pcr_digest);
        buf.extend_from_slice(&quote.nonce);
        buf.extend_from_slice(&quote.signature);
        buf.extend_from_slice(&quote.ak_public_key);
    }

    buf
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
        options.set_keep_alive(Duration::from_secs(5)); // Aggressive KeepAlive for faster failure detection
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
            let _event = SecurityEvent::IdentityLoaded {
                peer_id: client_id.to_string(), 
                path: identity_path.to_str().unwrap_or("INVALID_UTF8_PATH").to_string(),
            };
            // Log to global log for startup visibility
            log::info!("[AUDIT] IdentityLoaded {{ peer_id: {}, path: {:?} }}", client_id, identity_path);

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
            // log_security_event(&SecurityEvent::IdentityGenerated { client_id });
            log::info!("Generating new identity for client: {}", client_id);
            let (pk, sk) = kyber.generate_keypair()?;
            let (sig_pk, sig_sk) = falcon.generate_keypair()?;
            (pk, sk, sig_pk, sig_sk, 1)
        };

        // Load Keystore
        let keystore_path = data_dir.join(format!("keystore_{}.json", client_id));
        let keystore_path_str = keystore_path.to_str().ok_or(Error::ClientError("Invalid Keystore Path (Non-UTF8)".into()))?;
        let keystore = KeyStore::load_from_file(keystore_path_str)?;

        // Instantiate SoftwareSecurityProvider
        let provider = Arc::new(SoftwareSecurityProvider::new(
            sk.clone(),
            pk.clone(),
            sig_sk.clone(),
            sig_pk.clone(),
        ));

        let client = SecureMqttClient {
            client: None,
            // eventloop: None, // Removed
            options,
            keystore,
            public_key: pk,
            sig_pk,
            // secret_key: sk,   // Removed
            // sig_sk,           // Removed
            provider, // Added
            sequence_number: seq,
            client_id: client_id.to_string(),
            // Secure by default: reject unknown peers unless explicitly opted out.
            strict_mode: true,
            data_dir: data_dir.clone(), // Clone here to avoid move
            encryption_key: key,
            // kyber, // Removed
            falcon,
            audit_logger: Box::new(ChainedAuditLogger::new(&data_dir)),
            metrics: Arc::new(SecurityMetrics::new()),
            persist_manager: crate::persistence::LazyPersistManager::new(
                Duration::from_secs(300), // Flush every 5 mins
                50,                       // OR every 50 updates
            ),
            network_recv: None,
            heartbeat: Arc::new(AtomicU64::new(0)),
            key_prefix: "pqc/keys/".to_string(),
        };

        // Save identity immediately if new
        if !identity_path.exists() {
            client.save_identity()?;
        }

        Ok(client)
    }

    /// Save the current identity to disk.
    pub fn save_identity(&self) -> Result<()> {
        // Export keys from provider.
        let (sk, ssk) = match self.provider.export_secret_keys() {
            Some(keys) => keys,
            None => return Err(Error::ClientError("Cannot save identity: Provider does not export keys".to_string())),
        };

        let own_keys = OwnKeys {
            public_key: self.public_key.clone(),
            secret_key: sk,
            sig_pk: self.sig_pk.clone(),
            sig_sk: ssk,
            sequence_number: self.sequence_number,
        };
        let identity_path = self.data_dir.join(format!("identity_{}.json", self.client_id));

        let data_to_write = if let Some(key) = &self.encryption_key {
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

            // Nonce + Ciphertext
            let mut final_blob = Vec::with_capacity(12 + ciphertext.len());
            final_blob.extend_from_slice(&nonce_bytes);
            final_blob.extend_from_slice(&ciphertext);
            final_blob
        } else {
            // Plain JSON
            serde_json::to_vec_pretty(&own_keys)
                .map_err(|e| Error::ClientError(format!("Serialization error: {}", e)))?
        };

        // ATOMIC WRITE
        AtomicFileStore::write(&identity_path, &data_to_write)?;
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

    /// Set the key topics prefix (default "pqc/keys/").
    pub fn with_key_prefix(mut self, prefix: &str) -> Self {
        self.key_prefix = prefix.to_string();
        // Ensure trailing slash
        if !self.key_prefix.ends_with('/') {
            self.key_prefix.push('/');
        }
        self
    }

    /// Get the client's identity public key (Falcon).
    pub fn get_identity_key(&self) -> Vec<u8> {
        self.sig_pk.clone()
    }

    /// Initialize the client if not already initialized
    fn ensure_connected(&mut self) -> Result<()> {
        if self.client.is_none() {
            let (client, mut eventloop) = Client::new(self.options.clone(), 10);
            let client_handle = client.clone();
            self.client = Some(client);
            
            // SPAWN THREADED WATCHDOG
            let (tx, rx) = sync_channel(50);
            self.network_recv = Some(rx);
            
            let heartbeat = self.heartbeat.clone();
            
            thread::spawn(move || {
                for notification in eventloop.iter() {
                    // Update heartbeat
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    heartbeat.store(now, Ordering::Relaxed);
                    
                    if let Ok(Event::Incoming(Packet::Publish(ref p))) = notification {
                         println!("NET_THREAD: Rx Publish on {} (Retain={})", p.topic, p.retain);
                    }
                    
                    // Send to main thread
                    if tx.send(notification).is_err() {
                        // Main thread dropped receiver (shutdown)
                        break; 
                    }
                }
                println!("NET_THREAD: Exited!");
            });

            // SPAWN HEARTBEAT TELEMETRY THREAD
            let mut hb_client = client_handle;
            let hb_metrics = self.metrics.clone();
            let hb_client_id = self.client_id.clone();
            let hb_provider = self.provider.clone(); // Arc clone
            
            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(60));
                    
                    let dec_fail = hb_metrics.decryption_failures.load(Ordering::Relaxed);
                    let rep_atk = hb_metrics.replay_attacks_detected.load(Ordering::Relaxed);
                    let svn = hb_metrics.current_svn.load(Ordering::Relaxed);
                    let integrity = hb_metrics.integrity_ok.load(Ordering::Relaxed) == 1;
                    
                    let snapshot = serde_json::json!({
                        "client_id": hb_client_id,
                        "decryption_failures": dec_fail,
                        "replay_attacks": rep_atk,
                        "current_svn": svn,
                        "integrity": integrity,
                        "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                    });
                    
                    // Sign the snapshot for "Abyssal" security
                    let mut payload = serde_json::to_vec(&snapshot).unwrap_or_default();
                    if let Ok(sig) = hb_provider.sign(&payload) {
                        payload.extend_from_slice(&sig);
                        let sig_len = sig.len() as u16;
                        payload.extend_from_slice(&sig_len.to_be_bytes());
                    }
                    
                    let topic = format!("telemetry/security/health/{}", hb_client_id);
                    if let Err(e) = hb_client.publish(topic, QoS::AtLeastOnce, false, payload) {
                         eprintln!("HEARTBEAT_THREAD: Publish fail: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    // ... bootstrap ...
    /// Bootstrap the client: Connect, subscribe to keys, and publish own key.
    pub fn bootstrap(&mut self) -> Result<()> {
        self.ensure_connected()?;
        println!("SecureMqttClient[{}]: Connected. Subscribing to keys...", self.client_id);

        if let Some(client) = &mut self.client {
            // Subscribe to all keys
            let subscription_topic = format!("{}+", self.key_prefix);
            client
                .subscribe(&subscription_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;
            println!("SecureMqttClient[{}]: Subscribed.", self.client_id);

            // 2. Generate Attestation Quote for "Handshake"
            let nonce = vec![1, 2, 3, 4]; // In production, this comes from a Challenge message
            let quote = self.provider.generate_quote(&[0, 1, 2, 3], &nonce).ok();

            // Publish my keys (signed)
            let mut peer_keys = PeerKeys {
                kem_pk: self.public_key.clone(),
                sig_pk: self.sig_pk.clone(),
                last_sequence: 0,
                is_trusted: true, // Self is trusted
                quote,
                key_signature: None,
            };

            // Sign announcement with our identity key
            let payload = key_announcement_payload(&peer_keys);
            let signature = self.provider.sign(&payload)?;
            peer_keys.key_signature = Some(signature);

            let payload = serde_json::to_string(&peer_keys)
                .map_err(|e| Error::ClientError(format!("JSON error: {}", e)))?;

            let topic = format!("{}{}", self.key_prefix, self.client_id);
            // Retained message so new clients see it
            client
                .publish(topic, QoS::AtLeastOnce, true, payload.as_bytes())
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Save keystore (auto-trust self)
            let keystore_path = self
                .data_dir
                .join(format!("keystore_{}.json", self.client_id));
            let keystore_path_str = keystore_path.to_str().ok_or(Error::ClientError("Invalid Keystore Path".into()))?;
            let _ = self.keystore.save_to_file(keystore_path_str);
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
        message.extend_from_slice(&signature);
        message.extend_from_slice(&sig_len.to_be_bytes());

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, message)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Increment sequence number after successful publish
            self.sequence_number += 1;
            
            // LAZY PERSISTENCE: Mark dirty, only save if threshold reached
            self.persist_manager.mark_dirty();
            if self.persist_manager.should_flush() {
                 self.save_identity()?;
                 self.persist_manager.notify_flushed();
            }
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
        // Create a PeerKeys entry with the discovered identity key (sig_pk)
        let initial_peer_keys = PeerKeys {
            kem_pk: Vec::new(), // Kyber PK will be updated on first Bootstrap received
            sig_pk: sig_pk.to_vec(),
            last_sequence: 0,
            is_trusted: true, 
            quote: None,
        };

        // Cache the peer's keys for future encrypted communications
        self.keystore.insert(client_id, initial_peer_keys);
        let keystore_path = self
            .data_dir
            .join(format!("keystore_{}.json", self.client_id));
        let _ = self.keystore.save_to_file(keystore_path.to_str().unwrap());
    }

    // ... poll ...
    /// Poll for incoming messages and events (Non-Blocking / Timeout).
    ///
    /// The callback receives (topic, payload) for any valid decrypted/verified message.
    /// Returns Ok(()) if processed, or Error if connection lost.
    pub fn poll<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(&str, &[u8]),
    {
        self.ensure_connected()?;

        // 1. WATCHDOG CHECK
        let last_beat = self.heartbeat.load(Ordering::Relaxed);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        // If no heartbeat for > 15s (3x KeepAlive), the watchdog treats the network thread as unresponsive.
        if now > last_beat + 15 && last_beat > 0 {
             error!("WATCHDOG TRIGGERED: MQTT Network Thread Stuck! Force Reconnect.");
             self.client = None; // Drop client -> Drops channel -> Thread error -> Exit
             self.network_recv = None;
             return Err(Error::MqttError("Watchdog Timeout: Network Thread Stuck".to_string()));
        }

        // 2. NON-BLOCKING READ
        if let Some(rx) = &self.network_recv {
            // Try to read all available events without blocking
            // Or use recv_timeout for a tiny slice if we want to yield CPU?
            // try_recv is fully non-blocking.
            match rx.try_recv() {
                Ok(notification) => {
                    match notification {
                        Ok(event) => {
                             if let Some((topic, payload)) = self.process_notification(event)? {
                                 callback(&topic, &payload);
                             }
                        }
                        Err(e) => return Err(Error::MqttError(e.to_string())),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // No messages, return cleanly (Non-blocking!)
                    return Ok(());
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(Error::MqttError("Network Thread Disconnected".to_string()));
                }
            }
        }
        Ok(())
    }

    /// Process a single MQTT notification, returning (topic, payload) if a message is available.
    fn process_notification(&mut self, notification: Event) -> Result<Option<(String, Vec<u8>)>> {
        if let Event::Incoming(Packet::Publish(publish)) = notification {
            let topic = publish.topic.clone();
            let payload = publish.payload;

            // 1. Check Key Exchange
            if let Some(sender_id) = topic.strip_prefix(&self.key_prefix) {
                if sender_id != self.client_id {
                    let keys: PeerKeys = serde_json::from_slice(&payload)
                        .map_err(|e| Error::ClientError(format!("Invalid keys: {}", e)))?;
                    self.handle_key_exchange(sender_id, keys)?;
                }
                return Ok(None);
            }

            // 2. Check Encrypted Packet (SenderID prefixed)
            if payload.len() > 2 {
                let (len_bytes, _) = payload.split_at(2);
                let id_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

                // Heuristic check
                if id_len > 0 && id_len < 256 && payload.len() > 2 + id_len + 4 {
                    let (id_bytes, rest) = payload[2..].split_at(id_len);
                    if let Ok(sender_id) = std::str::from_utf8(id_bytes) {
                        println!("DEBUG: Extracted SenderID: {}", sender_id);
                        // Look for signature at end
                        if rest.len() > 2 {
                            let (blob_and_sig, sig_len_bytes) =
                                rest.split_at(rest.len() - 2);
                            let sig_len = u16::from_be_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;
                            
                            if blob_and_sig.len() > sig_len {
                                let (encrypted_blob, signature) = blob_and_sig.split_at(blob_and_sig.len() - sig_len);
                                
                                if let Some(keys) = self.keystore.get(sender_id) {
                                    if self.falcon.verify(&keys.sig_pk, encrypted_blob, signature).is_ok() {
                                        match self.provider.decrypt(encrypted_blob) {
                                            Ok(decrypted) => {
                                                // Extract Sequence Number (First 8 bytes)
                                                if decrypted.len() > 8 {
                                                    let (seq_bytes, actual_payload) = decrypted.split_at(8);
                                                    let seq = u64::from_be_bytes(seq_bytes.try_into().unwrap());
                                                    
                                                    if seq > keys.last_sequence {
                                                        // Update KeyStore with new sequence
                                                        if let Some(keys_mut) = self.keystore.get_mut(sender_id) {
                                                            keys_mut.last_sequence = seq;
                                                            self.persist_manager.mark_dirty();
                                                        }
                                                        
                                                        return Ok(Some((topic, actual_payload.to_vec())));
                                                    } else {
                                                        warn!("Replay detected: Seq {} <= Last {}", seq, keys.last_sequence);
                                                        self.metrics.inc_replay_attack();
                                                    }
                                                } else {
                                                    warn!("Decrypted payload too short");
                                                }
                                            }
                                            Err(e) => {
                                                 warn!("Decryption failed for {}: {:?}", sender_id, e);
                                                 self.metrics.inc_decryption_failure();
                                            }
                                        }
                                    } else {
                                         warn!("Signature verification failed for {}", sender_id);
                                    }
                                } else {
                                    // Sender unknown?
                                    // warning is noisy if we receive random packets, but for test it's fine
                                }
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
                         return Ok(Some((topic, message.to_vec())));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Handle Key Exchange messages (Identity Verification)
    fn handle_key_exchange(&mut self, sender_id: &str, mut keys: PeerKeys) -> Result<()> {
        // STRICT MODE CHECK
        if self.strict_mode {
            // Must be known AND trusted
            let existing = self.keystore.get(sender_id);
            let is_trusted = existing.map(|k| k.is_trusted).unwrap_or(false);

            if !is_trusted {
                warn!("Strict Mode: Rejecting unknown peer {}", sender_id);
                return Ok(());
            }

            // Verify Identity Key matches the Pre-Approved one!
            if let Some(known) = existing {
                if !known.sig_pk.is_empty() && known.sig_pk != keys.sig_pk {
                    error!("SECURITY ALERT: Peer {} presented different Identity Key!", sender_id);
                    let event = SecurityEvent::IdentityRotation {
                        new_key_id: "mismatch_with_trust".to_string(),
                    };
                    self.audit_logger.log(AuditLog::new(event, Severity::Critical, "SecureMqttClient"));
                    self.metrics.inc_failed_handshake();
                    return Ok(()); // Reject
                }
            }
        }

        // VERIFY ANNOUNCEMENT SIGNATURE (required)
        let signature = match &keys.key_signature {
            Some(sig) => sig,
            None => {
                warn!("Key exchange from {} rejected: missing signature", sender_id);
                self.metrics.inc_failed_handshake();
                return Ok(());
            }
        };

        // Use pinned identity if known; otherwise TOFU on provided sig_pk
        let verify_pk = if let Some(existing) = self.keystore.get(sender_id) {
            &existing.sig_pk
        } else {
            &keys.sig_pk
        };

        let payload = key_announcement_payload(&keys);
        let is_valid = self
            .falcon
            .verify(verify_pk, &payload, signature)
            .map_err(|e| Error::CryptoError(format!("Key announcement verify error: {}", e)))?;

        if !is_valid {
            warn!("Key exchange from {} rejected: invalid signature", sender_id);
            self.metrics.inc_failed_handshake();
            return Ok(());
        }

        // TRUST CONTINUITY
        if let Some(existing) = self.keystore.get(sender_id) {
            if existing.is_trusted {
                keys.is_trusted = true;
                // Check for Identity Rotation
                if !existing.sig_pk.is_empty() && existing.sig_pk != keys.sig_pk {
                    let event = SecurityEvent::IdentityRotation {
                        new_key_id: "revoked_trust_change".to_string(),
                    };
                    self.audit_logger.log(AuditLog::new(event, Severity::Warning, "SecureMqttClient"));
                    keys.is_trusted = false; // Revoke trust on identity change
                }
            }
            // Reset sequence on re-key (new session)
            keys.last_sequence = 0;
        }

        self.keystore.insert(sender_id, keys);
        
        // Lazy Persistence
        self.persist_manager.mark_dirty();
        if self.persist_manager.should_flush() {
            let keystore_path = self.data_dir.join(format!("keystore_{}.json", self.client_id));
            let _ = self.keystore.save_to_file(keystore_path.to_str().unwrap_or(""));
            self.persist_manager.notify_flushed();
        }
        
        self.metrics.inc_success_handshake();
        let event = SecurityEvent::HandshakeSuccess { peer_id: sender_id.to_string() };
        self.audit_logger.log(AuditLog::new(event, Severity::Info, "SecureMqttClient"));
        
        Ok(())
    }
}
