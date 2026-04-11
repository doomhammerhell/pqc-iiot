use crate::crypto::traits::{PqcKEM, PqcSignature};
// use crate::kem::{MAX_PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE};
// use crate::sign::MAX_SIGNATURE_SIZE;
use crate::provisioning::OperationalCertificate;
use crate::security::audit::{AuditLog, AuditLogger, ChainedAuditLogger, SecurityEvent, Severity};
use crate::security::hybrid;
use crate::security::keystore::{KeyStore, PeerKeys};
use crate::security::metrics::SecurityMetrics;
use crate::security::policy::FleetPolicyUpdate;
use crate::security::provider::{SecurityProvider, SoftwareSecurityProvider};
use crate::security::revocation::RevocationUpdate;
use crate::security::time::SecureTimeFloor;
use crate::{Error, Falcon, Kyber, KyberSecurityLevel, Result}; // Import Kyber and Falcon from root
use hkdf::Hkdf;
use log::{debug, error, info, trace, warn};
use sha2::{Digest, Sha256};
use std::sync::Arc;
// use heapless::Vec as HeaplessVec;
use rumqttc::{Client, Event, LastWill, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use serde_json;
use std::string::{String, ToString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
    Key, // Or wrappers
    Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Encrypted identity file magic prefix.
///
/// The encrypted identity format is:
/// `[MAGIC][nonce:12][ciphertext+tag]`
///
/// This removes test flakiness (ciphertext may start with `{` by chance) and provides a stable
/// discriminator for format upgrades and strict parsing.
const IDENTITY_ENC_MAGIC: &[u8] = b"PQCENC1";

/// Maximum peer/client identifier length accepted on-wire (MQTT topic suffix + message prefix).
///
/// This is a hard DoS containment limit: peer IDs are used as hashmap keys and show up in
/// logs/metrics. Allowing unbounded IDs turns the broker into a cardinality amplifier.
const MAX_WIRE_ID_LEN: usize = 128;

/// Default maximum accepted bytes for key announcements (`pqc/keys/<peer>` payload).
const DEFAULT_MAX_KEY_ANNOUNCEMENT_BYTES: usize = 64 * 1024;

/// Default maximum accepted bytes for attestation messages (challenge/quote JSON payloads).
const DEFAULT_MAX_ATTESTATION_BYTES: usize = 32 * 1024;

/// Default maximum accepted bytes for encrypted messages (wire packet).
const DEFAULT_MAX_ENCRYPTED_MESSAGE_BYTES: usize = 256 * 1024;

/// Default maximum accepted bytes for revocation updates.
const DEFAULT_MAX_REVOCATION_BYTES: usize = 128 * 1024;

/// Default maximum accepted bytes for fleet policy updates.
const DEFAULT_MAX_POLICY_BYTES: usize = 64 * 1024;

/// Default maximum accepted bytes for MQTT session-init/response control messages.
const DEFAULT_MAX_SESSION_BYTES: usize = 64 * 1024;

/// Default MQTT topic prefix for session initiation messages addressed to a peer.
const DEFAULT_SESSION_INIT_PREFIX: &str = "pqc/session/init/";

/// Default MQTT topic prefix for session responses addressed to a peer.
const DEFAULT_SESSION_RESP_PREFIX: &str = "pqc/session/resp/";

/// Default MQTT topic for fleet policy updates.
const DEFAULT_POLICY_TOPIC: &str = "pqc/policy/v1";

/// Default MQTT topic for requesting fleet policy sync (client -> CA service).
///
/// The CA service is expected to answer by publishing a signed `FleetPolicyUpdate` on `DEFAULT_POLICY_TOPIC`.
const DEFAULT_POLICY_SYNC_TOPIC: &str = "pqc/policy/sync/v1";

/// Default MQTT topic for requesting revocation sync (client -> CA service).
///
/// The CA service is expected to answer by publishing a signed `RevocationUpdate` on `revocation_topic`.
const DEFAULT_REVOCATION_SYNC_TOPIC: &str = "pqc/revocations/sync/v1";

/// Rate limit for outbound sync requests to avoid turning stale-state into a spam amplifier.
const DEFAULT_SYNC_REQUEST_COOLDOWN: Duration = Duration::from_secs(30);

/// Default token bucket limits for expensive cryptographic verification work.
///
/// These values are intentionally conservative to protect CPU under sustained adversarial load.
/// For safety/security-critical deployments, tune them based on device class and expected fleet traffic.
const DEFAULT_SIGVERIFY_BUDGET_CAPACITY: u32 = 40;
const DEFAULT_SIGVERIFY_BUDGET_REFILL_PER_SEC: u32 = 20;

/// Default token bucket limits for expensive decryption/KEM work.
const DEFAULT_DECRYPT_BUDGET_CAPACITY: u32 = 20;
const DEFAULT_DECRYPT_BUDGET_REFILL_PER_SEC: u32 = 10;

/// Global budget caps protect against sender-id cardinality attacks (many spoofed IDs).
const DEFAULT_GLOBAL_SIGVERIFY_BUDGET_CAPACITY: u32 = 200;
const DEFAULT_GLOBAL_SIGVERIFY_BUDGET_REFILL_PER_SEC: u32 = 100;
const DEFAULT_GLOBAL_DECRYPT_BUDGET_CAPACITY: u32 = 80;
const DEFAULT_GLOBAL_DECRYPT_BUDGET_REFILL_PER_SEC: u32 = 40;

const DEFAULT_BUDGET_MAX_PEERS: usize = 10_000;

/// Maximum bytes read from a keystore file when computing integrity digests.
const MAX_KEYSTORE_FILE_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

const KEYSTORE_META_VERSION_V1: u8 = 1;
const KEYSTORE_META_BYTES_V1: usize = 1 + 8 + 32;

/// Fixed-rate token bucket.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
    capacity: u32,
    refill_rate_per_sec: u32,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate_per_sec: u32) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate_per_sec,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs() as u32;
        if elapsed > 0 {
            self.tokens = std::cmp::min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate_per_sec,
            );
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Per-peer token buckets with a hard cap on tracked peers.
#[derive(Debug, Clone)]
struct TokenBucketMap {
    peers: std::collections::HashMap<String, (u32, Instant)>,
    capacity: u32,
    refill_rate_per_sec: u32,
    max_peers: usize,
}

impl TokenBucketMap {
    fn new(capacity: u32, refill_rate_per_sec: u32, max_peers: usize) -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            capacity,
            refill_rate_per_sec,
            max_peers,
        }
    }

    fn allow(&mut self, peer_id: &str) -> bool {
        if self.peers.len() > self.max_peers {
            // Nuclear option under cardinality attack: drop state to bound memory.
            self.peers.clear();
        }

        let now = Instant::now();
        let (tokens, last_refill) = self
            .peers
            .entry(peer_id.to_string())
            .or_insert((self.capacity, now));

        let elapsed = now.duration_since(*last_refill).as_secs() as u32;
        if elapsed > 0 {
            *tokens = std::cmp::min(self.capacity, *tokens + elapsed * self.refill_rate_per_sec);
            *last_refill = now;
        }

        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}

fn is_filesystem_safe_id(id: &str) -> bool {
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_valid_wire_peer_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_WIRE_ID_LEN && is_filesystem_safe_id(id)
}

fn storage_id_for(client_id: &str) -> String {
    // Preserve readable IDs when they are already filesystem-safe and bounded.
    // Otherwise, hash to avoid traversal/injection via separators/.. components.
    let is_safe = is_filesystem_safe_id(client_id);
    if is_safe && client_id.len() <= 128 {
        client_id.to_string()
    } else {
        let digest = Sha256::digest(client_id.as_bytes());
        format!("id_{}", hex::encode(digest))
    }
}

fn encode_keystore_meta_v1(generation: u64, hash: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEYSTORE_META_BYTES_V1);
    out.push(KEYSTORE_META_VERSION_V1);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&hash);
    out
}

fn decode_keystore_meta_v1(blob: &[u8]) -> Result<(u64, [u8; 32])> {
    if blob.len() != KEYSTORE_META_BYTES_V1 {
        return Err(Error::CryptoError(format!(
            "Invalid keystore meta length: {}",
            blob.len()
        )));
    }
    if blob[0] != KEYSTORE_META_VERSION_V1 {
        return Err(Error::ProtocolError(format!(
            "Unsupported keystore meta version: {}",
            blob[0]
        )));
    }
    let mut gen_bytes = [0u8; 8];
    gen_bytes.copy_from_slice(&blob[1..9]);
    let generation = u64::from_be_bytes(gen_bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&blob[9..]);
    Ok((generation, hash))
}

/// Secure MQTT client using post-quantum cryptography
pub struct SecureMqttClient {
    options: MqttOptions,
    client: Option<Client>,
    // eventloop moved to thread
    // kyber: Kyber, // Removed as unused
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
    storage_id: String,
    sequence_number: u64,
    strict_mode: bool,
    /// If true, disallow v1 per-message hybrid encryption and require session/ratchet (v2).
    require_sessions: bool,
    /// If true, require rollback-resistant sealing/storage in the active fleet policy.
    require_rollback_resistant_storage: bool,
    /// Optional minimum revocation sequence required by fleet policy.
    min_revocation_seq: Option<u64>,
    /// Optional session rekey threshold (messages sent) from fleet policy.
    session_rekey_after_msgs: Option<u32>,
    /// Optional session rekey threshold (seconds since establishment) from fleet policy.
    session_rekey_after_secs: Option<u64>,
    /// Pinned mesh CA public key used to verify OperationalCertificates.
    trust_anchor_ca_sig_pk: Option<Vec<u8>>,
    /// This device's OperationalCertificate (factory -> operational).
    operational_cert: Option<OperationalCertificate>,
    /// If true, peers are marked trusted/ready only after a verifier-driven attestation challenge succeeds.
    attestation_required: bool,
    /// Expected PCR digest for attestation (simple policy; production should be per-device/per-firmware).
    expected_pcr_digest: Vec<u8>,
    /// Pending attestation nonces we issued: peer_id -> nonce.
    pending_attestation: std::collections::HashMap<String, Vec<u8>>,
    /// MQTT topic prefix for attestation challenges (default "pqc/attest/challenge/").
    attest_challenge_prefix: String,
    /// MQTT topic prefix for attestation quotes addressed to this verifier (default "pqc/attest/quote/").
    attest_quote_prefix: String,
    data_dir: std::path::PathBuf,
    encryption_key: Option<Zeroizing<Vec<u8>>>,

    // Observability
    audit_logger: Box<dyn AuditLogger>,
    metrics: Arc<SecurityMetrics>,

    // Reliability
    persist_manager: crate::persistence::LazyPersistManager,

    // Threading & Watchdog
    network_recv: Option<Receiver<std::result::Result<Event, rumqttc::ConnectionError>>>, // Receive events from thread
    heartbeat: Arc<AtomicU64>,
    key_prefix: String,

    // Hard limits (DoS containment)
    max_key_announcement_bytes: usize,
    max_attestation_bytes: usize,
    max_encrypted_message_bytes: usize,
    max_revocation_bytes: usize,
    revocation_topic: String,
    max_policy_bytes: usize,
    policy_topic: String,
    policy_sync_topic: String,
    fleet_policy: Option<FleetPolicyUpdate>,
    /// Sealed monotonic floor for the fleet policy sequence.
    ///
    /// This is meaningful only when the `SecurityProvider` is backed by rollback-resistant
    /// storage (TPM NV / HSM / TEE monotonic storage / WORM remote append-only).
    ///
    /// Used to detect policy rollback across restarts and fail closed under partitions.
    fleet_policy_seq_floor: u64,
    /// Sealed monotonic floor for the revocation sequence (CRL/denylist updates).
    ///
    /// This provides rollback resistance for emergency revocations under the same assumptions as
    /// `fleet_policy_seq_floor`.
    revocation_seq_floor: u64,

    // Asymmetric-cost DoS budgets (token buckets).
    sig_verify_budget: TokenBucketMap,
    decrypt_budget: TokenBucketMap,
    global_sig_verify_budget: TokenBucket,
    global_decrypt_budget: TokenBucket,

    // Secure time (best-effort monotonic floor)
    secure_time: SecureTimeFloor,

    // Session + ratchet (forward secrecy / PCS building block)
    max_session_bytes: usize,
    session_init_prefix: String,
    session_resp_prefix: String,
    pending_sessions: std::collections::HashMap<[u8; 16], PendingSessionInit>,
    sessions: std::collections::HashMap<String, PeerSessions>,
    session_resp_cache: std::collections::HashMap<String, CachedSessionResponse>,

    // Partition handling / catch-up
    revocation_sync_topic: String,
    last_policy_sync_request: Option<Instant>,
    last_revocation_sync_request: Option<Instant>,
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
    /// Persisted X25519 static secret used for Hybrid KEM decryption.
    /// Stored only for exportable software identities; hardware providers should seal internally.
    #[serde(default, with = "crate::security::keystore::base64_serde")]
    x25519_sk: Vec<u8>,
    /// Redundant (derivable) X25519 public key. Kept to detect file corruption/mismatch.
    #[serde(default, with = "crate::security::keystore::base64_serde")]
    x25519_pk: Vec<u8>,
    /// Optional pinned CA public key (Falcon) used for provisioning-backed trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::security::keystore::base64_serde_opt")]
    trust_anchor_ca_sig_pk: Option<Vec<u8>>,
    /// This device's OperationalCertificate (factory -> operational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operational_cert: Option<OperationalCertificate>,
    sequence_number: u64,
}

#[derive(Serialize, Deserialize)]
struct SealedIdentityMeta {
    version: u8,
    /// Optional pinned CA public key (Falcon) used for provisioning-backed trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::security::keystore::base64_serde_opt")]
    trust_anchor_ca_sig_pk: Option<Vec<u8>>,
    /// This device's OperationalCertificate (factory -> operational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operational_cert: Option<OperationalCertificate>,
    /// Outbound message sequence number (must be >= 1).
    sequence_number: u64,
}

impl SealedIdentityMeta {
    const VERSION_V1: u8 = 1;
}

fn identity_meta_label_for(storage_id: &str) -> String {
    format!("pqc-iiot:identity-meta:v1:{}", storage_id)
}

fn load_sealed_identity_meta(
    provider: &Arc<dyn SecurityProvider>,
    storage_id: &str,
) -> Result<(SealedIdentityMeta, bool)> {
    let label = identity_meta_label_for(storage_id);
    match provider.unseal_data(&label) {
        Ok(blob) => {
            let meta: SealedIdentityMeta = serde_json::from_slice(&blob).map_err(|e| {
                Error::ClientError(format!("Invalid sealed identity meta ({}): {}", label, e))
            })?;
            if meta.version != SealedIdentityMeta::VERSION_V1 {
                return Err(Error::ProtocolError(format!(
                    "Unsupported identity meta version: {}",
                    meta.version
                )));
            }
            Ok((meta, false))
        }
        Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok((
            SealedIdentityMeta {
                version: SealedIdentityMeta::VERSION_V1,
                trust_anchor_ca_sig_pk: None,
                operational_cert: None,
                sequence_number: 1,
            },
            true,
        )),
        Err(e) => Err(e),
    }
}

#[derive(Serialize, Deserialize)]
struct AttestationChallenge {
    verifier_id: String,
    #[serde(with = "crate::security::keystore::base64_serde")]
    nonce: Vec<u8>,
    ts: u64,
}

#[derive(Serialize, Deserialize)]
struct AttestationQuoteMessage {
    subject_id: String,
    quote: crate::attestation::quote::AttestationQuote,
}

#[derive(Serialize, Deserialize)]
struct SessionInitMessage {
    version: u8,
    initiator_id: String,
    responder_id: String,
    /// 16-byte session identifier (random, unique per handshake).
    #[serde(with = "crate::security::keystore::base64_serde")]
    session_id: Vec<u8>,
    /// Monotonic per-peer sequence number (anti-replay / anti-downgrade for session init).
    session_seq: u64,
    /// Initiator ephemeral Kyber public key.
    #[serde(with = "crate::security::keystore::base64_serde")]
    kem_pk: Vec<u8>,
    /// Initiator ephemeral X25519 public key (32 bytes).
    #[serde(with = "crate::security::keystore::base64_serde")]
    x25519_pk: Vec<u8>,
    /// Informational timestamp (unix seconds) from the initiator.
    ts: u64,
    /// Detached Falcon signature by the initiator over `session_init_payload_v1`.
    #[serde(with = "crate::security::keystore::base64_serde")]
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SessionResponseMessage {
    version: u8,
    initiator_id: String,
    responder_id: String,
    /// Session identifier from the initiator.
    #[serde(with = "crate::security::keystore::base64_serde")]
    session_id: Vec<u8>,
    /// Session sequence echoed from the initiator.
    session_seq: u64,
    /// Responder ephemeral X25519 public key (32 bytes).
    #[serde(with = "crate::security::keystore::base64_serde")]
    x25519_pk: Vec<u8>,
    /// Kyber encapsulation ciphertext to the initiator ephemeral KEM public key.
    #[serde(with = "crate::security::keystore::base64_serde")]
    kem_ciphertext: Vec<u8>,
    /// Informational timestamp (unix seconds) from the responder.
    ts: u64,
    /// Detached Falcon signature by the responder over `session_resp_payload_v1`.
    #[serde(with = "crate::security::keystore::base64_serde")]
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct FleetPolicySyncRequest {
    version: u8,
    client_id: String,
    current_seq: u64,
}

impl FleetPolicySyncRequest {
    const VERSION_V1: u8 = 1;
}

#[derive(Serialize, Deserialize)]
struct RevocationSyncRequest {
    version: u8,
    client_id: String,
    current_seq: u64,
}

impl RevocationSyncRequest {
    const VERSION_V1: u8 = 1;
}

impl SessionInitMessage {
    const VERSION_V1: u8 = 1;
}

impl SessionResponseMessage {
    const VERSION_V1: u8 = 1;
}

fn vec_to_16(bytes: &[u8]) -> Result<[u8; 16]> {
    if bytes.len() != 16 {
        return Err(Error::InvalidInput(format!(
            "Invalid 16-byte field length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn vec_to_32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "Invalid 32-byte field length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

struct SessionInitSigInput<'a> {
    topic: &'a str,
    session_id: &'a [u8; 16],
    session_seq: u64,
    initiator_id: &'a str,
    responder_id: &'a str,
    kem_pk: &'a [u8],
    x25519_pk: &'a [u8; 32],
    ts: u64,
}

fn session_init_payload_v1(input: &SessionInitSigInput<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"pqc-iiot:mqtt-session:init:v1");
    buf.extend_from_slice(&(input.topic.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.topic.as_bytes());
    buf.extend_from_slice(&(input.initiator_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.initiator_id.as_bytes());
    buf.extend_from_slice(&(input.responder_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.responder_id.as_bytes());
    buf.extend_from_slice(input.session_id);
    buf.extend_from_slice(&input.session_seq.to_be_bytes());
    buf.extend_from_slice(&input.ts.to_be_bytes());
    buf.extend_from_slice(&(input.kem_pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(input.kem_pk);
    buf.extend_from_slice(input.x25519_pk);
    buf
}

struct SessionRespSigInput<'a> {
    topic: &'a str,
    session_id: &'a [u8; 16],
    session_seq: u64,
    initiator_id: &'a str,
    responder_id: &'a str,
    x25519_pk: &'a [u8; 32],
    kem_ciphertext: &'a [u8],
    ts: u64,
}

fn session_resp_payload_v1(input: &SessionRespSigInput<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"pqc-iiot:mqtt-session:resp:v1");
    buf.extend_from_slice(&(input.topic.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.topic.as_bytes());
    buf.extend_from_slice(&(input.initiator_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.initiator_id.as_bytes());
    buf.extend_from_slice(&(input.responder_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(input.responder_id.as_bytes());
    buf.extend_from_slice(input.session_id);
    buf.extend_from_slice(&input.session_seq.to_be_bytes());
    buf.extend_from_slice(&input.ts.to_be_bytes());
    buf.extend_from_slice(input.x25519_pk);
    buf.extend_from_slice(&(input.kem_ciphertext.len() as u32).to_be_bytes());
    buf.extend_from_slice(input.kem_ciphertext);
    buf
}

fn kyber_for_pk_len(len: usize) -> Result<Kyber> {
    match len {
        800 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber512)),
        1184 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber768)),
        1568 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber1024)),
        _ => Err(Error::InvalidInput(format!(
            "Invalid Kyber public key length: {}",
            len
        ))),
    }
}

fn kyber_for_sk_len(len: usize) -> Result<Kyber> {
    match len {
        1632 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber512)),
        2400 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber768)),
        3168 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber1024)),
        _ => Err(Error::InvalidInput(format!(
            "Invalid Kyber secret key length: {}",
            len
        ))),
    }
}

fn derive_session_chain_keys_v1(kem_ss: &[u8], dh_ss: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if kem_ss.len() != 32 || dh_ss.len() != 32 {
        return Err(Error::CryptoError(format!(
            "Invalid session shared secret lengths: kem_ss={} dh_ss={}",
            kem_ss.len(),
            dh_ss.len()
        )));
    }
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(kem_ss);
    ikm[32..].copy_from_slice(dh_ss);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut ck_initiator = [0u8; 32];
    let mut ck_responder = [0u8; 32];
    hk.expand(b"pqc-iiot:mqtt-session:v1:ck-initiator", &mut ck_initiator)
        .map_err(|_| Error::CryptoError("HKDF expand failed (ck-initiator)".into()))?;
    hk.expand(b"pqc-iiot:mqtt-session:v1:ck-responder", &mut ck_responder)
        .map_err(|_| Error::CryptoError("HKDF expand failed (ck-responder)".into()))?;

    ikm.zeroize();

    Ok((ck_initiator, ck_responder))
}

const MQTT_SESSION_MAX_SKIPPED_KEYS: usize = 50;
const MQTT_SESSION_MAX_MESSAGES: u32 = 100_000;

#[derive(Debug)]
struct MqttSession {
    session_id: [u8; 16],
    created_at: Instant,
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    send_msg_num: u32,
    recv_msg_num: u32,
    skipped_message_keys: std::collections::HashMap<u32, [u8; 32]>,
}

impl MqttSession {
    fn new(session_id: [u8; 16], send_chain_key: [u8; 32], recv_chain_key: [u8; 32]) -> Self {
        Self {
            session_id,
            created_at: Instant::now(),
            send_chain_key,
            recv_chain_key,
            send_msg_num: 0,
            recv_msg_num: 0,
            skipped_message_keys: std::collections::HashMap::new(),
        }
    }

    fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let hkdf = Hkdf::<Sha256>::from_prk(ck)
            .map_err(|_| Error::CryptoError("HKDF PRK init failed".into()))?;
        let mut mk = [0u8; 32];
        let mut next_ck = [0u8; 32];
        hkdf.expand(b"pqc-iiot:mqtt-session:v1:mk", &mut mk)
            .map_err(|_| Error::CryptoError("HKDF expand failed (mk)".into()))?;
        hkdf.expand(b"pqc-iiot:mqtt-session:v1:ck", &mut next_ck)
            .map_err(|_| Error::CryptoError("HKDF expand failed (ck)".into()))?;
        Ok((next_ck, mk))
    }

    fn aad_v2(
        sender_id: &str,
        receiver_id: &str,
        topic: &str,
        session_id: &[u8; 16],
        msg_num: u32,
    ) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"pqc-iiot:mqtt-msg:v2");
        aad.extend_from_slice(&(sender_id.len() as u16).to_be_bytes());
        aad.extend_from_slice(sender_id.as_bytes());
        aad.extend_from_slice(&(receiver_id.len() as u16).to_be_bytes());
        aad.extend_from_slice(receiver_id.as_bytes());
        aad.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        aad.extend_from_slice(topic.as_bytes());
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&msg_num.to_be_bytes());
        aad
    }

    fn nonce_v2(session_id: &[u8; 16], msg_num: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&session_id[..8]);
        nonce[8..].copy_from_slice(&msg_num.to_be_bytes());
        nonce
    }

    fn encrypt_v2(
        &mut self,
        sender_id: &str,
        receiver_id: &str,
        topic: &str,
        plaintext: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        if self.send_msg_num >= MQTT_SESSION_MAX_MESSAGES {
            return Err(Error::ProtocolError(format!(
                "Session {} exhausted message budget (send)",
                hex::encode(self.session_id)
            )));
        }

        let (next_ck, mk) = Self::kdf_ck(&self.send_chain_key)?;
        self.send_chain_key = next_ck;
        let msg_num = self.send_msg_num;
        self.send_msg_num = self.send_msg_num.saturating_add(1);

        let aad = Self::aad_v2(sender_id, receiver_id, topic, &self.session_id, msg_num);
        let nonce_bytes = Self::nonce_v2(&self.session_id, msg_num);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&mk));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))?;

        Ok((msg_num, ciphertext))
    }

    fn decrypt_with_mk_v2(
        &self,
        sender_id: &str,
        receiver_id: &str,
        topic: &str,
        msg_num: u32,
        mk: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let aad = Self::aad_v2(sender_id, receiver_id, topic, &self.session_id, msg_num);
        let nonce_bytes = Self::nonce_v2(&self.session_id, msg_num);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(mk));
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
    }

    fn decrypt_v2(
        &mut self,
        sender_id: &str,
        receiver_id: &str,
        topic: &str,
        msg_num: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(mk) = self.skipped_message_keys.remove(&msg_num) {
            return self.decrypt_with_mk_v2(
                sender_id,
                receiver_id,
                topic,
                msg_num,
                &mk,
                ciphertext,
            );
        }

        if msg_num < self.recv_msg_num {
            return Err(Error::CryptoError("Message too old / replay".into()));
        }

        let delta = msg_num - self.recv_msg_num;
        if delta > MQTT_SESSION_MAX_SKIPPED_KEYS as u32 {
            return Err(Error::CryptoError(
                "Message too far in the future (skip limit exceeded)".into(),
            ));
        }

        while self.recv_msg_num < msg_num {
            let (next_ck, mk) = Self::kdf_ck(&self.recv_chain_key)?;
            self.skipped_message_keys.insert(self.recv_msg_num, mk);
            self.recv_chain_key = next_ck;
            self.recv_msg_num = self.recv_msg_num.saturating_add(1);
        }

        let (next_ck, mk) = Self::kdf_ck(&self.recv_chain_key)?;
        self.recv_chain_key = next_ck;
        self.recv_msg_num = self.recv_msg_num.saturating_add(1);

        self.decrypt_with_mk_v2(sender_id, receiver_id, topic, msg_num, &mk, ciphertext)
    }
}

impl Drop for MqttSession {
    fn drop(&mut self) {
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
        for (_, key) in self.skipped_message_keys.iter_mut() {
            key.zeroize();
        }
        self.skipped_message_keys.clear();
    }
}

/// Decryption grace window for the previous session after a rotation.
///
/// This is an availability safeguard: MQTT can reorder/duplicate deliveries, so in-flight packets
/// encrypted under the previous session may arrive after the handshake completes.
const MQTT_PREVIOUS_SESSION_GRACE: Duration = Duration::from_secs(30);

struct PeerSessions {
    current: MqttSession,
    previous: Option<(MqttSession, Instant)>,
}

impl PeerSessions {
    fn new(current: MqttSession) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    fn rotate_to(&mut self, new_session: MqttSession) {
        let old = std::mem::replace(&mut self.current, new_session);
        self.previous = Some((old, Instant::now()));
    }

    fn prune(&mut self) {
        if let Some((_, since)) = &self.previous {
            if since.elapsed() > MQTT_PREVIOUS_SESSION_GRACE {
                self.previous = None;
            }
        }
    }

    fn current_mut(&mut self) -> &mut MqttSession {
        self.prune();
        &mut self.current
    }

    fn get_mut_by_session_id(&mut self, session_id: &[u8; 16]) -> Option<&mut MqttSession> {
        self.prune();
        if &self.current.session_id == session_id {
            return Some(&mut self.current);
        }
        if let Some((prev, _)) = self.previous.as_mut() {
            if &prev.session_id == session_id {
                return Some(prev);
            }
        }
        None
    }
}

struct PendingSessionInit {
    peer_id: String,
    session_seq: u64,
    kem_sk: Zeroizing<Vec<u8>>,
    x25519_sk: X25519StaticSecret,
}

struct CachedSessionResponse {
    session_seq: u64,
    session_id: [u8; 16],
    bytes: Vec<u8>,
}

impl Drop for PendingSessionInit {
    fn drop(&mut self) {
        self.kem_sk.zeroize();
        // x25519_dalek secrets are zeroized on drop.
    }
}

/// Canonical payload used for signing/verifying key announcements.
/// Excludes the detached signature field to avoid recursion.
fn key_announcement_payload(peer_id: &str, keys: &PeerKeys) -> Vec<u8> {
    let mut buf = Vec::new();
    // Domain separation + identity binding: prevents re-publishing a signed announcement under a different topic/id.
    buf.extend_from_slice(b"pqc-iiot:key-announce:v2");
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id.as_bytes());
    buf.extend_from_slice(&keys.key_epoch.to_be_bytes());
    if let Some(key_id) = &keys.key_id {
        buf.push(1);
        buf.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(key_id);
    } else {
        buf.push(0);
    }
    buf.extend_from_slice(&(keys.kem_pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(&keys.kem_pk);
    buf.extend_from_slice(&(keys.sig_pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(&keys.sig_pk);
    buf.extend_from_slice(&(keys.x25519_pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(&keys.x25519_pk);

    if let Some(cert) = &keys.operational_cert {
        buf.push(1);
        buf.push(cert.version);
        buf.extend_from_slice(&(cert.device_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(cert.device_id.as_bytes());
        buf.extend_from_slice(&cert.key_epoch.to_be_bytes());
        buf.extend_from_slice(&cert.expires_at.to_be_bytes());
        buf.extend_from_slice(&(cert.key_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&cert.key_id);
        buf.extend_from_slice(&(cert.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&cert.signature);
    } else {
        buf.push(0);
    }

    if let Some(quote) = &keys.quote {
        buf.push(1);
        buf.extend_from_slice(&(quote.pcr_digest.len() as u32).to_be_bytes());
        buf.extend_from_slice(&quote.pcr_digest);
        buf.extend_from_slice(&(quote.nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(&quote.nonce);
        buf.extend_from_slice(&(quote.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&quote.signature);
        buf.extend_from_slice(&(quote.ak_public_key.len() as u32).to_be_bytes());
        buf.extend_from_slice(&quote.ak_public_key);
    } else {
        buf.push(0);
    }

    buf
}

fn mqtt_encrypted_message_signature_digest(
    sender_id: &str,
    topic: &str,
    encrypted_blob: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pqc-iiot:mqtt-msg:v1");
    hasher.update((sender_id.len() as u16).to_be_bytes());
    hasher.update(sender_id.as_bytes());
    hasher.update((topic.len() as u16).to_be_bytes());
    hasher.update(topic.as_bytes());
    hasher.update((encrypted_blob.len() as u32).to_be_bytes());
    hasher.update(encrypted_blob);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Sliding replay window check.
///
/// Returns `true` if `seq` is accepted and updates `(last_sequence, replay_window)` in-place.
/// Returns `false` if `seq` is a replay or is too old (outside the window).
fn replay_window_accept(last_sequence: &mut u64, replay_window: &mut u64, seq: u64) -> bool {
    const WINDOW_BITS: u64 = 64;

    if seq == 0 {
        return false;
    }

    if *last_sequence == 0 {
        *last_sequence = seq;
        *replay_window = 1;
        return true;
    }

    if seq > *last_sequence {
        let delta = seq - *last_sequence;
        if delta >= WINDOW_BITS {
            *replay_window = 1;
        } else {
            *replay_window <<= delta;
            *replay_window |= 1;
        }
        *last_sequence = seq;
        return true;
    }

    let delta = *last_sequence - seq;
    if delta >= WINDOW_BITS {
        return false;
    }
    let mask = 1u64 << delta;
    if (*replay_window & mask) != 0 {
        return false;
    }
    *replay_window |= mask;
    true
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

    /// Create a new Secure MQTT client using an externally provided `SecurityProvider` (TPM/HSM/TEE).
    ///
    /// In this mode, long-term secrets are assumed to be managed by the provider and are **not**
    /// loaded from or written to the local identity file. Only non-secret metadata
    /// (CA trust anchor, operational certificate, sequence number) is persisted via
    /// `SecurityProvider::seal_data`.
    pub fn new_with_provider(
        broker: &str,
        port: u16,
        client_id: &str,
        provider: Arc<dyn SecurityProvider>,
    ) -> Result<Self> {
        Self::init_with_provider(broker, port, client_id, provider)
    }

    fn init(broker: &str, port: u16, client_id: &str, key: Option<Vec<u8>>) -> Result<Self> {
        // MQTT identities are used on-wire as topic suffixes and message prefixes.
        // Enforce a strict, bounded charset to avoid topic injection and cardinality DoS.
        if !is_valid_wire_peer_id(client_id) {
            return Err(Error::InvalidInput(format!(
                "Invalid client_id (must match [A-Za-z0-9_.-] and be <= {} bytes)",
                MAX_WIRE_ID_LEN
            )));
        }

        // Run FIPS/Compliance Self-Tests on startup
        crate::compliance::run_self_tests()?;

        let storage_id = storage_id_for(client_id);
        let encryption_key = key.map(Zeroizing::new);
        if let Some(k) = &encryption_key {
            if k.len() != 32 {
                return Err(Error::ClientError(
                    "Encryption key must be 32 bytes (AES-256)".to_string(),
                ));
            }
        }

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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
            {
                warn!("failed to set permissions on {:?}: {}", data_dir, e);
            }
        }
        let data_dir = data_dir.to_path_buf();

        let mut need_save_identity = false;
        let mut regenerated_x25519 = false;
        // Load Identity if exists
        let storage_identity_path = data_dir.join(format!("identity_{}.json", storage_id));
        let mut identity_path = storage_identity_path.clone();
        // Legacy path migration: only attempt when client_id is filesystem-safe (no separators).
        if !storage_identity_path.exists()
            && is_filesystem_safe_id(client_id)
            && client_id.len() <= 240
        {
            let legacy_identity_path = data_dir.join(format!("identity_{}.json", client_id));
            if legacy_identity_path.exists() {
                identity_path = legacy_identity_path;
                // Migrate to the new storage path on next flush.
                need_save_identity = true;
            }
        }

        let (pk, sk, sig_pk, sig_sk, x25519_sk, trust_anchor_ca_sig_pk, operational_cert, seq) =
            if identity_path.exists() {
                let _event = SecurityEvent::IdentityLoaded {
                    peer_id: client_id.to_string(),
                    path: identity_path
                        .to_str()
                        .unwrap_or("INVALID_UTF8_PATH")
                        .to_string(),
                };
                // Log to global log for startup visibility
                log::info!(
                    "[AUDIT] IdentityLoaded {{ peer_id: {}, path: {:?} }}",
                    client_id,
                    identity_path
                );

                const MAX_IDENTITY_BYTES: usize = 256 * 1024; // anti-OOM guardrail
                let buffer = Zeroizing::new(crate::persistence::AtomicFileStore::read_with_limit(
                    &identity_path,
                    MAX_IDENTITY_BYTES,
                )?);

                // If encrypted, decrypt first
                let own_keys: OwnKeys = if let Some(k) = &encryption_key {
                    // New format: [MAGIC][nonce:12][ciphertext+tag]
                    // Legacy format: [nonce:12][ciphertext+tag]
                    let (blob, is_magic) = if buffer.starts_with(IDENTITY_ENC_MAGIC) {
                        (&buffer[IDENTITY_ENC_MAGIC.len()..], true)
                    } else {
                        (&buffer[..], false)
                    };

                    // Expect Nonce (12) + Ciphertext
                    if blob.len() < 12 {
                        return Err(Error::ClientError("Encrypted file too short".to_string()));
                    }

                    let (nonce_bytes, ciphertext) = blob.split_at(12);
                    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k.as_slice()));
                    let nonce = Nonce::from_slice(nonce_bytes);

                    let plaintext =
                        Zeroizing::new(cipher.decrypt(nonce, ciphertext).map_err(|_| {
                            Error::ClientError(
                                "Decryption failed: Invalid key or corrupted file".to_string(),
                            )
                        })?);

                    // Successful legacy decrypt => rewrite with magic prefix on next flush.
                    if !is_magic {
                        need_save_identity = true;
                    }

                    serde_json::from_slice(plaintext.as_slice())
                        .map_err(|e| Error::ClientError(format!("Deserialization error: {}", e)))?
                } else {
                    serde_json::from_slice(buffer.as_slice()).map_err(|e| {
                        Error::ClientError(format!("Deserialization error (expected JSON): {}", e))
                    })?
                };

                // X25519 secret persistence (required for Hybrid KEM decrypt).
                let OwnKeys {
                    secret_key,
                    public_key,
                    sig_sk,
                    sig_pk,
                    x25519_sk,
                    x25519_pk,
                    trust_anchor_ca_sig_pk,
                    operational_cert,
                    sequence_number,
                } = own_keys;

                let mut x25519_sk_bytes = [0u8; 32];
                {
                    let x25519_sk = Zeroizing::new(x25519_sk);
                    if x25519_sk.len() == 32 {
                        x25519_sk_bytes.copy_from_slice(&x25519_sk);
                    } else {
                        // Identity files created before hybrid support will not carry an X25519 secret.
                        // Generate a new one but *invalidate* any existing OperationalCertificate.
                        regenerated_x25519 = true;
                        need_save_identity = true;
                        rand_core::OsRng.fill_bytes(&mut x25519_sk_bytes);
                    }
                }

                let x_secret = x25519_dalek::StaticSecret::from(x25519_sk_bytes);
                let computed_pk = x25519_dalek::PublicKey::from(&x_secret).to_bytes().to_vec();

                if !x25519_pk.is_empty() {
                    if x25519_pk.len() != 32 || x25519_pk != computed_pk {
                        return Err(Error::ClientError(
                            "Identity x25519_pk mismatch (corrupt file or mixed identities)"
                                .to_string(),
                        ));
                    }
                } else {
                    // Older identities may not store the derived pk. Persist for consistency.
                    need_save_identity = true;
                }

                let operational_cert = if regenerated_x25519 {
                    if operational_cert.is_some() {
                        warn!(
                        "OperationalCertificate cleared for {}: regenerated x25519 secret invalidates provisioned identity",
                        client_id
                    );
                    }
                    None
                } else {
                    operational_cert
                };

                (
                    public_key,
                    secret_key,
                    sig_pk,
                    sig_sk,
                    x25519_sk_bytes,
                    trust_anchor_ca_sig_pk,
                    operational_cert,
                    sequence_number,
                )
            } else {
                // Generate NEW keys
                // log_security_event(&SecurityEvent::IdentityGenerated { client_id });
                log::info!("Generating new identity for client: {}", client_id);
                let (pk, sk) = kyber.generate_keypair()?;
                let (sig_pk, sig_sk) = falcon.generate_keypair()?;
                let mut x25519_sk_bytes = [0u8; 32];
                rand_core::OsRng.fill_bytes(&mut x25519_sk_bytes);
                need_save_identity = true;
                (pk, sk, sig_pk, sig_sk, x25519_sk_bytes, None, None, 1)
            };

        // Load Keystore
        let storage_keystore_path = data_dir.join(format!("keystore_{}.json", storage_id));
        let mut keystore_path = storage_keystore_path.clone();
        let mut need_flush_keystore = false;
        // Legacy keystore migration: only attempt when client_id is filesystem-safe (no separators).
        if !storage_keystore_path.exists()
            && is_filesystem_safe_id(client_id)
            && client_id.len() <= 240
        {
            let legacy_keystore_path = data_dir.join(format!("keystore_{}.json", client_id));
            if legacy_keystore_path.exists() {
                keystore_path = legacy_keystore_path;
                need_flush_keystore = true;
            }
        }

        let keystore_path_str = keystore_path.to_str().ok_or(Error::ClientError(
            "Invalid Keystore Path (Non-UTF8)".into(),
        ))?;
        let keystore = KeyStore::load_from_file(keystore_path_str)?;

        // Instantiate SoftwareSecurityProvider (exportable for identity persistence).
        // X25519 static secret must be pinned to avoid "self-bricking" decryption failures after restart.
        let mut x25519_sk_bytes = x25519_sk;
        let provider: Arc<dyn SecurityProvider> =
            Arc::new(SoftwareSecurityProvider::new_exportable_with_x25519(
                sk,
                pk.clone(),
                sig_sk,
                sig_pk.clone(),
                x25519_sk_bytes,
            ));
        x25519_sk_bytes.zeroize();

        let audit_signer = provider.clone();
        let secure_time = SecureTimeFloor::load(
            provider.clone(),
            format!("pqc-iiot:time-floor:v1:{}", storage_id),
        )?;

        let mut client = SecureMqttClient {
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
            storage_id,
            // Secure by default: reject unknown peers unless explicitly opted out.
            strict_mode: true,
            require_sessions: false,
            require_rollback_resistant_storage: false,
            min_revocation_seq: None,
            session_rekey_after_msgs: None,
            session_rekey_after_secs: None,
            trust_anchor_ca_sig_pk,
            operational_cert,
            attestation_required: false,
            expected_pcr_digest: vec![0u8; 32],
            pending_attestation: std::collections::HashMap::new(),
            attest_challenge_prefix: "pqc/attest/challenge/".to_string(),
            attest_quote_prefix: "pqc/attest/quote/".to_string(),
            data_dir: data_dir.clone(), // Clone here to avoid move
            encryption_key,
            // kyber, // Removed
            audit_logger: Box::new(ChainedAuditLogger::new_signed(&data_dir, audit_signer)),
            metrics: Arc::new(SecurityMetrics::new()),
            persist_manager: crate::persistence::LazyPersistManager::new(
                Duration::from_secs(300), // Flush every 5 mins
                50,                       // OR every 50 updates
            ),
            network_recv: None,
            heartbeat: Arc::new(AtomicU64::new(0)),
            key_prefix: "pqc/keys/".to_string(),
            max_key_announcement_bytes: DEFAULT_MAX_KEY_ANNOUNCEMENT_BYTES,
            max_attestation_bytes: DEFAULT_MAX_ATTESTATION_BYTES,
            max_encrypted_message_bytes: DEFAULT_MAX_ENCRYPTED_MESSAGE_BYTES,
            max_revocation_bytes: DEFAULT_MAX_REVOCATION_BYTES,
            revocation_topic: "pqc/revocations/v1".to_string(),
            max_policy_bytes: DEFAULT_MAX_POLICY_BYTES,
            policy_topic: DEFAULT_POLICY_TOPIC.to_string(),
            policy_sync_topic: DEFAULT_POLICY_SYNC_TOPIC.to_string(),
            fleet_policy: None,
            fleet_policy_seq_floor: 0,
            revocation_seq_floor: 0,
            sig_verify_budget: TokenBucketMap::new(
                DEFAULT_SIGVERIFY_BUDGET_CAPACITY,
                DEFAULT_SIGVERIFY_BUDGET_REFILL_PER_SEC,
                DEFAULT_BUDGET_MAX_PEERS,
            ),
            decrypt_budget: TokenBucketMap::new(
                DEFAULT_DECRYPT_BUDGET_CAPACITY,
                DEFAULT_DECRYPT_BUDGET_REFILL_PER_SEC,
                DEFAULT_BUDGET_MAX_PEERS,
            ),
            global_sig_verify_budget: TokenBucket::new(
                DEFAULT_GLOBAL_SIGVERIFY_BUDGET_CAPACITY,
                DEFAULT_GLOBAL_SIGVERIFY_BUDGET_REFILL_PER_SEC,
            ),
            global_decrypt_budget: TokenBucket::new(
                DEFAULT_GLOBAL_DECRYPT_BUDGET_CAPACITY,
                DEFAULT_GLOBAL_DECRYPT_BUDGET_REFILL_PER_SEC,
            ),
            secure_time,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            session_init_prefix: DEFAULT_SESSION_INIT_PREFIX.to_string(),
            session_resp_prefix: DEFAULT_SESSION_RESP_PREFIX.to_string(),
            pending_sessions: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            session_resp_cache: std::collections::HashMap::new(),
            revocation_sync_topic: DEFAULT_REVOCATION_SYNC_TOPIC.to_string(),
            last_policy_sync_request: None,
            last_revocation_sync_request: None,
        };

        // Migrate legacy keystore to the new storage path (best-effort; atomic write).
        if need_flush_keystore {
            client.flush_keystore()?;
        }

        // Persist identity if newly generated or migrated (e.g. backfilled x25519 fields).
        if need_save_identity {
            client.save_identity()?;
        }

        // Initialize keystore anti-rollback binding after any legacy migration flush.
        client.init_keystore_anti_rollback()?;
        client.load_revocation_seq_floor()?;
        client.load_fleet_policy_seq_floor()?;

        if let Some(policy) = client.load_sealed_fleet_policy()? {
            if let Some(ca_pk) = client.trust_anchor_ca_sig_pk.clone() {
                if let Err(e) = policy.verify(&ca_pk, &client.policy_topic) {
                    warn!("Ignoring sealed fleet policy: {}", e);
                } else {
                    if policy.seq < client.fleet_policy_seq_floor {
                        warn!(
                            "Ignoring sealed fleet policy: seq rollback detected (policy_seq={} < sealed_floor={})",
                            policy.seq, client.fleet_policy_seq_floor
                        );
                    } else {
                        // Crash window repair: policy was sealed but the monotonic floor wasn't advanced.
                        let label = client.fleet_policy_seq_label();
                        let _ = client
                            .provider
                            .sealed_monotonic_u64_advance_to(&label, policy.seq)?;
                        client.fleet_policy_seq_floor =
                            client.fleet_policy_seq_floor.max(policy.seq);
                        client.apply_fleet_policy(policy);
                    }
                }
            }
        }

        Ok(client)
    }

    fn init_with_provider(
        broker: &str,
        port: u16,
        client_id: &str,
        provider: Arc<dyn SecurityProvider>,
    ) -> Result<Self> {
        if !is_valid_wire_peer_id(client_id) {
            return Err(Error::InvalidInput(format!(
                "Invalid client_id (must match [A-Za-z0-9_.-] and be <= {} bytes)",
                MAX_WIRE_ID_LEN
            )));
        }

        crate::compliance::run_self_tests()?;

        let storage_id = storage_id_for(client_id);

        let mut options = MqttOptions::new(client_id, broker, port);
        options.set_keep_alive(Duration::from_secs(5));
        options.set_clean_session(true);

        let data_dir = std::path::Path::new("pqc-data");
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir).map_err(Error::IoError)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
            {
                warn!("failed to set permissions on {:?}: {}", data_dir, e);
            }
        }
        let data_dir = data_dir.to_path_buf();

        // Load keystore.
        let keystore_path = data_dir.join(format!("keystore_{}.json", storage_id));
        let keystore_path_str = keystore_path.to_str().ok_or(Error::ClientError(
            "Invalid Keystore Path (Non-UTF8)".into(),
        ))?;
        let keystore = KeyStore::load_from_file(keystore_path_str)?;

        // Load sealed identity metadata (best-effort; first run initializes defaults).
        let (meta, meta_missing) = load_sealed_identity_meta(&provider, &storage_id)?;
        let mut sequence_number = meta.sequence_number;
        if sequence_number == 0 {
            sequence_number = 1;
        }

        let audit_signer = provider.clone();
        let secure_time = SecureTimeFloor::load(
            provider.clone(),
            format!("pqc-iiot:time-floor:v1:{}", storage_id),
        )?;

        let mut client = SecureMqttClient {
            client: None,
            options,
            keystore,
            public_key: provider.kem_public_key().to_vec(),
            sig_pk: provider.sig_public_key().to_vec(),
            provider,
            sequence_number,
            client_id: client_id.to_string(),
            storage_id: storage_id.clone(),
            strict_mode: true,
            require_sessions: false,
            require_rollback_resistant_storage: false,
            min_revocation_seq: None,
            session_rekey_after_msgs: None,
            session_rekey_after_secs: None,
            trust_anchor_ca_sig_pk: meta.trust_anchor_ca_sig_pk,
            operational_cert: meta.operational_cert,
            attestation_required: false,
            expected_pcr_digest: vec![0u8; 32],
            pending_attestation: std::collections::HashMap::new(),
            attest_challenge_prefix: "pqc/attest/challenge/".to_string(),
            attest_quote_prefix: "pqc/attest/quote/".to_string(),
            data_dir: data_dir.clone(),
            encryption_key: None,
            audit_logger: Box::new(ChainedAuditLogger::new_signed(&data_dir, audit_signer)),
            metrics: Arc::new(SecurityMetrics::new()),
            persist_manager: crate::persistence::LazyPersistManager::new(
                Duration::from_secs(300),
                50,
            ),
            network_recv: None,
            heartbeat: Arc::new(AtomicU64::new(0)),
            key_prefix: "pqc/keys/".to_string(),
            max_key_announcement_bytes: DEFAULT_MAX_KEY_ANNOUNCEMENT_BYTES,
            max_attestation_bytes: DEFAULT_MAX_ATTESTATION_BYTES,
            max_encrypted_message_bytes: DEFAULT_MAX_ENCRYPTED_MESSAGE_BYTES,
            max_revocation_bytes: DEFAULT_MAX_REVOCATION_BYTES,
            revocation_topic: "pqc/revocations/v1".to_string(),
            max_policy_bytes: DEFAULT_MAX_POLICY_BYTES,
            policy_topic: DEFAULT_POLICY_TOPIC.to_string(),
            policy_sync_topic: DEFAULT_POLICY_SYNC_TOPIC.to_string(),
            fleet_policy: None,
            fleet_policy_seq_floor: 0,
            revocation_seq_floor: 0,
            sig_verify_budget: TokenBucketMap::new(
                DEFAULT_SIGVERIFY_BUDGET_CAPACITY,
                DEFAULT_SIGVERIFY_BUDGET_REFILL_PER_SEC,
                DEFAULT_BUDGET_MAX_PEERS,
            ),
            decrypt_budget: TokenBucketMap::new(
                DEFAULT_DECRYPT_BUDGET_CAPACITY,
                DEFAULT_DECRYPT_BUDGET_REFILL_PER_SEC,
                DEFAULT_BUDGET_MAX_PEERS,
            ),
            global_sig_verify_budget: TokenBucket::new(
                DEFAULT_GLOBAL_SIGVERIFY_BUDGET_CAPACITY,
                DEFAULT_GLOBAL_SIGVERIFY_BUDGET_REFILL_PER_SEC,
            ),
            global_decrypt_budget: TokenBucket::new(
                DEFAULT_GLOBAL_DECRYPT_BUDGET_CAPACITY,
                DEFAULT_GLOBAL_DECRYPT_BUDGET_REFILL_PER_SEC,
            ),
            secure_time,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            session_init_prefix: DEFAULT_SESSION_INIT_PREFIX.to_string(),
            session_resp_prefix: DEFAULT_SESSION_RESP_PREFIX.to_string(),
            pending_sessions: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            session_resp_cache: std::collections::HashMap::new(),
            revocation_sync_topic: DEFAULT_REVOCATION_SYNC_TOPIC.to_string(),
            last_policy_sync_request: None,
            last_revocation_sync_request: None,
        };

        if !client.provider.is_rollback_resistant_storage() {
            warn!(
                "SecurityProvider '{}' does not provide rollback-resistant storage; secure time and anti-rollback checks are best-effort only",
                client.provider.provider_kind()
            );
        }

        // Anchor keystore anti-rollback counter.
        client.init_keystore_anti_rollback()?;
        client.load_revocation_seq_floor()?;
        client.load_fleet_policy_seq_floor()?;

        if let Some(policy) = client.load_sealed_fleet_policy()? {
            if let Some(ca_pk) = client.trust_anchor_ca_sig_pk.clone() {
                if let Err(e) = policy.verify(&ca_pk, &client.policy_topic) {
                    warn!("Ignoring sealed fleet policy: {}", e);
                } else {
                    if policy.seq < client.fleet_policy_seq_floor {
                        warn!(
                            "Ignoring sealed fleet policy: seq rollback detected (policy_seq={} < sealed_floor={})",
                            policy.seq, client.fleet_policy_seq_floor
                        );
                    } else {
                        let label = client.fleet_policy_seq_label();
                        let _ = client
                            .provider
                            .sealed_monotonic_u64_advance_to(&label, policy.seq)?;
                        client.fleet_policy_seq_floor =
                            client.fleet_policy_seq_floor.max(policy.seq);
                        client.apply_fleet_policy(policy);
                    }
                }
            }
        }

        // First run: persist initial metadata so subsequent boots have a stable anchor.
        if meta_missing {
            client.save_identity()?;
        }

        Ok(client)
    }

    /// Save the current identity to disk.
    pub fn save_identity(&self) -> Result<()> {
        // Non-exportable providers (TPM/HSM) persist only non-secret metadata behind seal/unseal.
        if self.provider.export_secret_keys().is_none() {
            return self.seal_identity_meta();
        }

        // Export keys from provider (software identity path).
        let exported = self.provider.export_secret_keys().ok_or_else(|| {
            Error::ClientError("Cannot save identity: Provider does not export keys".to_string())
        })?;

        let x25519_pk = self.provider.x25519_public_key();

        let mut own_keys = OwnKeys {
            public_key: self.public_key.clone(),
            secret_key: exported.kem_sk,
            sig_pk: self.sig_pk.clone(),
            sig_sk: exported.sig_sk,
            x25519_sk: exported.x25519_sk.to_vec(),
            x25519_pk: x25519_pk.to_vec(),
            trust_anchor_ca_sig_pk: self.trust_anchor_ca_sig_pk.clone(),
            operational_cert: self.operational_cert.clone(),
            sequence_number: self.sequence_number,
        };
        let identity_path = self
            .data_dir
            .join(format!("identity_{}.json", self.storage_id));

        let data_to_write = if let Some(key) = &self.encryption_key {
            // Encrypt
            let plaintext = Zeroizing::new(
                serde_json::to_vec(&own_keys)
                    .map_err(|e| Error::ClientError(format!("Serialization error: {}", e)))?,
            );

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
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
            let mut final_blob =
                Vec::with_capacity(IDENTITY_ENC_MAGIC.len() + 12 + ciphertext.len());
            final_blob.extend_from_slice(IDENTITY_ENC_MAGIC);
            final_blob.extend_from_slice(&nonce_bytes);
            final_blob.extend_from_slice(&ciphertext);
            Zeroizing::new(final_blob)
        } else {
            // Plain JSON
            Zeroizing::new(
                serde_json::to_vec_pretty(&own_keys)
                    .map_err(|e| Error::ClientError(format!("Serialization error: {}", e)))?,
            )
        };

        // ATOMIC WRITE
        AtomicFileStore::write(&identity_path, data_to_write.as_slice())?;

        // Best-effort scrubbing of exported secrets (software provider only).
        own_keys.secret_key.zeroize();
        own_keys.sig_sk.zeroize();
        own_keys.x25519_sk.zeroize();
        Ok(())
    }

    fn identity_meta_label(&self) -> String {
        format!("pqc-iiot:identity-meta:v1:{}", self.storage_id)
    }

    fn session_out_seq_label(&self, peer_id: &str) -> String {
        format!(
            "pqc-iiot:mqtt-session-outseq:v1:{}:{}",
            self.storage_id,
            storage_id_for(peer_id)
        )
    }

    fn session_in_seq_label(&self, peer_id: &str) -> String {
        format!(
            "pqc-iiot:mqtt-session-inseq:v1:{}:{}",
            self.storage_id,
            storage_id_for(peer_id)
        )
    }

    fn next_session_seq(&self, peer_id: &str) -> Result<u64> {
        let label = self.session_out_seq_label(peer_id);
        self.provider.sealed_monotonic_u64_increment(&label)
    }

    fn last_inbound_session_seq(&self, peer_id: &str) -> Result<u64> {
        let label = self.session_in_seq_label(peer_id);
        Ok(self.provider.sealed_monotonic_u64_get(&label)?.unwrap_or(0))
    }

    fn persist_inbound_session_seq(&self, peer_id: &str, seq: u64) -> Result<()> {
        let label = self.session_in_seq_label(peer_id);
        let _ = self.provider.sealed_monotonic_u64_advance_to(&label, seq)?;
        Ok(())
    }

    fn fleet_policy_label(&self) -> String {
        format!("pqc-iiot:fleet-policy:v1:{}", self.storage_id)
    }

    fn fleet_policy_seq_label(&self) -> String {
        format!("pqc-iiot:fleet-policy-seq:v1:{}", self.storage_id)
    }

    fn revocation_seq_label(&self) -> String {
        format!("pqc-iiot:revocation-seq:v1:{}", self.storage_id)
    }

    fn load_sealed_fleet_policy(&self) -> Result<Option<FleetPolicyUpdate>> {
        let label = self.fleet_policy_label();
        match self.provider.unseal_data(&label) {
            Ok(blob) => {
                let policy: FleetPolicyUpdate = serde_json::from_slice(&blob).map_err(|e| {
                    Error::ClientError(format!("Invalid sealed fleet policy ({}): {}", label, e))
                })?;
                Ok(Some(policy))
            }
            Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn seal_fleet_policy(&self, policy: &FleetPolicyUpdate) -> Result<()> {
        let label = self.fleet_policy_label();
        let blob = serde_json::to_vec(policy)
            .map_err(|e| Error::ClientError(format!("Fleet policy serialization error: {}", e)))?;
        self.provider.seal_data(&label, &blob)
    }

    fn load_fleet_policy_seq_floor(&mut self) -> Result<()> {
        let label = self.fleet_policy_seq_label();
        let sealed = self.provider.sealed_monotonic_u64_get(&label)?.unwrap_or(0);
        self.fleet_policy_seq_floor = self.fleet_policy_seq_floor.max(sealed);
        Ok(())
    }

    fn load_revocation_seq_floor(&mut self) -> Result<()> {
        let label = self.revocation_seq_label();
        let sealed = self.provider.sealed_monotonic_u64_get(&label)?.unwrap_or(0);
        self.revocation_seq_floor = self.revocation_seq_floor.max(sealed);

        let file_seq = self.keystore.revocation_seq();
        if file_seq > self.revocation_seq_floor {
            // Crash window repair / upgrade path: keystore has advanced but the sealed floor hasn't.
            let _ = self
                .provider
                .sealed_monotonic_u64_advance_to(&label, file_seq)?;
            self.revocation_seq_floor = file_seq;
        } else if file_seq < self.revocation_seq_floor {
            warn!(
                "revocation seq rollback detected: file_seq={} sealed_floor={} (storage_id={})",
                file_seq, self.revocation_seq_floor, self.storage_id
            );
        }

        Ok(())
    }

    fn apply_fleet_policy(&mut self, policy: FleetPolicyUpdate) {
        self.strict_mode = policy.strict_mode;
        self.attestation_required = policy.attestation_required;
        self.require_sessions = policy.require_sessions;
        self.require_rollback_resistant_storage = policy.require_rollback_resistant_storage;
        self.min_revocation_seq = policy.min_revocation_seq;
        self.session_rekey_after_msgs = policy.session_rekey_after_msgs;
        self.session_rekey_after_secs = policy.session_rekey_after_secs;

        if let Some(b) = &policy.sig_verify_budget {
            let max_peers = self.sig_verify_budget.max_peers;
            self.sig_verify_budget =
                TokenBucketMap::new(b.per_peer_capacity, b.per_peer_refill_per_sec, max_peers);
            self.global_sig_verify_budget =
                TokenBucket::new(b.global_capacity, b.global_refill_per_sec);
        }
        if let Some(b) = &policy.decrypt_budget {
            let max_peers = self.decrypt_budget.max_peers;
            self.decrypt_budget =
                TokenBucketMap::new(b.per_peer_capacity, b.per_peer_refill_per_sec, max_peers);
            self.global_decrypt_budget =
                TokenBucket::new(b.global_capacity, b.global_refill_per_sec);
        }

        self.fleet_policy = Some(policy);
    }

    fn ensure_fleet_policy_caught_up(&mut self, op: &str) -> Result<()> {
        let floor = self.fleet_policy_seq_floor;
        if floor == 0 {
            return Ok(());
        }
        let have = self.fleet_policy.as_ref().map(|p| p.seq).unwrap_or(0);
        if have < floor {
            warn!(
                "fleet policy state behind sealed floor: have_seq={} < floor_seq={} (op={})",
                have, floor, op
            );
            let _ = self.maybe_request_fleet_policy_sync();
            return Err(Error::ClientError(format!(
                "Fleet policy state behind sealed floor (have_seq={} < floor_seq={}); refusing {}",
                have, floor, op
            )));
        }
        Ok(())
    }

    fn ensure_storage_assurance(&self, op: &str) -> Result<()> {
        if self.require_rollback_resistant_storage && !self.provider.is_rollback_resistant_storage()
        {
            return Err(Error::ClientError(format!(
                "Fleet policy requires rollback-resistant storage; refusing {} (provider_kind={})",
                op,
                self.provider.provider_kind()
            )));
        }
        Ok(())
    }

    fn ensure_revocation_caught_up(&mut self, op: &str) -> Result<()> {
        let min_policy = self.min_revocation_seq.unwrap_or(0);
        let min = std::cmp::max(min_policy, self.revocation_seq_floor);
        if min == 0 {
            return Ok(());
        }
        let have = self.keystore.revocation_seq();
        if have < min {
            warn!(
                "Revocation state behind policy requirement: have_seq={} < min_seq={} (op={})",
                have, min, op
            );
            let _ = self.maybe_request_revocation_sync();
            return Err(Error::ClientError(format!(
                "Revocation state behind policy requirement (have_seq={} < min_seq={}); refusing {}",
                have, min, op
            )));
        }
        Ok(())
    }

    fn maybe_request_fleet_policy_sync(&mut self) -> Result<()> {
        let now = Instant::now();
        if let Some(last) = self.last_policy_sync_request {
            if now.duration_since(last) < DEFAULT_SYNC_REQUEST_COOLDOWN {
                return Ok(());
            }
        }
        self.last_policy_sync_request = Some(now);

        let current_seq = self.fleet_policy.as_ref().map(|p| p.seq).unwrap_or(0);
        let req = FleetPolicySyncRequest {
            version: FleetPolicySyncRequest::VERSION_V1,
            client_id: self.client_id.clone(),
            current_seq,
        };
        let payload = serde_json::to_vec(&req)
            .map_err(|e| Error::ClientError(format!("FleetPolicySyncRequest JSON error: {}", e)))?;

        if let Some(client) = &mut self.client {
            if let Err(e) =
                client.publish(&self.policy_sync_topic, QoS::AtLeastOnce, false, payload)
            {
                warn!(
                    "FleetPolicySyncRequest publish failed (topic={}): {}",
                    self.policy_sync_topic, e
                );
            }
        }
        Ok(())
    }

    fn maybe_request_revocation_sync(&mut self) -> Result<()> {
        let now = Instant::now();
        if let Some(last) = self.last_revocation_sync_request {
            if now.duration_since(last) < DEFAULT_SYNC_REQUEST_COOLDOWN {
                return Ok(());
            }
        }
        self.last_revocation_sync_request = Some(now);

        let current_seq = self.keystore.revocation_seq();
        let req = RevocationSyncRequest {
            version: RevocationSyncRequest::VERSION_V1,
            client_id: self.client_id.clone(),
            current_seq,
        };
        let payload = serde_json::to_vec(&req)
            .map_err(|e| Error::ClientError(format!("RevocationSyncRequest JSON error: {}", e)))?;

        if let Some(client) = &mut self.client {
            if let Err(e) = client.publish(
                &self.revocation_sync_topic,
                QoS::AtLeastOnce,
                false,
                payload,
            ) {
                warn!(
                    "RevocationSyncRequest publish failed (topic={}): {}",
                    self.revocation_sync_topic, e
                );
            }
        }
        Ok(())
    }

    fn is_fleet_policy_stale(&mut self) -> Result<bool> {
        let (issued_at, ttl_secs) = match &self.fleet_policy {
            Some(p) => match p.ttl_secs {
                Some(ttl) => (p.issued_at, ttl),
                None => return Ok(false),
            },
            None => return Ok(false),
        };

        let now = self.secure_time.now_unix_s()?;
        Ok(now.saturating_sub(issued_at) > ttl_secs)
    }

    fn ensure_fleet_policy_fresh(&mut self, op: &str) -> Result<()> {
        self.ensure_fleet_policy_caught_up(op)?;
        self.ensure_storage_assurance(op)?;
        self.ensure_revocation_caught_up(op)?;
        if self.is_fleet_policy_stale()? {
            let _ = self.maybe_request_fleet_policy_sync();
            return Err(Error::ClientError(format!(
                "Fleet policy stale (ttl exceeded); refusing {}",
                op
            )));
        }
        Ok(())
    }

    fn drop_if_fleet_policy_stale(&mut self, op: &str) -> Result<bool> {
        let floor = self.fleet_policy_seq_floor;
        if floor > 0 {
            let have = self.fleet_policy.as_ref().map(|p| p.seq).unwrap_or(0);
            if have < floor {
                let _ = self.maybe_request_fleet_policy_sync();
                warn!(
                    "Dropping {}: fleet policy behind sealed floor (have_seq={} < floor_seq={})",
                    op, have, floor
                );
                return Ok(true);
            }
        }
        if self.is_fleet_policy_stale()? {
            let _ = self.maybe_request_fleet_policy_sync();
            warn!("Dropping {}: fleet policy stale (ttl exceeded)", op);
            return Ok(true);
        }
        Ok(false)
    }

    fn seal_identity_meta(&self) -> Result<()> {
        let meta = SealedIdentityMeta {
            version: SealedIdentityMeta::VERSION_V1,
            trust_anchor_ca_sig_pk: self.trust_anchor_ca_sig_pk.clone(),
            operational_cert: self.operational_cert.clone(),
            sequence_number: self.sequence_number.max(1),
        };
        let blob = serde_json::to_vec(&meta)
            .map_err(|e| Error::ClientError(format!("Identity meta serialization error: {}", e)))?;
        self.provider.seal_data(&self.identity_meta_label(), &blob)
    }

    fn keystore_path(&self) -> std::path::PathBuf {
        self.data_dir
            .join(format!("keystore_{}.json", self.storage_id))
    }

    fn flush_keystore(&mut self) -> Result<()> {
        let keystore_path = self.keystore_path();
        let keystore_path_str = keystore_path.to_str().ok_or(Error::ClientError(
            "Invalid Keystore Path (Non-UTF8)".into(),
        ))?;
        // Bump generation *before* persistence. If we crash after file write but before sealing,
        // the next boot repairs a +1 mismatch (see init_keystore_anti_rollback).
        let gen = self.keystore.bump_generation();
        self.keystore.save_to_file(keystore_path_str)?;

        // Bind the persisted keystore generation to a sealed counter behind the provider.
        // In TPM/HSM-backed providers, this becomes an anti-rollback primitive for replay windows.
        let label = self.keystore_generation_label();
        let _ = self.provider.sealed_monotonic_u64_advance_to(&label, gen)?;

        // Bind the file bytes to a sealed digest for tamper detection within the same generation.
        let hash = self
            .keystore_file_hash()?
            .ok_or_else(|| Error::ClientError("Keystore missing after flush".into()))?;
        let meta_label = self.keystore_meta_label();
        let meta_bytes = encode_keystore_meta_v1(gen, hash);
        self.provider.seal_data(&meta_label, &meta_bytes)?;

        Ok(())
    }

    fn maybe_flush_keystore(&mut self) -> Result<()> {
        if self.persist_manager.should_flush() {
            self.flush_keystore()?;
            self.persist_manager.notify_flushed();
        }
        Ok(())
    }

    fn keystore_generation_label(&self) -> String {
        // Tie the counter to storage_id to avoid using client_id as a filesystem fragment and to
        // keep identities stable across display-name changes.
        format!("pqc-iiot:keystore-gen:v1:{}", self.storage_id)
    }

    fn keystore_meta_label(&self) -> String {
        format!("pqc-iiot:keystore-meta:v1:{}", self.storage_id)
    }

    fn keystore_file_hash(&self) -> Result<Option<[u8; 32]>> {
        let path = self.keystore_path();
        if !path.exists() {
            return Ok(None);
        }
        let blob = AtomicFileStore::read_with_limit(&path, MAX_KEYSTORE_FILE_BYTES)?;
        let digest = Sha256::digest(&blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(Some(out))
    }

    fn init_keystore_anti_rollback(&mut self) -> Result<()> {
        let label = self.keystore_generation_label();
        let file_gen = self.keystore.generation();
        let sealed_gen = self.provider.sealed_monotonic_u64_get(&label)?;
        let mut crash_repair = false;

        match sealed_gen {
            None => {
                // First run (or legacy upgrade): anchor the counter to the current on-disk generation.
                self.provider.seal_data(&label, &file_gen.to_be_bytes())?;
            }
            Some(sealed) => {
                if file_gen < sealed {
                    return Err(Error::ClientError(format!(
                        "Keystore rollback detected: file_gen={} < sealed_gen={}",
                        file_gen, sealed
                    )));
                }
                if file_gen > sealed {
                    // Accept a +1 mismatch as a crash window repair; anything larger is suspicious.
                    if file_gen == sealed.saturating_add(1) {
                        self.provider.seal_data(&label, &file_gen.to_be_bytes())?;
                        crash_repair = true;
                    } else {
                        return Err(Error::ClientError(format!(
                            "Keystore generation mismatch: file_gen={} sealed_gen={}",
                            file_gen, sealed
                        )));
                    }
                }
            }
        }

        // Bind the keystore file contents to a sealed digest to detect tampering within the same generation.
        let meta_label = self.keystore_meta_label();
        let meta = match self.provider.unseal_data(&meta_label) {
            Ok(blob) => Some(blob),
            Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };

        let file_hash = self.keystore_file_hash()?;
        match (meta, file_hash) {
            (None, None) => {
                // No keystore on disk yet; nothing to bind.
            }
            (Some(_), None) => {
                // Sealed meta exists but file is missing: treat as tamper/destructive rollback.
                return Err(Error::ClientError(
                    "Keystore missing but sealed meta present (possible tamper/rollback)".into(),
                ));
            }
            (None, Some(hash)) => {
                // Upgrade path: keystore exists but no sealed meta yet. Anchor it now.
                let bytes = encode_keystore_meta_v1(file_gen, hash);
                self.provider.seal_data(&meta_label, &bytes)?;
            }
            (Some(blob), Some(hash)) => {
                let (meta_gen, meta_hash) = decode_keystore_meta_v1(&blob)?;
                if meta_gen != file_gen {
                    if crash_repair && meta_gen == file_gen.saturating_sub(1) {
                        // Crash window repair: file advanced but meta didn't get sealed. Re-anchor.
                        let bytes = encode_keystore_meta_v1(file_gen, hash);
                        self.provider.seal_data(&meta_label, &bytes)?;
                    } else {
                        return Err(Error::ClientError(format!(
                            "Keystore meta generation mismatch: meta_gen={} file_gen={}",
                            meta_gen, file_gen
                        )));
                    }
                } else if meta_hash != hash {
                    return Err(Error::ClientError(
                        "Keystore tamper detected (sealed digest mismatch)".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn allow_sig_verify(&mut self, peer_id: &str) -> bool {
        self.global_sig_verify_budget.allow() && self.sig_verify_budget.allow(peer_id)
    }

    fn allow_decrypt(&mut self, peer_id: &str) -> bool {
        self.global_decrypt_budget.allow() && self.decrypt_budget.allow(peer_id)
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

    /// Set the maximum accepted bytes for key announcements (`pqc/keys/<peer>`).
    ///
    /// This is a DoS containment boundary: payloads larger than this are dropped before parsing.
    pub fn with_max_key_announcement_bytes(mut self, max_bytes: usize) -> Self {
        self.max_key_announcement_bytes = max_bytes;
        self
    }

    /// Set the maximum accepted bytes for attestation messages (challenge/quote).
    pub fn with_max_attestation_bytes(mut self, max_bytes: usize) -> Self {
        self.max_attestation_bytes = max_bytes;
        self
    }

    /// Set the maximum accepted bytes for encrypted messages.
    pub fn with_max_encrypted_message_bytes(mut self, max_bytes: usize) -> Self {
        self.max_encrypted_message_bytes = max_bytes;
        self
    }

    /// Set the maximum accepted bytes for revocation updates.
    pub fn with_max_revocation_bytes(mut self, max_bytes: usize) -> Self {
        self.max_revocation_bytes = max_bytes;
        self
    }

    /// Set the maximum accepted bytes for fleet policy updates.
    pub fn with_max_policy_bytes(mut self, max_bytes: usize) -> Self {
        self.max_policy_bytes = max_bytes;
        self
    }

    /// Set the maximum accepted bytes for MQTT session control messages (init/resp).
    ///
    /// These messages carry ephemeral public keys and signatures and should remain bounded.
    pub fn with_max_session_bytes(mut self, max_bytes: usize) -> Self {
        self.max_session_bytes = max_bytes;
        self
    }

    /// Configure signature verification DoS budgets.
    ///
    /// This caps **expensive** cryptographic work (Falcon signature verification, certificate verification).
    /// Budgets are enforced per-peer *and* globally to prevent sender-id cardinality attacks.
    pub fn with_sig_verify_budget(
        mut self,
        per_peer_capacity: u32,
        per_peer_refill_per_sec: u32,
        global_capacity: u32,
        global_refill_per_sec: u32,
    ) -> Self {
        let max_peers = self.sig_verify_budget.max_peers;
        self.sig_verify_budget =
            TokenBucketMap::new(per_peer_capacity, per_peer_refill_per_sec, max_peers);
        self.global_sig_verify_budget = TokenBucket::new(global_capacity, global_refill_per_sec);
        self
    }

    /// Configure decryption/KEM DoS budgets.
    ///
    /// This caps decapsulation + AEAD decrypt work, which is typically the highest-cost path.
    pub fn with_decrypt_budget(
        mut self,
        per_peer_capacity: u32,
        per_peer_refill_per_sec: u32,
        global_capacity: u32,
        global_refill_per_sec: u32,
    ) -> Self {
        let max_peers = self.decrypt_budget.max_peers;
        self.decrypt_budget =
            TokenBucketMap::new(per_peer_capacity, per_peer_refill_per_sec, max_peers);
        self.global_decrypt_budget = TokenBucket::new(global_capacity, global_refill_per_sec);
        self
    }

    /// Configure the maximum number of tracked peers in DoS budget maps.
    ///
    /// This is a hard memory bound under sender-id cardinality attacks.
    pub fn with_budget_max_peers(mut self, max_peers: usize) -> Self {
        self.sig_verify_budget = TokenBucketMap::new(
            self.sig_verify_budget.capacity,
            self.sig_verify_budget.refill_rate_per_sec,
            max_peers,
        );
        self.decrypt_budget = TokenBucketMap::new(
            self.decrypt_budget.capacity,
            self.decrypt_budget.refill_rate_per_sec,
            max_peers,
        );
        self
    }

    /// Set the revocation topic (default "pqc/revocations/v1").
    ///
    /// This topic is expected to carry CA-signed revocation updates (CRL-like) and should be
    /// retained by the broker so reconnecting devices can fetch the latest policy.
    pub fn with_revocation_topic(mut self, topic: &str) -> Self {
        self.revocation_topic = topic.to_string();
        self
    }

    /// Set the fleet policy topic (default "pqc/policy/v1").
    ///
    /// This topic is expected to carry CA-signed FleetPolicyUpdate messages and should be retained
    /// by the broker so reconnecting devices can fetch the latest policy.
    pub fn with_policy_topic(mut self, topic: &str) -> Self {
        self.policy_topic = topic.to_string();
        self
    }

    /// Set the fleet policy sync request topic (default "pqc/policy/sync/v1").
    ///
    /// This topic is used by devices to request that the control plane republishes the latest signed
    /// `FleetPolicyUpdate` on `policy_topic`. It is a best-effort catch-up mechanism for long
    /// partitions; it is not a delivery guarantee.
    pub fn with_policy_sync_topic(mut self, topic: &str) -> Self {
        self.policy_sync_topic = topic.to_string();
        self
    }

    /// Set the revocation sync request topic (default "pqc/revocations/sync/v1").
    ///
    /// This topic is used by devices to request that the control plane republishes the latest signed
    /// `RevocationUpdate` on `revocation_topic`. It is a best-effort catch-up mechanism for long
    /// partitions; it is not a delivery guarantee.
    pub fn with_revocation_sync_topic(mut self, topic: &str) -> Self {
        self.revocation_sync_topic = topic.to_string();
        self
    }

    /// Set the session init topic prefix (default `pqc/session/init/`).
    ///
    /// Session init messages are addressed to the **responder** under:
    /// `{session_init_prefix}{responder_id}`.
    pub fn with_session_init_prefix(mut self, prefix: &str) -> Self {
        self.session_init_prefix = prefix.to_string();
        if !self.session_init_prefix.ends_with('/') {
            self.session_init_prefix.push('/');
        }
        self
    }

    /// Set the session response topic prefix (default `pqc/session/resp/`).
    ///
    /// Session responses are addressed to the **initiator** under:
    /// `{session_resp_prefix}{initiator_id}`.
    pub fn with_session_resp_prefix(mut self, prefix: &str) -> Self {
        self.session_resp_prefix = prefix.to_string();
        if !self.session_resp_prefix.ends_with('/') {
            self.session_resp_prefix.push('/');
        }
        self
    }

    /// Pin the mesh CA public key used to verify OperationalCertificates.
    ///
    /// This is the trust anchor that eliminates TOFU for `pqc/keys/*` announcements.
    pub fn with_trust_anchor_ca_sig_pk(mut self, ca_sig_pk: Vec<u8>) -> Self {
        self.trust_anchor_ca_sig_pk = Some(ca_sig_pk);
        self
    }

    /// Set this device's OperationalCertificate (factory -> operational identity).
    pub fn with_operational_cert(mut self, cert: OperationalCertificate) -> Self {
        self.operational_cert = Some(cert);
        self
    }

    /// Require verifier-driven remote attestation before marking peers as trusted/ready.
    pub fn with_attestation_required(mut self, required: bool) -> Self {
        self.attestation_required = required;
        self
    }

    /// Set the expected PCR digest used to verify attestation quotes.
    ///
    /// This is a simplified policy hook; production deployments should tie this to
    /// firmware/boot measurements and device classes.
    pub fn with_expected_pcr_digest(mut self, digest: Vec<u8>) -> Self {
        self.expected_pcr_digest = digest;
        self
    }

    /// Override attestation topic prefixes.
    pub fn with_attestation_topics(mut self, challenge_prefix: &str, quote_prefix: &str) -> Self {
        self.attest_challenge_prefix = challenge_prefix.to_string();
        if !self.attest_challenge_prefix.ends_with('/') {
            self.attest_challenge_prefix.push('/');
        }
        self.attest_quote_prefix = quote_prefix.to_string();
        if !self.attest_quote_prefix.ends_with('/') {
            self.attest_quote_prefix.push('/');
        }
        self
    }

    /// Get the client's identity public key (Falcon).
    pub fn get_identity_key(&self) -> Vec<u8> {
        self.sig_pk.clone()
    }

    /// Get the client's Kyber public key (KEM).
    pub fn get_kem_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Get the client's X25519 static public key.
    pub fn get_x25519_public_key(&self) -> Vec<u8> {
        self.provider.x25519_public_key().to_vec()
    }

    /// Initialize the client if not already initialized
    fn ensure_connected(&mut self) -> Result<()> {
        if self.client.is_none() {
            let (client, mut eventloop) = Client::new(self.options.clone(), 10);
            let client_handle = client.clone();
            self.client = Some(client);

            // SPAWN THREADED WATCHDOG
            let (tx, rx) = sync_channel(256);
            self.network_recv = Some(rx);

            let heartbeat = self.heartbeat.clone();
            let net_metrics = self.metrics.clone();

            thread::spawn(move || {
                for notification in eventloop.iter() {
                    // Update heartbeat
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    heartbeat.store(now, Ordering::Relaxed);

                    if let Ok(Event::Incoming(Packet::Publish(p))) = &notification {
                        trace!("mqtt/net rx publish topic={} retain={}", p.topic, p.retain);
                    }

                    // Send to main thread
                    match tx.try_send(notification) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            // Hard backpressure: never block the network thread on untrusted input.
                            // Dropping here is preferable to deadlocking the event loop (which would
                            // stall keep-alives and cause liveness collapse).
                            net_metrics.inc_mqtt_rx_queue_drop();
                            debug!("mqtt/net rx queue full: dropped notification");
                        }
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
                debug!("mqtt/net thread exited");
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
                        "mqtt_rx_queue_drops": hb_metrics.mqtt_rx_queue_drops.load(Ordering::Relaxed),
                        "current_svn": svn,
                        "integrity": integrity,
                        "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                    });

                    // Sign the snapshot for "Abyssal" security
                    let mut payload = match serde_json::to_vec(&snapshot) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("heartbeat telemetry JSON serialization failed: {}", e);
                            continue;
                        }
                    };
                    if let Ok(sig) = hb_provider.sign(&payload) {
                        if sig.len() > u16::MAX as usize {
                            error!("heartbeat signature too large: {} bytes", sig.len());
                        } else {
                            payload.extend_from_slice(&sig);
                            let sig_len = sig.len() as u16;
                            payload.extend_from_slice(&sig_len.to_be_bytes());
                        }
                    } else {
                        warn!("heartbeat telemetry signing failed");
                    }

                    let topic = format!("telemetry/security/health/{}", hb_client_id);
                    if let Err(e) = hb_client.publish(topic, QoS::AtLeastOnce, false, payload) {
                        warn!("heartbeat telemetry publish failed: {}", e);
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
        info!(
            "SecureMqttClient[{}]: Connected. Subscribing to keys...",
            self.client_id
        );

        if let Some(client) = &mut self.client {
            // Subscribe to all keys
            let subscription_topic = format!("{}+", self.key_prefix);
            client
                .subscribe(&subscription_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;
            info!("SecureMqttClient[{}]: Subscribed.", self.client_id);

            // Subscribe to attestation topics directed to this client (challenge + quote responses).
            let challenge_topic = format!("{}{}", self.attest_challenge_prefix, self.client_id);
            client
                .subscribe(&challenge_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;
            let quote_topic = format!("{}{}", self.attest_quote_prefix, self.client_id);
            client
                .subscribe(&quote_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Subscribe to session control topics directed to this client.
            let session_init_topic = format!("{}{}", self.session_init_prefix, self.client_id);
            client
                .subscribe(&session_init_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;
            let session_resp_topic = format!("{}{}", self.session_resp_prefix, self.client_id);
            client
                .subscribe(&session_resp_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Subscribe to fleet revocations (CA-signed CRL-like updates).
            client
                .subscribe(&self.revocation_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Subscribe to fleet policy updates (CA-signed, retained).
            client
                .subscribe(&self.policy_topic, QoS::AtLeastOnce)
                .map_err(|e| Error::MqttError(e.to_string()))?;

            // Provisioned identity is the default trust model: eliminate TOFU.
            // Nonce-based attestation is challenge-driven (handled out-of-band), so bootstrap does not emit a quote.
            let cert = match &self.operational_cert {
                Some(c) => Some(c.clone()),
                None => {
                    if self.strict_mode {
                        return Err(Error::ClientError(
                            "Missing OperationalCertificate: provision the device before bootstrap()".to_string(),
                        ));
                    }
                    None
                }
            };

            let x25519_pk = self.provider.x25519_public_key().to_vec();

            // Self-consistency: if provisioned, the cert must bind the live identity keys.
            if let Some(c) = &cert {
                if c.device_id != self.client_id {
                    return Err(Error::ClientError(
                        "OperationalCertificate device_id mismatch".to_string(),
                    ));
                }
                if c.kem_pk != self.public_key {
                    return Err(Error::ClientError(
                        "OperationalCertificate kem_pk mismatch".to_string(),
                    ));
                }
                if c.sig_pk != self.sig_pk {
                    return Err(Error::ClientError(
                        "OperationalCertificate sig_pk mismatch".to_string(),
                    ));
                }
                if c.x25519_pk != x25519_pk {
                    return Err(Error::ClientError(
                        "OperationalCertificate x25519_pk mismatch".to_string(),
                    ));
                }
            }

            let key_epoch = cert.as_ref().map(|c| c.key_epoch).unwrap_or(0);
            let key_id = cert.as_ref().map(|c| c.key_id.clone());

            // Publish my keys (signed)
            let mut peer_keys = PeerKeys {
                kem_pk: self.public_key.clone(),
                sig_pk: self.sig_pk.clone(),
                x25519_pk,
                key_epoch,
                key_id,
                operational_cert: cert,
                last_sequence: 0,
                replay_window: 0,
                is_trusted: true, // Self is trusted
                quote: None,
                key_signature: None,
            };

            // Sign announcement with our identity key
            let payload = key_announcement_payload(&self.client_id, &peer_keys);
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
            if let Err(e) = self.flush_keystore() {
                warn!("keystore flush failed: {}", e);
            }
        }

        // Best-effort catch-up for long partitions: request the latest policy/revocations from the control plane.
        let _ = self.maybe_request_revocation_sync();
        let _ = self.maybe_request_fleet_policy_sync();
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
        self.ensure_fleet_policy_fresh("publish_encrypted")?;

        // Prefer forward-secure session encryption when a session is established.
        // This is opt-in by calling `initiate_session()`; v1 remains as the fallback.
        if self.sessions.contains_key(target_client_id) {
            return self.publish_encrypted_session(topic, payload, target_client_id);
        }
        if self.require_sessions {
            return Err(Error::ClientError(format!(
                "Fleet policy requires sessions; no active session for {}. Call initiate_session() first",
                target_client_id
            )));
        }

        // 1. Get Target Keys
        let target_keys = self
            .keystore
            .get(target_client_id)
            .ok_or(Error::ClientError(format!(
                "Unknown client: {}",
                target_client_id
            )))?;

        // Never encrypt to an untrusted or incomplete peer identity.
        // This prevents accidental data leakage while attestation is pending, and blocks TOFU downgrades.
        if !target_keys.is_trusted {
            return Err(Error::ClientError(format!(
                "Peer not trusted/ready for encrypted publish: {}",
                target_client_id
            )));
        }
        if target_keys.kem_pk.is_empty() || target_keys.x25519_pk.len() != 32 {
            return Err(Error::ClientError(format!(
                "Peer missing hybrid keys (kem/x25519) for encrypted publish: {}",
                target_client_id
            )));
        }

        // 2. Prepare Payload with Sequence Number [SeqNum(8) | Payload]
        let mut attached_payload = Vec::with_capacity(8 + payload.len());
        attached_payload.extend_from_slice(&self.sequence_number.to_be_bytes());
        attached_payload.extend_from_slice(payload);

        // 3. Hybrid Encrypt (Kyber + X25519 -> AEAD)
        let encrypted_blob = hybrid::encrypt(
            &target_keys.kem_pk,
            &target_keys.x25519_pk,
            &attached_payload,
        )?;

        // 4. Sign the encrypted blob with explicit domain separation and topic binding.
        // This prevents cross-protocol confusion and topic re-routing attacks.
        let digest =
            mqtt_encrypted_message_signature_digest(&self.client_id, topic, &encrypted_blob);
        let signature = self.provider.sign(&digest)?;
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
            keys.is_trusted && !keys.kem_pk.is_empty() && keys.x25519_pk.len() == 32
        } else {
            false
        }
    }

    /// Check if a forward-secure session (ratchet) is established for this peer.
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Initiate an ephemeral authenticated session with a trusted peer.
    ///
    /// This is a building block for forward secrecy and post-compromise recovery:
    /// - it uses ephemeral Kyber + ephemeral X25519, authenticated by long-term Falcon identities.
    /// - once established, payloads can be protected via a symmetric ratchet without per-message KEM/signature costs.
    pub fn initiate_session(&mut self, peer_id: &str) -> Result<()> {
        self.ensure_connected()?;
        self.ensure_fleet_policy_fresh("initiate_session")?;

        if !is_valid_wire_peer_id(peer_id) {
            return Err(Error::InvalidInput("Invalid peer_id for session".into()));
        }

        let keys = self.keystore.get(peer_id).ok_or_else(|| {
            Error::ClientError(format!(
                "Cannot initiate session: unknown peer (no keystore entry): {}",
                peer_id
            ))
        })?;

        if !keys.is_trusted {
            return Err(Error::ClientError(format!(
                "Cannot initiate session: peer not trusted/ready: {}",
                peer_id
            )));
        }

        if let Some(key_id) = keys.key_id.as_deref() {
            if self.keystore.is_key_id_revoked(peer_id, key_id) {
                return Err(Error::ClientError(format!(
                    "Cannot initiate session: peer key_id is revoked: {}",
                    peer_id
                )));
            }
        }

        // Generate session_id (16 bytes).
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);

        // Ephemeral X25519 key pair.
        let x25519_sk = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk).to_bytes();

        // Ephemeral Kyber key pair (match our configured Kyber level).
        let kyber = kyber_for_pk_len(self.public_key.len())?;
        let (kem_pk, kem_sk) = kyber.generate_keypair()?;

        let topic = format!("{}{}", self.session_init_prefix, peer_id);
        let ts = self.secure_time.now_unix_s()?;
        let session_seq = self.next_session_seq(peer_id)?;
        let payload = session_init_payload_v1(&SessionInitSigInput {
            topic: topic.as_str(),
            session_id: &session_id,
            session_seq,
            initiator_id: &self.client_id,
            responder_id: peer_id,
            kem_pk: &kem_pk,
            x25519_pk: &x25519_pk,
            ts,
        });
        let signature = self.provider.sign(&payload)?;

        let msg = SessionInitMessage {
            version: SessionInitMessage::VERSION_V1,
            initiator_id: self.client_id.clone(),
            responder_id: peer_id.to_string(),
            session_id: session_id.to_vec(),
            session_seq,
            kem_pk,
            x25519_pk: x25519_pk.to_vec(),
            ts,
            signature,
        };

        let bytes = serde_json::to_vec(&msg)
            .map_err(|e| Error::ClientError(format!("SessionInit JSON error: {}", e)))?;

        self.pending_sessions.insert(
            session_id,
            PendingSessionInit {
                peer_id: peer_id.to_string(),
                session_seq,
                kem_sk: Zeroizing::new(kem_sk),
                x25519_sk,
            },
        );

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, bytes)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }

        Ok(())
    }

    /// Publish an encrypted message using the forward-secure session ratchet (v2).
    ///
    /// Requires a session to be established via `initiate_session()` and a corresponding response.
    pub fn publish_encrypted_session(
        &mut self,
        topic: &str,
        payload: &[u8],
        target_peer_id: &str,
    ) -> Result<()> {
        self.ensure_connected()?;
        self.ensure_fleet_policy_fresh("publish_encrypted_session")?;

        // Enforce periodic re-handshake thresholds from fleet policy (PCS building block).
        let needs_rekey = match self.sessions.get(target_peer_id) {
            Some(peer_sessions) => {
                let msgs = self.session_rekey_after_msgs;
                let secs = self.session_rekey_after_secs;
                let mut required = false;
                if let Some(max_msgs) = msgs {
                    if peer_sessions.current.send_msg_num >= max_msgs {
                        required = true;
                    }
                }
                if let Some(max_secs) = secs {
                    if peer_sessions.current.created_at.elapsed() >= Duration::from_secs(max_secs) {
                        required = true;
                    }
                }
                required
            }
            None => {
                return Err(Error::ClientError(format!(
                    "No active session for {}; call initiate_session() and wait for response",
                    target_peer_id
                )))
            }
        };
        if needs_rekey {
            if !self
                .pending_sessions
                .values()
                .any(|p| p.peer_id == target_peer_id)
            {
                // Best-effort: initiate a fresh session; caller retries once established.
                self.initiate_session(target_peer_id)?;
            }
            return Err(Error::ClientError(format!(
                "Session requires rekey; initiated session handshake for {}; retry later",
                target_peer_id
            )));
        }

        let peer_sessions = self.sessions.get_mut(target_peer_id).ok_or_else(|| {
            Error::ClientError(format!(
                "No active session for {}; call initiate_session() and wait for response",
                target_peer_id
            ))
        })?;

        let session = peer_sessions.current_mut();
        let (msg_num, ciphertext) =
            session.encrypt_v2(&self.client_id, target_peer_id, topic, payload)?;

        // Packet: [sender_id_len:u16][sender_id][v=2][session_id:16][msg_num:u32][ct_len:u32][ct]
        let sender_id_bytes = self.client_id.as_bytes();
        let sender_id_len = sender_id_bytes.len() as u16;

        if ciphertext.len() > u32::MAX as usize {
            return Err(Error::InvalidInput("Ciphertext too large".into()));
        }
        let ct_len = ciphertext.len() as u32;

        let mut packet =
            Vec::with_capacity(2 + sender_id_bytes.len() + 1 + 16 + 4 + 4 + ciphertext.len());
        packet.extend_from_slice(&sender_id_len.to_be_bytes());
        packet.extend_from_slice(sender_id_bytes);
        packet.push(2);
        packet.extend_from_slice(&session.session_id);
        packet.extend_from_slice(&msg_num.to_be_bytes());
        packet.extend_from_slice(&ct_len.to_be_bytes());
        packet.extend_from_slice(&ciphertext);

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, packet)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    /// Manually add a trusted peer with their Identity Key (Falcon).
    pub fn add_trusted_peer(&mut self, client_id: &str, sig_pk: Vec<u8>) -> Result<()> {
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
            x25519_pk: Vec::new(),
            key_epoch: 0,
            key_id: None,
            operational_cert: None,
            last_sequence: 0,
            replay_window: 0,
            is_trusted: true,
            quote: None,
            key_signature: None,
        };

        // Cache the peer's keys for future encrypted communications
        self.keystore.insert(client_id, initial_peer_keys);
        // Manual trust changes must be persisted deterministically.
        self.persist_manager.mark_dirty();
        self.flush_keystore()?;
        self.persist_manager.notify_flushed();
        Ok(())
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // If no heartbeat for > 15s (3x KeepAlive), the watchdog treats the network thread as unresponsive.
        if now > last_beat + 15 && last_beat > 0 {
            error!("WATCHDOG TRIGGERED: MQTT Network Thread Stuck! Force Reconnect.");
            self.client = None; // Drop client -> Drops channel -> Thread error -> Exit
            self.network_recv = None;
            return Err(Error::MqttError(
                "Watchdog Timeout: Network Thread Stuck".to_string(),
            ));
        }

        // 2. NON-BLOCKING READ
        if let Some(rx) = &self.network_recv {
            // Try to read all available events without blocking
            // Or use recv_timeout for a tiny slice if we want to yield CPU?
            // try_recv is fully non-blocking.
            match rx.try_recv() {
                Ok(notification) => match notification {
                    Ok(event) => {
                        if let Some((topic, payload)) = self.process_notification(event)? {
                            callback(&topic, &payload);
                        }
                    }
                    Err(e) => return Err(Error::MqttError(e.to_string())),
                },
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
                    if !is_valid_wire_peer_id(sender_id) {
                        warn!(
                            "Dropping key announcement with invalid peer id: {:?}",
                            sender_id
                        );
                        return Ok(None);
                    }
                    if payload.len() > self.max_key_announcement_bytes {
                        warn!(
                            "Dropping key announcement from {}: payload too large ({} bytes > {})",
                            sender_id,
                            payload.len(),
                            self.max_key_announcement_bytes
                        );
                        return Ok(None);
                    }
                    let keys: PeerKeys = serde_json::from_slice(&payload)
                        .map_err(|e| Error::ClientError(format!("Invalid keys: {}", e)))?;
                    self.handle_key_exchange(sender_id, keys)?;
                }
                return Ok(None);
            }

            // 1.1 Attestation challenge (directed to this subject)
            if let Some(target_id) = topic.strip_prefix(&self.attest_challenge_prefix) {
                if target_id == self.client_id {
                    if payload.len() > self.max_attestation_bytes {
                        warn!(
                            "Dropping attestation challenge: payload too large ({} bytes > {})",
                            payload.len(),
                            self.max_attestation_bytes
                        );
                        return Ok(None);
                    }
                    let challenge: AttestationChallenge = serde_json::from_slice(&payload)
                        .map_err(|e| {
                            Error::ClientError(format!("Invalid attestation challenge: {}", e))
                        })?;
                    self.handle_attestation_challenge(challenge)?;
                }
                return Ok(None);
            }

            // 1.2 Attestation quote (directed to this verifier)
            if let Some(verifier_id) = topic.strip_prefix(&self.attest_quote_prefix) {
                if verifier_id == self.client_id {
                    if payload.len() > self.max_attestation_bytes {
                        warn!(
                            "Dropping attestation quote msg: payload too large ({} bytes > {})",
                            payload.len(),
                            self.max_attestation_bytes
                        );
                        return Ok(None);
                    }
                    let msg: AttestationQuoteMessage =
                        serde_json::from_slice(&payload).map_err(|e| {
                            Error::ClientError(format!("Invalid attestation quote msg: {}", e))
                        })?;
                    self.handle_attestation_quote(msg)?;
                }
                return Ok(None);
            }

            // 1.3 Revocation updates (CA-signed, CRL-like).
            if topic == self.revocation_topic {
                if payload.len() > self.max_revocation_bytes {
                    warn!(
                        "Dropping revocation update: payload too large ({} bytes > {})",
                        payload.len(),
                        self.max_revocation_bytes
                    );
                    return Ok(None);
                }
                let update: RevocationUpdate = serde_json::from_slice(&payload).map_err(|e| {
                    Error::ClientError(format!("Invalid revocation update JSON: {}", e))
                })?;
                self.handle_revocation_update(&topic, update)?;
                return Ok(None);
            }

            // 1.3.1 Fleet policy updates (CA-signed, retained).
            if topic == self.policy_topic {
                if payload.len() > self.max_policy_bytes {
                    warn!(
                        "Dropping fleet policy update: payload too large ({} bytes > {})",
                        payload.len(),
                        self.max_policy_bytes
                    );
                    return Ok(None);
                }
                let update: FleetPolicyUpdate = serde_json::from_slice(&payload).map_err(|e| {
                    Error::ClientError(format!("Invalid fleet policy update JSON: {}", e))
                })?;
                self.handle_fleet_policy_update(&topic, update)?;
                return Ok(None);
            }

            // 1.4 Session control: init (directed to this responder).
            if let Some(target_id) = topic.strip_prefix(&self.session_init_prefix) {
                if target_id == self.client_id {
                    if payload.len() > self.max_session_bytes {
                        warn!(
                            "Dropping session init: payload too large ({} bytes > {})",
                            payload.len(),
                            self.max_session_bytes
                        );
                        return Ok(None);
                    }
                    let msg: SessionInitMessage =
                        serde_json::from_slice(&payload).map_err(|e| {
                            Error::ClientError(format!("Invalid session init JSON: {}", e))
                        })?;
                    self.handle_session_init(&topic, msg)?;
                }
                return Ok(None);
            }

            // 1.5 Session control: response (directed to this initiator).
            if let Some(target_id) = topic.strip_prefix(&self.session_resp_prefix) {
                if target_id == self.client_id {
                    if payload.len() > self.max_session_bytes {
                        warn!(
                            "Dropping session response: payload too large ({} bytes > {})",
                            payload.len(),
                            self.max_session_bytes
                        );
                        return Ok(None);
                    }
                    let msg: SessionResponseMessage =
                        serde_json::from_slice(&payload).map_err(|e| {
                            Error::ClientError(format!("Invalid session response JSON: {}", e))
                        })?;
                    self.handle_session_response(&topic, msg)?;
                }
                return Ok(None);
            }

            // 2. Check Encrypted Packet (SenderID prefixed)
            if payload.len() > self.max_encrypted_message_bytes {
                warn!(
                    "Dropping encrypted message: payload too large ({} bytes > {})",
                    payload.len(),
                    self.max_encrypted_message_bytes
                );
                return Ok(None);
            }

            // If policy TTL is in effect and is stale, fail closed for decrypt/verify work.
            if self.drop_if_fleet_policy_stale("mqtt encrypted message")? {
                return Ok(None);
            }
            if let Err(e) = self.ensure_storage_assurance("mqtt encrypted message") {
                warn!("Dropping encrypted message: {}", e);
                return Ok(None);
            }
            if let Err(e) = self.ensure_revocation_caught_up("mqtt encrypted message") {
                warn!("Dropping encrypted message: {}", e);
                return Ok(None);
            }
            if payload.len() > 2 {
                let (len_bytes, _) = payload.split_at(2);
                let id_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

                // Heuristic check
                if id_len > 0 && id_len <= MAX_WIRE_ID_LEN && payload.len() > 2 + id_len + 4 {
                    let (id_bytes, rest) = payload[2..].split_at(id_len);
                    if let Ok(sender_id) = std::str::from_utf8(id_bytes) {
                        if !is_valid_wire_peer_id(sender_id) {
                            warn!(
                                "Dropping encrypted message with invalid sender_id: {:?}",
                                sender_id
                            );
                            return Ok(None);
                        }
                        trace!("mqtt rx extracted sender_id={}", sender_id);
                        // Session/ratchet encrypted packet (v2): [2][session_id:16][msg_num:u32][ct_len:u32][ct]
                        // No per-message signature; authenticity is provided by the established session keys.
                        if !rest.is_empty() && rest[0] == 2 {
                            if let Some(plaintext) =
                                self.try_decrypt_session_packet_v2(&topic, sender_id, rest)?
                            {
                                return Ok(Some((topic, plaintext)));
                            }
                            return Ok(None);
                        }

                        // Policy enforcement: when sessions are required, drop v1 hybrid encrypted packets.
                        if self.require_sessions {
                            warn!(
                                "Dropping v1 encrypted message from {}: fleet policy requires sessions",
                                sender_id
                            );
                            return Ok(None);
                        }

                        // v1: Look for signature at end
                        if rest.len() > 2 {
                            let (blob_and_sig, sig_len_bytes) = rest.split_at(rest.len() - 2);
                            let sig_len =
                                u16::from_be_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;

                            // Falcon signatures are small; reject absurd lengths early.
                            if sig_len == 0 || sig_len > 2048 {
                                warn!(
                                    "Dropping encrypted message from {}: invalid signature length {}",
                                    sender_id, sig_len
                                );
                                return Ok(None);
                            }

                            if blob_and_sig.len() > sig_len {
                                let (encrypted_blob, signature) =
                                    blob_and_sig.split_at(blob_and_sig.len() - sig_len);

                                if let Some(keys) = self.keystore.get(sender_id) {
                                    let sig_pk = keys.sig_pk.clone();
                                    let key_id = keys.key_id.clone();
                                    let is_trusted = keys.is_trusted;

                                    if let Some(key_id) = key_id.as_deref() {
                                        if self.keystore.is_key_id_revoked(sender_id, key_id) {
                                            warn!(
                                                "Dropping encrypted message from {}: key_id revoked",
                                                sender_id
                                            );
                                            return Ok(None);
                                        }
                                    }
                                    if !is_trusted {
                                        warn!(
                                            "Dropping encrypted message from untrusted peer: {}",
                                            sender_id
                                        );
                                        return Ok(None);
                                    }

                                    // Asymmetric-cost DoS budget: signature verification is expensive.
                                    if !self.allow_sig_verify(sender_id) {
                                        warn!(
                                            "Dropping encrypted message from {}: rate limited (sig verify budget)",
                                            sender_id
                                        );
                                        self.metrics.inc_rate_limit_drop();
                                        return Ok(None);
                                    }

                                    let digest = mqtt_encrypted_message_signature_digest(
                                        sender_id,
                                        &topic,
                                        encrypted_blob,
                                    );
                                    let is_valid =
                                        match verify_falcon_auto(&sig_pk, &digest, signature) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                warn!(
                                                    "Signature verification error for {}: {}",
                                                    sender_id, e
                                                );
                                                false
                                            }
                                        };

                                    if is_valid {
                                        // Asymmetric-cost DoS budget: KEM + AEAD decrypt work is expensive.
                                        if !self.allow_decrypt(sender_id) {
                                            warn!(
                                                "Dropping encrypted message from {}: rate limited (decrypt budget)",
                                                sender_id
                                            );
                                            self.metrics.inc_rate_limit_drop();
                                            return Ok(None);
                                        }

                                        match self.provider.decrypt(encrypted_blob) {
                                            Ok(decrypted) => {
                                                // Extract Sequence Number (First 8 bytes).
                                                // Payload may be empty.
                                                if decrypted.len() >= 8 {
                                                    let (seq_bytes, actual_payload) =
                                                        decrypted.split_at(8);
                                                    let mut seq_arr = [0u8; 8];
                                                    seq_arr.copy_from_slice(seq_bytes);
                                                    let seq = u64::from_be_bytes(seq_arr);

                                                    // Update per-peer replay window (bounded OOO support).
                                                    let mut accepted = false;
                                                    if let Some(keys_mut) =
                                                        self.keystore.get_mut(sender_id)
                                                    {
                                                        accepted = replay_window_accept(
                                                            &mut keys_mut.last_sequence,
                                                            &mut keys_mut.replay_window,
                                                            seq,
                                                        );
                                                        if accepted {
                                                            self.persist_manager.mark_dirty();
                                                        }
                                                    }

                                                    if accepted {
                                                        // Flush lazily (bounded by persist_manager policy).
                                                        let _ = self.maybe_flush_keystore();
                                                        return Ok(Some((
                                                            topic,
                                                            actual_payload.to_vec(),
                                                        )));
                                                    }

                                                    warn!(
                                                        "Replay detected from {}: seq={}",
                                                        sender_id, seq
                                                    );
                                                    self.metrics.inc_replay_attack();
                                                } else {
                                                    warn!("Decrypted payload too short");
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Decryption failed for {}: {:?}",
                                                    sender_id, e
                                                );
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
                    if verify_falcon_auto(&self.sig_pk, message, signature).unwrap_or(false) {
                        return Ok(Some((topic, message.to_vec())));
                    }
                }
            }
        }
        Ok(None)
    }

    fn handle_session_init(&mut self, topic: &str, msg: SessionInitMessage) -> Result<()> {
        if self.drop_if_fleet_policy_stale("mqtt session init")? {
            return Ok(());
        }
        if let Err(e) = self.ensure_storage_assurance("mqtt session init") {
            warn!("Dropping session init on {}: {}", topic, e);
            return Ok(());
        }
        if let Err(e) = self.ensure_revocation_caught_up("mqtt session init") {
            warn!("Dropping session init on {}: {}", topic, e);
            return Ok(());
        }

        if msg.version != SessionInitMessage::VERSION_V1 {
            warn!(
                "Ignoring session init on {}: unsupported version {}",
                topic, msg.version
            );
            return Ok(());
        }

        if !is_valid_wire_peer_id(&msg.initiator_id) || !is_valid_wire_peer_id(&msg.responder_id) {
            warn!("Ignoring session init: invalid peer ids");
            return Ok(());
        }

        if msg.responder_id != self.client_id {
            warn!(
                "Ignoring session init: responder_id mismatch {} != {}",
                msg.responder_id, self.client_id
            );
            return Ok(());
        }

        if msg.session_seq == 0 {
            warn!(
                "Ignoring session init from {}: invalid session_seq=0",
                msg.initiator_id
            );
            return Ok(());
        }

        let session_id = match vec_to_16(&msg.session_id) {
            Ok(v) => v,
            Err(e) => {
                warn!("Ignoring session init from {}: {}", msg.initiator_id, e);
                return Ok(());
            }
        };

        let initiator_x_pk = match vec_to_32(&msg.x25519_pk) {
            Ok(v) => v,
            Err(e) => {
                warn!("Ignoring session init from {}: {}", msg.initiator_id, e);
                return Ok(());
            }
        };

        // Only accept sessions from trusted peers.
        let (peer_sig_pk, peer_key_id, peer_is_trusted) = match self.keystore.get(&msg.initiator_id)
        {
            Some(k) => (k.sig_pk.clone(), k.key_id.clone(), k.is_trusted),
            None => {
                warn!(
                    "Ignoring session init from {}: unknown peer (no keystore entry)",
                    msg.initiator_id
                );
                return Ok(());
            }
        };

        if !peer_is_trusted {
            warn!(
                "Ignoring session init from {}: peer not trusted/ready",
                msg.initiator_id
            );
            return Ok(());
        }

        if let Some(key_id) = peer_key_id.as_deref() {
            if self.keystore.is_key_id_revoked(&msg.initiator_id, key_id) {
                warn!(
                    "Ignoring session init from {}: key_id revoked",
                    msg.initiator_id
                );
                return Ok(());
            }
        }

        let last_seq = self.last_inbound_session_seq(&msg.initiator_id)?;
        if msg.session_seq < last_seq {
            warn!(
                "Ignoring session init from {}: session_seq rollback ({} < {})",
                msg.initiator_id, msg.session_seq, last_seq
            );
            self.metrics.inc_replay_attack();
            return Ok(());
        }
        if msg.session_seq == last_seq {
            // Idempotent retransmit: if we have a cached response for this (peer, seq, session_id),
            // resend it without redoing expensive signature/KEM work.
            if let Some(cached) = self.session_resp_cache.get(&msg.initiator_id) {
                if cached.session_seq == msg.session_seq && cached.session_id == session_id {
                    let resp_topic = format!("{}{}", self.session_resp_prefix, msg.initiator_id);
                    if let Some(client) = &mut self.client {
                        client
                            .publish(resp_topic, QoS::AtLeastOnce, false, cached.bytes.clone())
                            .map_err(|e| Error::MqttError(e.to_string()))?;
                    }
                }
            }
            return Ok(());
        }

        if !self.allow_sig_verify(&msg.initiator_id) {
            warn!(
                "Dropping session init from {}: rate limited (sig verify budget)",
                msg.initiator_id
            );
            self.metrics.inc_rate_limit_drop();
            return Ok(());
        }

        let payload = session_init_payload_v1(&SessionInitSigInput {
            topic,
            session_id: &session_id,
            session_seq: msg.session_seq,
            initiator_id: &msg.initiator_id,
            responder_id: &msg.responder_id,
            kem_pk: &msg.kem_pk,
            x25519_pk: &initiator_x_pk,
            ts: msg.ts,
        });

        let sig_ok = match verify_falcon_auto(&peer_sig_pk, &payload, &msg.signature) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session init from {}: signature verify error: {}",
                    msg.initiator_id, e
                );
                false
            }
        };
        if !sig_ok {
            warn!(
                "Ignoring session init from {}: invalid signature",
                msg.initiator_id
            );
            return Ok(());
        }

        // Asymmetric-cost DoS budget: session establishment performs KEM work.
        if !self.allow_decrypt(&msg.initiator_id) {
            warn!(
                "Dropping session init from {}: rate limited (decrypt budget)",
                msg.initiator_id
            );
            self.metrics.inc_rate_limit_drop();
            return Ok(());
        }

        // Responder ephemeral X25519 key pair.
        let responder_x_sk = X25519StaticSecret::random_from_rng(OsRng);
        let responder_x_pk = X25519PublicKey::from(&responder_x_sk).to_bytes();

        let peer_pub = X25519PublicKey::from(initiator_x_pk);
        let dh_ss = responder_x_sk.diffie_hellman(&peer_pub).to_bytes();

        let kyber = match kyber_for_pk_len(msg.kem_pk.len()) {
            Ok(k) => k,
            Err(e) => {
                warn!("Ignoring session init from {}: {}", msg.initiator_id, e);
                return Ok(());
            }
        };
        let (kem_ct, kem_ss) = match kyber.encapsulate(&msg.kem_pk) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session init from {}: kyber encapsulate failed: {}",
                    msg.initiator_id, e
                );
                return Ok(());
            }
        };

        let (ck_initiator, ck_responder) = match derive_session_chain_keys_v1(&kem_ss, &dh_ss) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session init from {}: session key derivation failed: {}",
                    msg.initiator_id, e
                );
                return Ok(());
            }
        };

        // Responder uses ck_responder for sending, ck_initiator for receiving.
        let session = MqttSession::new(session_id, ck_responder, ck_initiator);

        if let Some(existing) = self.sessions.get_mut(&msg.initiator_id) {
            existing.rotate_to(session);
        } else {
            self.sessions
                .insert(msg.initiator_id.clone(), PeerSessions::new(session));
            self.metrics.inc_active_sessions();
        }

        // Send response to the initiator.
        let initiator_id = msg.initiator_id;
        let resp_topic = format!("{}{}", self.session_resp_prefix, initiator_id);
        let ts = self.secure_time.now_unix_s()?;
        let payload = session_resp_payload_v1(&SessionRespSigInput {
            topic: resp_topic.as_str(),
            session_id: &session_id,
            session_seq: msg.session_seq,
            initiator_id: &initiator_id,
            responder_id: &self.client_id,
            x25519_pk: &responder_x_pk,
            kem_ciphertext: &kem_ct,
            ts,
        });
        let signature = self.provider.sign(&payload)?;
        let resp = SessionResponseMessage {
            version: SessionResponseMessage::VERSION_V1,
            initiator_id: initiator_id.clone(),
            responder_id: self.client_id.clone(),
            session_id: session_id.to_vec(),
            session_seq: msg.session_seq,
            x25519_pk: responder_x_pk.to_vec(),
            kem_ciphertext: kem_ct,
            ts,
            signature,
        };
        let bytes = serde_json::to_vec(&resp)
            .map_err(|e| Error::ClientError(format!("SessionResponse JSON error: {}", e)))?;

        self.persist_inbound_session_seq(&initiator_id, msg.session_seq)?;
        self.session_resp_cache.insert(
            initiator_id.clone(),
            CachedSessionResponse {
                session_seq: msg.session_seq,
                session_id,
                bytes: bytes.clone(),
            },
        );

        if let Some(client) = &mut self.client {
            client
                .publish(resp_topic, QoS::AtLeastOnce, false, bytes)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    fn handle_session_response(&mut self, topic: &str, msg: SessionResponseMessage) -> Result<()> {
        if self.drop_if_fleet_policy_stale("mqtt session response")? {
            return Ok(());
        }
        if let Err(e) = self.ensure_storage_assurance("mqtt session response") {
            warn!("Dropping session response on {}: {}", topic, e);
            return Ok(());
        }
        if let Err(e) = self.ensure_revocation_caught_up("mqtt session response") {
            warn!("Dropping session response on {}: {}", topic, e);
            return Ok(());
        }

        if msg.version != SessionResponseMessage::VERSION_V1 {
            warn!(
                "Ignoring session response on {}: unsupported version {}",
                topic, msg.version
            );
            return Ok(());
        }

        if msg.initiator_id != self.client_id {
            warn!(
                "Ignoring session response: initiator_id mismatch {} != {}",
                msg.initiator_id, self.client_id
            );
            return Ok(());
        }

        if msg.session_seq == 0 {
            warn!(
                "Ignoring session response from {}: invalid session_seq=0",
                msg.responder_id
            );
            return Ok(());
        }

        if !is_valid_wire_peer_id(&msg.responder_id) {
            warn!("Ignoring session response: invalid responder_id");
            return Ok(());
        }

        let session_id = match vec_to_16(&msg.session_id) {
            Ok(v) => v,
            Err(e) => {
                warn!("Ignoring session response from {}: {}", msg.responder_id, e);
                return Ok(());
            }
        };

        let responder_x_pk = match vec_to_32(&msg.x25519_pk) {
            Ok(v) => v,
            Err(e) => {
                warn!("Ignoring session response from {}: {}", msg.responder_id, e);
                return Ok(());
            }
        };

        let pending = match self.pending_sessions.remove(&session_id) {
            Some(p) => p,
            None => {
                warn!(
                    "Ignoring session response from {}: unknown session_id {}",
                    msg.responder_id,
                    hex::encode(session_id)
                );
                return Ok(());
            }
        };

        if pending.peer_id != msg.responder_id {
            warn!(
                "Ignoring session response: peer mismatch pending={} responder_id={}",
                pending.peer_id, msg.responder_id
            );
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }

        if msg.session_seq != pending.session_seq {
            warn!(
                "Ignoring session response from {}: session_seq mismatch pending={} msg={}",
                msg.responder_id, pending.session_seq, msg.session_seq
            );
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }

        let (peer_sig_pk, peer_key_id, peer_is_trusted) = match self.keystore.get(&msg.responder_id)
        {
            Some(k) => (k.sig_pk.clone(), k.key_id.clone(), k.is_trusted),
            None => {
                warn!(
                    "Ignoring session response from {}: unknown peer (no keystore entry)",
                    msg.responder_id
                );
                self.pending_sessions.insert(session_id, pending);
                return Ok(());
            }
        };
        if !peer_is_trusted {
            warn!(
                "Ignoring session response from {}: peer not trusted/ready",
                msg.responder_id
            );
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }
        if let Some(key_id) = peer_key_id.as_deref() {
            if self.keystore.is_key_id_revoked(&msg.responder_id, key_id) {
                warn!(
                    "Ignoring session response from {}: key_id revoked",
                    msg.responder_id
                );
                self.pending_sessions.insert(session_id, pending);
                return Ok(());
            }
        }

        if !self.allow_sig_verify(&msg.responder_id) {
            warn!(
                "Dropping session response from {}: rate limited (sig verify budget)",
                msg.responder_id
            );
            self.metrics.inc_rate_limit_drop();
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }

        let payload = session_resp_payload_v1(&SessionRespSigInput {
            topic,
            session_id: &session_id,
            session_seq: msg.session_seq,
            initiator_id: &msg.initiator_id,
            responder_id: &msg.responder_id,
            x25519_pk: &responder_x_pk,
            kem_ciphertext: &msg.kem_ciphertext,
            ts: msg.ts,
        });
        let sig_ok = match verify_falcon_auto(&peer_sig_pk, &payload, &msg.signature) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session response from {}: signature verify error: {}",
                    msg.responder_id, e
                );
                false
            }
        };
        if !sig_ok {
            warn!(
                "Ignoring session response from {}: invalid signature",
                msg.responder_id
            );
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }

        // KEM decapsulation is expensive: enforce decrypt budget here as well.
        if !self.allow_decrypt(&msg.responder_id) {
            warn!(
                "Dropping session response from {}: rate limited (decrypt budget)",
                msg.responder_id
            );
            self.metrics.inc_rate_limit_drop();
            self.pending_sessions.insert(session_id, pending);
            return Ok(());
        }

        let peer_pub = X25519PublicKey::from(responder_x_pk);
        let dh_ss = pending.x25519_sk.diffie_hellman(&peer_pub).to_bytes();

        let kyber = match kyber_for_sk_len(pending.kem_sk.len()) {
            Ok(k) => k,
            Err(e) => {
                warn!("Ignoring session response from {}: {}", msg.responder_id, e);
                self.pending_sessions.insert(session_id, pending);
                return Ok(());
            }
        };
        let kem_ss = match kyber.decapsulate(pending.kem_sk.as_slice(), &msg.kem_ciphertext) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session response from {}: kyber decapsulate failed: {}",
                    msg.responder_id, e
                );
                self.pending_sessions.insert(session_id, pending);
                return Ok(());
            }
        };

        let (ck_initiator, ck_responder) = match derive_session_chain_keys_v1(&kem_ss, &dh_ss) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Ignoring session response from {}: session key derivation failed: {}",
                    msg.responder_id, e
                );
                self.pending_sessions.insert(session_id, pending);
                return Ok(());
            }
        };

        // Initiator uses ck_initiator for sending, ck_responder for receiving.
        let session = MqttSession::new(session_id, ck_initiator, ck_responder);
        if let Some(existing) = self.sessions.get_mut(&msg.responder_id) {
            existing.rotate_to(session);
        } else {
            self.sessions
                .insert(msg.responder_id.clone(), PeerSessions::new(session));
            self.metrics.inc_active_sessions();
        }

        Ok(())
    }

    fn try_decrypt_session_packet_v2(
        &mut self,
        topic: &str,
        sender_id: &str,
        rest: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // [2][session_id:16][msg_num:u32][ct_len:u32][ct]
        const HEADER_LEN: usize = 1 + 16 + 4 + 4;
        if rest.len() < HEADER_LEN {
            warn!(
                "Dropping session packet from {}: too short ({} bytes)",
                sender_id,
                rest.len()
            );
            return Ok(None);
        }

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&rest[1..17]);
        let msg_num = u32::from_be_bytes([rest[17], rest[18], rest[19], rest[20]]);
        let ct_len = u32::from_be_bytes([rest[21], rest[22], rest[23], rest[24]]) as usize;

        if rest.len() != HEADER_LEN + ct_len {
            warn!(
                "Dropping session packet from {}: length mismatch ct_len={} total={}",
                sender_id,
                ct_len,
                rest.len()
            );
            return Ok(None);
        }

        let ciphertext = &rest[HEADER_LEN..];

        let peer_sessions = match self.sessions.get_mut(sender_id) {
            Some(s) => s,
            None => {
                warn!(
                    "Dropping session packet from {}: no active session",
                    sender_id
                );
                return Ok(None);
            }
        };

        let session = match peer_sessions.get_mut_by_session_id(&session_id) {
            Some(s) => s,
            None => {
                warn!(
                    "Dropping session packet from {}: session_id mismatch",
                    sender_id
                );
                return Ok(None);
            }
        };

        match session.decrypt_v2(sender_id, &self.client_id, topic, msg_num, ciphertext) {
            Ok(pt) => Ok(Some(pt)),
            Err(e) => {
                warn!("Session decrypt failed for {}: {}", sender_id, e);
                self.metrics.inc_decryption_failure();
                Ok(None)
            }
        }
    }

    fn send_attestation_challenge(&mut self, peer_id: &str) -> Result<()> {
        if self.pending_attestation.contains_key(peer_id) {
            return Ok(());
        }
        let mut nonce = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        self.pending_attestation
            .insert(peer_id.to_string(), nonce.clone());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let challenge = AttestationChallenge {
            verifier_id: self.client_id.clone(),
            nonce,
            ts: now,
        };
        let payload = serde_json::to_vec(&challenge)
            .map_err(|e| Error::ClientError(format!("Challenge JSON error: {}", e)))?;
        let topic = format!("{}{}", self.attest_challenge_prefix, peer_id);

        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, payload)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    fn handle_attestation_challenge(&mut self, challenge: AttestationChallenge) -> Result<()> {
        if self.drop_if_fleet_policy_stale("attestation challenge")? {
            return Ok(());
        }

        // Generate quote bound to challenger nonce.
        let quote = self
            .provider
            .generate_quote(&[0, 1, 2, 3], &challenge.nonce)?;

        let msg = AttestationQuoteMessage {
            subject_id: self.client_id.clone(),
            quote,
        };
        let payload = serde_json::to_vec(&msg)
            .map_err(|e| Error::ClientError(format!("Quote JSON error: {}", e)))?;

        let topic = format!("{}{}", self.attest_quote_prefix, challenge.verifier_id);
        if let Some(client) = &mut self.client {
            client
                .publish(topic, QoS::AtLeastOnce, false, payload)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        Ok(())
    }

    fn handle_attestation_quote(&mut self, msg: AttestationQuoteMessage) -> Result<()> {
        if self.drop_if_fleet_policy_stale("attestation quote")? {
            return Ok(());
        }
        if let Err(e) = self.ensure_storage_assurance("attestation quote") {
            warn!("Dropping attestation quote: {}", e);
            return Ok(());
        }
        if let Err(e) = self.ensure_revocation_caught_up("attestation quote") {
            warn!("Dropping attestation quote: {}", e);
            return Ok(());
        }

        let expected_nonce = match self.pending_attestation.get(&msg.subject_id) {
            Some(n) => n.clone(),
            None => {
                warn!(
                    "Ignoring attestation quote from {}: no pending challenge",
                    msg.subject_id
                );
                return Ok(());
            }
        };

        let peer_keys = match self.keystore.get(&msg.subject_id) {
            Some(k) => k.clone(),
            None => {
                warn!(
                    "Ignoring attestation quote from {}: unknown peer",
                    msg.subject_id
                );
                return Ok(());
            }
        };

        // Bind quote AK to certified identity (simplified: AK == identity key).
        if msg.quote.ak_public_key != peer_keys.sig_pk {
            warn!(
                "Attestation quote rejected for {}: AK does not match certified sig_pk",
                msg.subject_id
            );
            return Ok(());
        }

        // Attestation verification is expensive; apply per-peer + global budgets.
        if !self.allow_sig_verify(&msg.subject_id) {
            warn!(
                "Attestation quote for {} dropped: rate limited (sig verify budget)",
                msg.subject_id
            );
            self.metrics.inc_rate_limit_drop();
            return Ok(());
        }
        if let Err(e) = msg.quote.verify(&expected_nonce, &self.expected_pcr_digest) {
            warn!("Attestation quote rejected for {}: {}", msg.subject_id, e);
            return Ok(());
        }

        // Mark peer trusted and persist.
        if let Some(k) = self.keystore.get_mut(&msg.subject_id) {
            k.is_trusted = true;
            k.quote = Some(msg.quote.clone());
        }
        self.pending_attestation.remove(&msg.subject_id);

        self.persist_manager.mark_dirty();
        self.maybe_flush_keystore()?;

        Ok(())
    }

    fn handle_revocation_update(&mut self, topic: &str, update: RevocationUpdate) -> Result<()> {
        let ca_pk = match &self.trust_anchor_ca_sig_pk {
            Some(pk) => pk,
            None => {
                warn!(
                    "Ignoring revocation update on {}: missing trust_anchor_ca_sig_pk",
                    topic
                );
                return Ok(());
            }
        };

        // Revocation verification is expensive and broker-controlled. Apply a global budget.
        if !self.global_sig_verify_budget.allow() {
            warn!(
                "Dropping revocation update on {}: rate limited (global sig verify budget)",
                topic
            );
            self.metrics.inc_rate_limit_drop();
            return Ok(());
        }

        if let Err(e) = update.verify(ca_pk, topic) {
            warn!("Revocation update rejected: {}", e);
            return Ok(());
        }

        let current_seq = std::cmp::max(self.keystore.revocation_seq(), self.revocation_seq_floor);
        if update.seq <= current_seq {
            debug!(
                "Ignoring revocation update: seq={} <= current_seq={}",
                update.seq, current_seq
            );
            return Ok(());
        }

        for entry in &update.entries {
            self.keystore
                .revoke_key_id(entry.device_id.as_str(), entry.key_id.as_slice());
            if let Some(peer) = self.keystore.get_mut(entry.device_id.as_str()) {
                if peer.key_id.as_deref() == Some(entry.key_id.as_slice()) {
                    peer.is_trusted = false;
                }
            }
        }

        self.keystore.set_revocation_seq(update.seq);

        // Persist immediately: revocations are emergency policy updates and must survive restarts.
        self.flush_keystore()?;
        let label = self.revocation_seq_label();
        let _ = self
            .provider
            .sealed_monotonic_u64_advance_to(&label, update.seq)?;
        self.revocation_seq_floor = self.revocation_seq_floor.max(update.seq);
        self.persist_manager.notify_flushed();

        Ok(())
    }

    fn handle_fleet_policy_update(&mut self, topic: &str, update: FleetPolicyUpdate) -> Result<()> {
        let ca_pk = match &self.trust_anchor_ca_sig_pk {
            Some(pk) => pk,
            None => {
                warn!(
                    "Ignoring fleet policy update on {}: missing trust_anchor_ca_sig_pk",
                    topic
                );
                return Ok(());
            }
        };

        // Policy verification is expensive and broker-controlled. Apply a global budget.
        if !self.global_sig_verify_budget.allow() {
            warn!(
                "Dropping fleet policy update on {}: rate limited (global sig verify budget)",
                topic
            );
            self.metrics.inc_rate_limit_drop();
            return Ok(());
        }

        if let Err(e) = update.verify(ca_pk, topic) {
            warn!("Fleet policy update rejected: {}", e);
            return Ok(());
        }

        let current_seq = std::cmp::max(
            self.fleet_policy.as_ref().map(|p| p.seq).unwrap_or(0),
            self.fleet_policy_seq_floor,
        );
        if update.seq <= current_seq {
            debug!(
                "Ignoring fleet policy update: seq={} <= current_seq={}",
                update.seq, current_seq
            );
            return Ok(());
        }

        // Persist before applying so a crash after apply doesn't revert to an older policy.
        self.seal_fleet_policy(&update)?;
        // Advance the sealed monotonic floor (anti-rollback). Hardware providers should back this
        // with a TPM NV counter / TEE monotonic store.
        let label = self.fleet_policy_seq_label();
        let _ = self
            .provider
            .sealed_monotonic_u64_advance_to(&label, update.seq)?;
        self.fleet_policy_seq_floor = self.fleet_policy_seq_floor.max(update.seq);
        self.apply_fleet_policy(update);

        Ok(())
    }

    /// Handle Key Exchange messages (Identity Verification)
    fn handle_key_exchange(&mut self, sender_id: &str, mut keys: PeerKeys) -> Result<()> {
        if self.drop_if_fleet_policy_stale("mqtt key announcement")? {
            return Ok(());
        }
        if let Err(e) = self.ensure_storage_assurance("mqtt key announcement") {
            warn!("Dropping key announcement from {}: {}", sender_id, e);
            return Ok(());
        }
        if let Err(e) = self.ensure_revocation_caught_up("mqtt key announcement") {
            warn!("Dropping key announcement from {}: {}", sender_id, e);
            return Ok(());
        }

        // Trust is local policy; never accept remote claims via key announcements.
        keys.is_trusted = false;
        // Attestation artifacts must only be accepted via the explicit attestation flow.
        keys.quote = None;
        // Replay state is local-only. Never accept remote-provided sequencing/window state.
        keys.last_sequence = 0;
        keys.replay_window = 0;

        // Detached signature is mandatory (older clients are rejected).
        let signature = match &keys.key_signature {
            Some(sig) => sig,
            None => {
                warn!(
                    "Key exchange from {} rejected: missing key_signature",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }
        };

        // Identity verification:
        // - strict_mode: require provisioning-backed OperationalCertificate (no TOFU)
        // - non-strict: apply TOFU semantics but pin `sig_pk` after first contact (prevents broker key rewrites)
        if let Some(cert) = &keys.operational_cert {
            let ca_pk = match self.trust_anchor_ca_sig_pk.clone() {
                Some(pk) => pk,
                None => {
                    error!(
                        "Strict mode requires a pinned trust anchor CA public key (missing on {})",
                        self.client_id
                    );
                    self.metrics.inc_failed_handshake();
                    return Ok(());
                }
            };

            // Validate cert now (time window + signature + internal consistency).
            let now = self.secure_time.now_unix_s()?;
            if !self.allow_sig_verify(sender_id) {
                warn!(
                    "Key exchange from {} dropped: rate limited (cert verify budget)",
                    sender_id
                );
                self.metrics.inc_rate_limit_drop();
                return Ok(());
            }
            if let Err(e) = cert.verify(&ca_pk, Some(now)) {
                warn!(
                    "Key exchange from {} rejected: invalid operational_cert: {}",
                    sender_id, e
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            // Bind cert subject to topic suffix.
            if cert.device_id != sender_id {
                warn!(
                    "Key exchange from {} rejected: cert device_id mismatch ({})",
                    sender_id, cert.device_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            // Enforce that the announced keys match the certified identity.
            if keys.kem_pk != cert.kem_pk
                || keys.sig_pk != cert.sig_pk
                || keys.x25519_pk != cert.x25519_pk
                || keys.key_epoch != cert.key_epoch
                || keys.key_id.as_deref() != Some(cert.key_id.as_slice())
            {
                warn!(
                    "Key exchange from {} rejected: announced keys do not match operational_cert",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            // Local revocation check.
            if self
                .keystore
                .is_key_id_revoked(sender_id, cert.key_id.as_slice())
            {
                warn!(
                    "Key exchange from {} rejected: key_id is locally revoked",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            // Announcement signature check (proof-of-possession of the certified signing key).
            let payload = key_announcement_payload(sender_id, &keys);
            if !self.allow_sig_verify(sender_id) {
                warn!(
                    "Key exchange from {} dropped: rate limited (announcement verify budget)",
                    sender_id
                );
                self.metrics.inc_rate_limit_drop();
                return Ok(());
            }
            let is_valid = verify_falcon_auto(&cert.sig_pk, &payload, signature)?;
            if !is_valid {
                warn!(
                    "Key exchange from {} rejected: invalid signature",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }
        } else {
            if self.strict_mode {
                warn!(
                    "Key exchange from {} rejected: missing operational_cert (strict_mode)",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            // Non-strict mode: TOFU with pinning.
            // If we already have a pinned sig_pk for this sender_id, reject any attempt to replace it.
            if let Some(existing) = self.keystore.get(sender_id) {
                if !existing.sig_pk.is_empty() && existing.sig_pk != keys.sig_pk {
                    warn!(
                        "Key exchange from {} rejected: sig_pk mismatch (pinned identity)",
                        sender_id
                    );
                    self.metrics.inc_failed_handshake();
                    return Ok(());
                }
            }

            if !self.allow_sig_verify(sender_id) {
                warn!(
                    "Key exchange from {} dropped: rate limited (announcement verify budget)",
                    sender_id
                );
                self.metrics.inc_rate_limit_drop();
                return Ok(());
            }
            let verify_pk = match self.keystore.get(sender_id) {
                Some(existing) if !existing.sig_pk.is_empty() => existing.sig_pk.clone(),
                _ => keys.sig_pk.clone(),
            };
            let payload = key_announcement_payload(sender_id, &keys);
            let is_valid = verify_falcon_auto(&verify_pk, &payload, signature)?;
            if !is_valid {
                warn!(
                    "Key exchange from {} rejected: invalid signature",
                    sender_id
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }
        }

        // Anti-rollback + safe rotation:
        // - accept replays of the same epoch/key_id (retain messages) without resetting sequencing
        // - accept higher epochs and reset replay window
        // - reject lower epochs
        if let Some(existing) = self.keystore.get(sender_id) {
            if existing.key_epoch > keys.key_epoch {
                warn!(
                    "Key exchange from {} rejected: rollback attempt epoch {} < {}",
                    sender_id, keys.key_epoch, existing.key_epoch
                );
                self.metrics.inc_failed_handshake();
                return Ok(());
            }

            if existing.key_epoch == keys.key_epoch {
                let same_key_id = existing.key_id.as_deref() == keys.key_id.as_deref();
                if !same_key_id {
                    warn!(
                        "Key exchange from {} rejected: epoch collision with different key_id",
                        sender_id
                    );
                    self.metrics.inc_failed_handshake();
                    return Ok(());
                }

                // Preserve replay window.
                keys.last_sequence = existing.last_sequence;
                keys.replay_window = existing.replay_window;
            } else {
                // New epoch => new session; reset replay window.
                keys.last_sequence = 0;
                keys.replay_window = 0;
            }
        }

        // Trust gating:
        // - baseline: provisioning cert + key_signature is sufficient for identity authenticity
        // - optional: require a verifier-driven attestation roundtrip before marking peer ready
        let mut needs_attestation = false;
        if self.attestation_required {
            if let Some(existing) = self.keystore.get(sender_id) {
                // Re-attest on key rotation (epoch change) or if never trusted.
                if existing.key_epoch != keys.key_epoch || !existing.is_trusted {
                    needs_attestation = true;
                }
                if existing.key_epoch != keys.key_epoch {
                    // Drop stale nonce (epoch rotated).
                    self.pending_attestation.remove(sender_id);
                }
            } else {
                needs_attestation = true;
            }
        }

        // Trust is local policy; never accept remote claims.
        keys.is_trusted = !needs_attestation;

        self.keystore.insert(sender_id, keys);

        if needs_attestation {
            if let Err(e) = self.send_attestation_challenge(sender_id) {
                warn!(
                    "Failed to send attestation challenge to {}: {}",
                    sender_id, e
                );
            }
        }

        // Lazy Persistence
        self.persist_manager.mark_dirty();
        self.maybe_flush_keystore()?;

        self.metrics.inc_success_handshake();
        let event = SecurityEvent::HandshakeSuccess {
            peer_id: sender_id.to_string(),
        };
        self.audit_logger
            .log(AuditLog::new(event, Severity::Info, "SecureMqttClient"));

        Ok(())
    }
}

fn verify_falcon_auto(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
    use crate::FalconSecurityLevel;
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
