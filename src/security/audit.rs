use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH}; // Fixed imports

/// Severity of a security event.
/// Used to categorize the impact of an event on the system's security posture.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)] // Added Deserialize
pub enum Severity {
    /// Informational event (e.g., successful login).
    Info,
    /// Warning event (e.g., failed login attempt).
    Warning,
    /// Critical event (e.g., replay attack detected).
    Critical,
    /// Alert event requiring immediate attention (e.g., tamper attempt).
    Alert,
}

/// Type of Security Event.
/// Comprehensive enumeration of all security-relevant occurrences in the system.
#[derive(Debug, Serialize, Deserialize, Clone)] // Added Deserialize
pub enum SecurityEvent {
    // Authentication & Identity
    /// A handshake was successfully completed with a peer.
    HandshakeSuccess { 
        /// The ID of the peer that connected.
        peer_id: String 
    },
    /// A handshake failed.
    HandshakeFailed { 
        /// The ID of the peer that failed to connect.
        peer_id: String, 
        /// The reason for failure.
        reason: String 
    },
    /// Use this event when a known identity is loaded from storage.
    IdentityLoaded { 
        /// The client ID.
        peer_id: String, 
        /// The path from which the identity was loaded.
        path: String 
    }, 
    /// An identity key was rotated.
    IdentityRotation { 
        /// The ID of the new key.
        new_key_id: String 
    },
    
    // Cryptographic Failures
    /// Failed to decrypt a payload. This could indicate probing or data corruption.
    DecryptionFailure { 
        /// The source of the packet.
        source: String, 
        /// Details of the error.
        details: String 
    },
    /// A signature verification failed.
    InvalidSignature { 
        /// The source of the signature.
        source: String 
    },
    /// A replay attack was detected and prevented.
    ReplayDetected { 
        /// The source of the replayed packet.
        source: String, 
        /// The sequence number in the packet.
        sequence: u64, 
        /// The expected sequence number.
        expected: u64 
    },
    
    // Use of weak/deprecated primitives
    /// Usage of a cryptographic algorithm that is considered weak or deprecated.
    WeakCryptoUsage { 
        /// The name of the algorithm.
        algorithm: String 
    },
    
    // System & Integrity
    /// Result of the startup integrity check.
    StartupIntegrityCheck { 
        /// True if the check passed.
        success: bool 
    },
    /// A physical memory tamper attempt was detected.
    MemoryTamperAttempt { 
        /// The memory address that was accessed.
        address: usize 
    },
    
    // DoS Defense
    /// A DoS puzzle was issued to a client.
    DosPuzzleChallenge { 
        /// The IP/ID of the client.
        client_ip: String, 
        /// The crypto-difficulty assigned.
        difficulty: u8 
    },
    /// Rate limiting was triggered for a client.
    DosRateLimitTriggered { 
        /// The IP/ID of the client.
        client_ip: String 
    },
    
    // Telemetry
    /// A recurring health snapshot of security metrics.
    TelemetryHealthSnapshot { 
        /// Total decryption failures.
        decryption_failures: u64,
        /// Total replay attacks detected.
        replay_attacks: u64,
        /// Current Security Version Number.
        current_svn: u64,
        /// System Integrity status.
        integrity_ok: bool,
    },
}

/// Structured Audit Log Entry.
/// Contains metadata and the specific security event.
#[derive(Debug, Serialize, Deserialize)] // Added Deserialize
pub struct AuditLog {
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// Severity level.
    pub severity: Severity,
    /// The specific security event.
    pub event: SecurityEvent,
    /// The context or module where the event occurred.
    pub context: String, // Context/Module name
}

impl AuditLog {
    /// Create a new audit log entry with current timestamp.
    pub fn new(event: SecurityEvent, severity: Severity, context: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            timestamp,
            severity,
            event,
            context: context.to_string(),
        }
    }
}

/// Trait for Audit Loggers.
/// Allows for different logging backends (JSON, Syslog, Chained).
pub trait AuditLogger: Send + Sync {
    /// Log an entry to the backend.
    fn log(&self, entry: AuditLog);
}

use sha2::{Sha256, Digest};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::path::PathBuf;

/// Cryptographically Chained Log Entry (Tamper-Evident).
/// Forms a hash chain where `hash_n = SHA256(hash_{n-1} + entry_n)`.
#[derive(Debug, Serialize, Deserialize)] // Added Deserialize
pub struct ChainedLogEntry {
    /// The hash of the previous entry.
    pub prev_hash: String,
    /// The actual log data.
    pub entry: AuditLog,
    /// The hash of this entry (including prev_hash).
    pub hash: String, // SHA256(prev_hash + json(entry))
}

/// Audit Logger that enforces specific ordering and integrity via Hash Chaining.
/// Writes to a local file.
pub struct ChainedAuditLogger {
    file_path: PathBuf,
    last_hash: Mutex<String>,
}

impl ChainedAuditLogger {
    /// Initialize the Chained Logger, recovering the last hash from disk if available.
    pub fn new(data_dir: &std::path::Path) -> Self {
        let file_path = data_dir.join("audit.log");
        
        // Recover last hash from file if exists, else generic genesis hash
        // Efficiently read from end of file
        let last_hash = if file_path.exists() {
             use std::io::{Read, Seek, SeekFrom};
             if let Ok(mut file) = std::fs::File::open(&file_path) {
                 if let Ok(len) = file.metadata().map(|m| m.len()) {
                     if len > 0 {
                         // Seek to end - 1024 bytes (heuristic for last line) or less
                         let seek_back = std::cmp::min(len, 4096);
                         if file.seek(SeekFrom::End(-(seek_back as i64))).is_ok() {
                             let mut buffer = std::vec::Vec::new();
                             if file.read_to_end(&mut buffer).is_ok() {
                                 // Convert to string (lossy is fine for JSON check)
                                 let content = String::from_utf8_lossy(&buffer);
                                 // Get last non-empty line
                                 if let Some(last_line) = content.lines().filter(|l| !l.trim().is_empty()).last() {
                                      match serde_json::from_str::<ChainedLogEntry>(last_line) {
                                          Ok(entry) => entry.hash,
                                          Err(_) => "GENESIS_HASH_JSON_ERROR".to_string()
                                      }
                                 } else {
                                     "GENESIS_HASH".to_string()
                                 }
                             } else {
                                 "GENESIS_HASH_READ_ERROR".to_string()
                             }
                         } else {
                             "GENESIS_HASH_SEEK_ERROR".to_string()
                         }
                     } else {
                         "GENESIS_HASH".to_string()
                     }
                 } else {
                     "GENESIS_HASH".to_string()
                 }
             } else {
                 "GENESIS_HASH".to_string()
             }
        } else {
            "GENESIS_HASH".to_string()
        };

        Self {
            file_path,
            last_hash: Mutex::new(last_hash),
        }
    }
}

impl AuditLogger for ChainedAuditLogger {
    fn log(&self, entry: AuditLog) {
        let mut last_hash_guard = self.last_hash.lock().unwrap();
        
        // 1. Serialize the core entry
        let entry_json = serde_json::to_string(&entry).unwrap_or_default();
        
        // 2. Calculate New Hash = SHA256(PrevHash + EntryJSON)
        let mut hasher = Sha256::new();
        hasher.update(last_hash_guard.as_bytes());
        hasher.update(entry_json.as_bytes());
        let new_hash = hex::encode(hasher.finalize());
        
        // 3. Create Chained Entry
        let chained = ChainedLogEntry {
            prev_hash: last_hash_guard.clone(),
            entry,
            hash: new_hash.clone(),
        };
        
        // 4. Atomic Write to Disk (Append)
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path) 
        {
            if let Ok(log_line) = serde_json::to_string(&chained) {
                if let Err(e) = writeln!(file, "{}", log_line) {
                    // FATAL: Audit Failure
                    eprintln!("CRITICAL AUDIT FAILURE: Could not write to log: {}", e);
                    // In a real system, we might trigger a shutdown or alert via alternate channel
                }
            } else {
                 eprintln!("CRITICAL AUDIT FAILURE: Serialization failed");
            }
        } else {
             eprintln!("CRITICAL AUDIT FAILURE: Could not open log file {:?}", self.file_path);
        }
        
        // 5. Update Memory State
        *last_hash_guard = new_hash;
    }
}
